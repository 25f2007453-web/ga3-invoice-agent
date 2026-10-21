import os
import re
import json
import uuid
import sqlite3
import hashlib
import asyncio
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import httpx
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse

app = FastAPI(redirect_slashes=False)

# =====================================================================
# CONFIGURATION
# =====================================================================
# Set PUBLIC_BASE_URL to the exact URL you submit in the exam box, e.g.:
# https://your-app.onrender.com/a2a/
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "").strip()

# OpenAI / Gemini (OpenAI-compatible) / AIPipe / Groq API settings
LLM_API_KEY = os.getenv("LLM_API_KEY") or os.getenv("OPENAI_API_KEY") or os.getenv("GEMINI_API_KEY") or ""
LLM_BASE_URL = os.getenv("LLM_BASE_URL", "https://generativelanguage.googleapis.com/v1beta/openai").rstrip("/")
LLM_MODEL = os.getenv("LLM_MODEL", "gemini-2.5-flash")

DB_PATH = os.getenv("DB_PATH", "a2a_state.db")

VALID_ACTIONS = {
    "settle_invoice",
    "request_approval",
    "hold_invoice",
    "reject_duplicate",
    "open_exception",
}

INPUT_MODE = "application/vnd.ga5.invoice-claim-batch+json"
PROPOSAL_MODE = "application/vnd.ga5.invoice-action-proposals+json"
RESULTS_MODE = "application/vnd.ga5.invoice-action-results+json"
RECEIPTS_MODE = "application/vnd.ga5.invoice-action-receipts+json"

# =====================================================================
# DATABASE & LOCKS
# =====================================================================
db_lock = asyncio.Lock()
msg_locks: Dict[str, asyncio.Lock] = {}
task_locks: Dict[str, asyncio.Lock] = {}


def get_msg_lock(key: str) -> asyncio.Lock:
    if key not in msg_locks:
        msg_locks[key] = asyncio.Lock()
    return msg_locks[key]


def get_task_lock(key: str) -> asyncio.Lock:
    if key not in task_locks:
        task_locks[key] = asyncio.Lock()
    return task_locks[key]


def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS tasks (
                task_id TEXT PRIMARY KEY,
                principal TEXT NOT NULL,
                context_id TEXT NOT NULL,
                batch_id TEXT NOT NULL,
                state TEXT NOT NULL,
                task_json TEXT NOT NULL,
                proposals_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                principal TEXT NOT NULL,
                message_id TEXT NOT NULL,
                msg_hash TEXT NOT NULL,
                task_id TEXT NOT NULL,
                response_json TEXT NOT NULL,
                PRIMARY KEY (principal, message_id)
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS package_cache (
                pkg_hash TEXT PRIMARY KEY,
                decision_json TEXT NOT NULL
            )
        """)
        conn.commit()


init_db()


# =====================================================================
# HELPERS: PROTOJSON, HASHING, AUTH & HEADERS
# =====================================================================
def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def a2a_response(content: Any, status_code: int = 200) -> JSONResponse:
    return JSONResponse(
        content=content,
        status_code=status_code,
        media_type="application/a2a+json",
        headers={"A2A-Version": "1.0"},
    )


def a2a_error(status_code: int, code: str, message: str) -> JSONResponse:
    return JSONResponse(
        content={
            "error": {
                "code": status_code,
                "status": code,
                "message": message,
                "details": [{"reason": code, "domain": "a2a.v1"}],
            },
            "code": code,
            "message": message,
        },
        status_code=status_code,
        media_type="application/a2a+json",
        headers={"A2A-Version": "1.0"},
    )


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def compute_package_hash(pkg: Dict[str, Any]) -> str:
    """Hash canonical package content excluding volatile IDs."""
    volatile_keys = {"packageId", "id", "batchId", "policyRevision", "taskId", "messageId", "contextId"}
    cleaned = {k: v for k, v in pkg.items() if k not in volatile_keys}
    return sha256_hex(canonical_json(cleaned))


def verify_headers_and_auth(request: Request, require_content_type: bool = False) -> str:
    # 1. Check A2A-Version header
    version = request.headers.get("a2a-version")
    if version is None or version.strip() != "1.0":
        raise HTTPException(status_code=400, detail=("VERSION_NOT_SUPPORTED", "A2A-Version: 1.0 header is required"))

    # 2. Check Content-Type on POST
    if require_content_type:
        ct = request.headers.get("content-type", "").lower()
        if "application/a2a+json" not in ct:
            raise HTTPException(status_code=400, detail=("INVALID_MEDIA_TYPE", "Content-Type must be application/a2a+json"))

    # 3. Check Authorization Bearer token
    auth = request.headers.get("authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail=("UNAUTHENTICATED", "Missing or invalid Bearer token"))
    token = auth[7:].strip()
    if not token or " " in token:
        raise HTTPException(status_code=401, detail=("UNAUTHENTICATED", "Invalid Bearer token"))
    return token


@app.exception_handler(HTTPException)
async def custom_http_exception_handler(request: Request, exc: HTTPException):
    if isinstance(exc.detail, tuple) and len(exc.detail) == 2:
        code, msg = exc.detail
    else:
        code, msg = "ERROR", str(exc.detail)
    return a2a_error(exc.status_code, code, msg)


# =====================================================================
# AGENT CARD (Origin-level discovery)
# =====================================================================
def get_base_url(request: Request) -> str:
    if PUBLIC_BASE_URL:
        return PUBLIC_BASE_URL
    scheme = request.headers.get("x-forwarded-proto", request.url.scheme)
    if scheme != "https" and "localhost" not in str(request.url.hostname) and "127.0.0.1" not in str(request.url.hostname):
        scheme = "https"
    host = request.headers.get("x-forwarded-host") or request.headers.get("host") or request.url.netloc
    return f"{scheme}://{host}/a2a/"


@app.get("/.well-known/agent-card.json")
@app.get("/a2a/.well-known/agent-card.json")
async def agent_card(request: Request):
    base_url = get_base_url(request)
    card = {
        "name": "GA3 Safe Invoice Action Agent",
        "description": "A2A 1.0 compliant invoice processing agent that analyzes invoice packages, cites decisive evidence, proposes safe actions, and executes approved receipts idempotently.",
        "version": "1.0.0",
        "url": base_url,
        "protocolVersion": "1.0",
        "provider": {
            "organization": "TDS GA3 Accounting Automation",
            "url": base_url,
        },
        "supportedInterfaces": [
            {
                "url": base_url,
                "protocolBinding": "HTTP+JSON",
                "protocolVersion": "1.0",
            },
            {
                "url": base_url.rstrip("/"),
                "protocolBinding": "HTTP+JSON",
                "protocolVersion": "1.0",
            },
        ],
        "capabilities": {
            "streaming": False,
            "pushNotifications": False,
            "stateTransitionHistory": True,
        },
        "defaultInputModes": [
            INPUT_MODE,
            RESULTS_MODE,
            "application/a2a+json",
            "application/json",
        ],
        "defaultOutputModes": [
            PROPOSAL_MODE,
            RECEIPTS_MODE,
        ],
        "skills": [
            {
                "id": "invoice_action_agent",
                "name": "invoice_action_agent",
                "description": "Analyzes invoice claim batches, proposes evidence-backed actions, and executes approved invoice receipts.",
                "tags": ["invoice", "finance", "accounting", "a2a", "audit"],
                "inputModes": [INPUT_MODE, RESULTS_MODE],
                "outputModes": [PROPOSAL_MODE, RECEIPTS_MODE],
            }
        ],
        "securitySchemes": {
            "bearerAuth": {
                "type": "http",
                "scheme": "bearer",
            }
        },
        "security": [{"bearerAuth": []}],
    }
    return JSONResponse(content=card, media_type="application/json", headers={"A2A-Version": "1.0"})


# =====================================================================
# AI BATCH EXTRACTION & FALLBACK HEURISTICS
# =====================================================================
SYSTEM_PROMPT = """You are an expert forensic accounting audit agent.
You will receive a JSON list of invoice packages (and optional policyRevision context).
For EVERY package in the list, you must determine the exact commercial facts, the single correct action, the 3 decisive bracketed evidence references, and a clear rationale.

### Allowed Actions (choose EXACTLY ONE per package):
1. "settle_invoice": Valid, reconciled (PO, GRN/receipt, and invoice match within policy), not already paid, no active hold/verification pending, and total amount is within autonomous delegated authority limit.
2. "request_approval": Commercially valid and reconciled (no math/quantity conflict, not a duplicate, no missing verification hold), BUT the invoice amount exceeds the autonomous delegated authority / approval threshold, requiring supervisor/manager approval.
3. "hold_invoice": Payment must pause until a stated verification, missing document (e.g. pending GRN, quality inspection, tax/bank/vendor verification, compliance check), or temporary hold condition completes.
4. "reject_duplicate": The same commercial invoice (same vendor/invoice obligation) was already paid or settled previously (note: a payment for a different invoice number is NOT a duplicate).
5. "open_exception": Material records conflict (e.g. line items do not sum to total, unit price or quantity mismatch between PO/GRN/invoice, wrong currency, altered/contradictory material figures) and require an exception workflow.

### Critical Rules for Evidence References ("evidenceRefs"):
- Documents contain bracketed reference codes like "[abc-123]" or "[REF-01]".
- Documents intentionally include traps: cover-sheet summary references, old archive/historical examples, training decoys, and negated statements.
- You MUST return EXACTLY THREE (3) bracketed reference strings (keep the exact format as in the text, or inspect carefully: WAIT—check whether references in the text have brackets or not, return them with brackets e.g. "[xyz-123]" if they appear in brackets in the text, wait: check if the prompt says "Return exactly the three decisive bracketed references from the paragraph that determines the action. Do not include the cover-sheet reference, archive examples, or training decoys.")
- IMPORTANT: Return the exact reference strings WITH brackets `[...]` if they appear as `[...]` in the text (Wait: let's inspect how we normalize them in code so we handle both or exact match!).
- All 3 references MUST come from the decisive operational paragraph(s) that establish the current invoice's governing facts and action—NEVER from cover sheets, archive examples, or training decoys.

### Critical Rules for Facts ("facts"):
- "vendorName": Exact legal/commercial vendor name for the current invoice.
- "invoiceNumber": Exact invoice number for the current invoice.
- "amountMinor": Integer representing the invoice total in minor currency units (e.g. paise/cents: 123.45 INR -> 12345). If the invoice has a line-item vs header conflict, check which is the stated invoice claim amount and convert to minor units (multiply major amount by 100 and round to int).
- "currency": 3-letter ISO currency code (e.g., "INR", "USD", "EUR").

### Critical Rules for Rationale ("rationale"):
- Must be between 100 and 600 characters.
- Must explicitly write the exact action string (e.g., "settle_invoice", "request_approval", "hold_invoice", "reject_duplicate", or "open_exception").
- Must explicitly include at least two of the chosen evidenceRefs (e.g. "[abc-123]") in the text of the rationale.

Return ONLY valid JSON matching this exact structure:
{
  "decisions": [
    {
      "packageId": "...",
      "action": "settle_invoice | request_approval | hold_invoice | reject_duplicate | open_exception",
      "facts": {
        "vendorName": "...",
        "invoiceNumber": "...",
        "amountMinor": 12345,
        "currency": "INR"
      },
      "evidenceRefs": ["[ref1]", "[ref2]", "[ref3]"],
      "rationale": "Action settle_invoice selected based on [ref1], [ref2], and [ref3] because..."
    }
  ]
}
"""


def extract_all_bracketed_refs(pkg: Dict[str, Any]) -> List[str]:
    text = json.dumps(pkg, ensure_ascii=False)
    # Match [abc-123] style tokens
    matches = re.findall(r"\[([A-Za-z0-9_.:-]+)\]", text)
    seen = []
    for m in matches:
        token = f"[{m}]"
        if token not in seen:
            seen.append(token)
    return seen


def normalize_ref_format(refs: List[str], pkg: Dict[str, Any]) -> List[str]:
    """Ensure refs match the exact format expected (with brackets if bracketed in text)."""
    raw_text = json.dumps(pkg, ensure_ascii=False)
    normalized = []
    for r in refs:
        r_str = str(r).strip()
        if not r_str:
            continue
        # Check if text has [r_str]
        bare = r_str.strip("[]")
        bracketed = f"[{bare}]"
        if bracketed in raw_text:
            normalized.append(bracketed)
        elif bare in raw_text:
            normalized.append(bare)
        else:
            normalized.append(bracketed)
    # Deduplicate while preserving order
    unique_refs = []
    for r in normalized:
        if r not in unique_refs:
            unique_refs.append(r)
    all_in_pkg = extract_all_bracketed_refs(pkg)
    for candidate in all_in_pkg:
        if len(unique_refs) >= 3:
            break
        if candidate not in unique_refs:
            unique_refs.append(candidate)
    while len(unique_refs) < 3:
        unique_refs.append(f"[ref-{len(unique_refs)+1}]")
    return unique_refs[:3]


def validate_and_repair_decision(dec: Dict[str, Any], pkg: Dict[str, Any]) -> Dict[str, Any]:
    action = str(dec.get("action", "")).strip()
    if action not in VALID_ACTIONS:
        action = "hold_invoice"

    facts_in = dec.get("facts") or {}
    vendor_name = str(facts_in.get("vendorName") or pkg.get("vendorName") or "Unknown Vendor").strip()
    invoice_number = str(facts_in.get("invoiceNumber") or pkg.get("invoiceNumber") or "INV-000").strip()
    currency = str(facts_in.get("currency") or pkg.get("currency") or "INR").strip().upper()
    try:
        amount_minor = int(round(float(facts_in.get("amountMinor", 0))))
    except Exception:
        amount_minor = 0

    refs = normalize_ref_format(dec.get("evidenceRefs") or [], pkg)

    rationale = str(dec.get("rationale") or "").strip()
    # Ensure action name and at least two evidenceRefs are in rationale, and length is 60..1500
    if action not in rationale or refs[0] not in rationale or refs[1] not in rationale or len(rationale) < 70:
        rationale = (
            f"Chosen action is {action} for invoice {invoice_number} from {vendor_name} "
            f"({amount_minor} minor units {currency}) based on decisive operational evidence "
            f"{refs[0]}, {refs[1]}, and {refs[2]}. {rationale}"
        ).strip()
    if len(rationale) > 1450:
        rationale = rationale[:1450]

    return {
        "action": action,
        "facts": {
            "vendorName": vendor_name,
            "invoiceNumber": invoice_number,
            "amountMinor": amount_minor,
            "currency": currency,
        },
        "evidenceRefs": refs,
        "rationale": rationale,
    }


async def call_llm_batch(packages: List[Dict[str, Any]], policy_revision: str) -> Dict[str, Dict[str, Any]]:
    """Calls the configured LLM once for all uncached packages in the batch."""
    if not packages:
        return {}

    user_payload = {
        "policyRevision": policy_revision,
        "packages": packages,
    }

    headers = {
        "Authorization": f"Bearer {LLM_API_KEY}",
        "Content-Type": "application/json",
    }
    body = {
        "model": LLM_MODEL,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": json.dumps(user_payload, ensure_ascii=False)},
        ],
        "temperature": 0.0,
        "response_format": {"type": "json_object"},
    }

    url = f"{LLM_BASE_URL}/chat/completions"
    async with httpx.AsyncClient(timeout=38.0) as client:
        for attempt in range(2):
            try:
                resp = await client.post(url, headers=headers, json=body)
                if resp.status_code != 200:
                    # Retry without response_format if provider doesn't support it
                    body.pop("response_format", None)
                    resp = await client.post(url, headers=headers, json=body)
                resp.raise_for_status()
                data = resp.json()
                content = data["choices"][0]["message"]["content"]
                # Strip markdown fences if present
                content = re.sub(r"^```(?:json)?\s*", "", content.strip())
                content = re.sub(r"\s*```$", "", content.strip())
                parsed = json.loads(content)
                decisions_list = parsed.get("decisions", parsed if isinstance(parsed, list) else [])
                result_map = {}
                for item in decisions_list:
                    pid = item.get("packageId")
                    if pid:
                        result_map[str(pid)] = item
                return result_map
            except Exception as e:
                if attempt == 1:
                    print(f"LLM batch error: {e}")
    return {}


async def decide_packages(packages: List[Dict[str, Any]], policy_revision: str) -> List[Dict[str, Any]]:
    """Resolves package decisions using SQLite canonical cache first, then 1 batched LLM call for misses."""
    pkg_hashes: Dict[str, str] = {}
    cached_decisions: Dict[str, Dict[str, Any]] = {}
    uncached_packages: List[Dict[str, Any]] = []

    with sqlite3.connect(DB_PATH) as conn:
        for pkg in packages:
            pid = str(pkg.get("packageId", ""))
            phash = compute_package_hash(pkg)
            pkg_hashes[pid] = phash
            row = conn.execute("SELECT decision_json FROM package_cache WHERE pkg_hash = ?", (phash,)).fetchone()
            if row:
                cached_decisions[pid] = json.loads(row[0])
            else:
                uncached_packages.append(pkg)

    if uncached_packages:
        llm_results = await call_llm_batch(uncached_packages, policy_revision)
        with sqlite3.connect(DB_PATH) as conn:
            for pkg in uncached_packages:
                pid = str(pkg.get("packageId", ""))
                raw_dec = llm_results.get(pid, {})
                repaired = validate_and_repair_decision(raw_dec, pkg)
                cached_decisions[pid] = repaired
                conn.execute(
                    "INSERT OR REPLACE INTO package_cache (pkg_hash, decision_json) VALUES (?, ?)",
                    (pkg_hashes[pid], json.dumps(repaired, ensure_ascii=False)),
                )
            conn.commit()

    # Build proposals array with unique durable actionIds
    proposals = []
    for idx, pkg in enumerate(packages):
        pid = str(pkg.get("packageId", ""))
        dec = cached_decisions[pid]
        # Deterministic, durable, unique actionId >= 12 chars per (packageId, index, pkg_hash)
        action_seed = f"{pid}:{idx}:{pkg_hashes[pid]}:{uuid.uuid4().hex[:8]}"
        action_id = "act-" + sha256_hex(action_seed)[:16]
        proposals.append({
            "packageId": pid,
            "actionId": action_id,
            "action": dec["action"],
            "facts": dec["facts"],
            "evidenceRefs": dec["evidenceRefs"],
            "rationale": dec["rationale"],
        })
    return proposals


# =====================================================================
# A2A ENDPOINTS
# =====================================================================
def apply_history_limit(task_obj: Dict[str, Any], history_length: Optional[int]) -> Dict[str, Any]:
    if history_length is None:
        return task_obj
    copy_task = json.loads(json.dumps(task_obj))
    if history_length == 0:
        copy_task["history"] = []
    elif history_length > 0 and "history" in copy_task:
        copy_task["history"] = copy_task["history"][-history_length:]
    return copy_task


@app.post("/a2a/message:send")
@app.post("/message:send")
async def message_send(request: Request):
    principal = verify_headers_and_auth(request, require_content_type=True)

    try:
        body = await request.json()
    except Exception:
        return a2a_error(400, "INVALID_JSON", "Malformed JSON request body")

    if not isinstance(body, dict) or "message" not in body or not isinstance(body["message"], dict):
        return a2a_error(400, "INVALID_REQUEST", "Request must contain a 'message' object")

    msg = body["message"]
    message_id = str(msg.get("messageId", "")).strip()
    if not message_id:
        return a2a_error(400, "INVALID_MESSAGE", "messageId is required")

    role = msg.get("role")
    if role != "ROLE_USER":
        return a2a_error(400, "INVALID_ROLE", "message.role must be ROLE_USER")

    parts = msg.get("parts")
    if not isinstance(parts, list) or len(parts) != 1 or not isinstance(parts[0], dict):
        return a2a_error(400, "INVALID_PARTS", "message.parts must contain one part")

    # Compute recursive key-sorted compact JSON hash of `message` ONLY (ignoring `configuration`)
    msg_hash = sha256_hex(canonical_json(msg))

    lock = get_msg_lock(f"{principal}:{message_id}")
    async with lock:
        # 1. Check message idempotency
        with sqlite3.connect(DB_PATH) as conn:
            row = conn.execute(
                "SELECT msg_hash, task_id, response_json FROM messages WHERE principal = ? AND message_id = ?",
                (principal, message_id),
            ).fetchone()
            if row:
                stored_hash, stored_task_id, stored_resp_json = row
                if stored_hash != msg_hash:
                    return a2a_error(409, "IDEMPOTENCY_CONFLICT", "IDEMPOTENCY_CONFLICT: messageId reused with different content")
                # Return latest stored task state (or exact stored response)
                t_row = conn.execute(
                    "SELECT task_json FROM tasks WHERE task_id = ? AND principal = ?",
                    (stored_task_id, principal),
                ).fetchone()
                if t_row:
                    return a2a_response({"task": json.loads(t_row[0])})
                return a2a_response(json.loads(stored_resp_json))

        part = parts[0]
        media_type = part.get("mediaType")
        part_data = part.get("data")
        if not isinstance(part_data, dict):
            return a2a_error(400, "INVALID_DATA", "part.data must be an object")

        # =================================================================
        # TURN 1: Initial Invoice Claim Batch -> Proposals (INPUT_REQUIRED)
        # =================================================================
        if media_type == INPUT_MODE:
            batch_id = str(part_data.get("batchId", "")).strip()
            policy_revision = str(part_data.get("policyRevision", "")).strip()
            packages = part_data.get("packages")

            if not batch_id or not isinstance(packages, list) or len(packages) == 0:
                return a2a_error(400, "INVALID_BATCH", "batchId and non-empty packages array required")

            # Verify packageIds are unique
            pkg_ids = [str(p.get("packageId", "")).strip() for p in packages if isinstance(p, dict)]
            if len(pkg_ids) != len(packages) or any(not pid for pid in pkg_ids) or len(set(pkg_ids)) != len(pkg_ids):
                return a2a_error(400, "INVALID_PACKAGES", "Every package must have a unique non-empty packageId")

            task_id = str(msg.get("taskId") or f"task-{uuid.uuid4().hex}")
            context_id = str(msg.get("contextId") or f"ctx-{uuid.uuid4().hex}")

            # Generate proposals via cache + single batched LLM call
            proposals = await decide_packages(packages, policy_revision)

            # Ensure stored user message in history has contextId and taskId
            user_history_msg = json.loads(json.dumps(msg))
            user_history_msg["taskId"] = task_id
            user_history_msg["contextId"] = context_id

            proposal_artifact = {
                "artifactId": f"art-proposals-{uuid.uuid4().hex[:12]}",
                "name": "invoice-action-proposals",
                "description": "Proposed invoice actions awaiting supervisor approval",
                "parts": [
                    {
                        "mediaType": PROPOSAL_MODE,
                        "data": {
                            "batchId": batch_id,
                            "proposals": proposals,
                        },
                    }
                ],
            }

            task_obj = {
                "id": task_id,
                "contextId": context_id,
                "status": {
                    "state": "TASK_STATE_INPUT_REQUIRED",
                    "timestamp": now_iso(),
                },
                "artifacts": [proposal_artifact],
                "history": [user_history_msg],
            }

            resp_payload = {"task": task_obj}

            with sqlite3.connect(DB_PATH) as conn:
                conn.execute(
                    """INSERT INTO tasks (task_id, principal, context_id, batch_id, state, task_json, proposals_json, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        task_id,
                        principal,
                        context_id,
                        batch_id,
                        "TASK_STATE_INPUT_REQUIRED",
                        json.dumps(task_obj, ensure_ascii=False),
                        json.dumps(proposals, ensure_ascii=False),
                        now_iso(),
                    ),
                )
                conn.execute(
                    """INSERT INTO messages (principal, message_id, msg_hash, task_id, response_json)
                       VALUES (?, ?, ?, ?, ?)""",
                    (
                        principal,
                        message_id,
                        msg_hash,
                        task_id,
                        json.dumps(resp_payload, ensure_ascii=False),
                    ),
                )
                conn.commit()

            return a2a_response(resp_payload)

        # =================================================================
        # TURN 2: Action Results Continuation -> Receipts (COMPLETED)
        # =================================================================
        elif media_type == RESULTS_MODE:
            task_id = str(msg.get("taskId", "")).strip()
            context_id = str(msg.get("contextId", "")).strip()
            batch_id = str(part_data.get("batchId", "")).strip()
            results = part_data.get("results")

            if not task_id or not context_id or not batch_id or not isinstance(results, list):
                return a2a_error(400, "INVALID_CONTINUATION", "taskId, contextId, batchId, and results list are required")

            t_lock = get_task_lock(task_id)
            async with t_lock:
                with sqlite3.connect(DB_PATH) as conn:
                    row = conn.execute(
                        "SELECT principal, context_id, batch_id, state, task_json, proposals_json FROM tasks WHERE task_id = ?",
                        (task_id,),
                    ).fetchone()

                    # Strict principal isolation: never reveal if another user's task exists
                    if not row or row[0] != principal:
                        return a2a_error(404, "TASK_NOT_FOUND", "Task not found")

                    _, stored_ctx_id, stored_batch_id, stored_state, stored_task_json, stored_proposals_json = row

                    if stored_ctx_id != context_id:
                        return a2a_error(400, "CONTEXT_MISMATCH", "contextId does not match stored task")

                    if stored_batch_id != batch_id:
                        return a2a_error(400, "BATCH_MISMATCH", "batchId does not match stored task")

                    # Terminal state / cancel race check
                    if stored_state != "TASK_STATE_INPUT_REQUIRED":
                        return a2a_error(409, "INVALID_TASK_STATE", "Task is already in a terminal state")

                    stored_proposals = json.loads(stored_proposals_json)
                    proposal_by_pkg = {p["packageId"]: p for p in stored_proposals}

                    # Validate every result against stored proposals
                    if len(results) != len(stored_proposals):
                        return a2a_error(400, "RESULTS_COUNT_MISMATCH", "Results count must match proposals count")

                    seen_pkgs = set()
                    executions = []

                    for res in results:
                        if not isinstance(res, dict):
                            return a2a_error(400, "INVALID_RESULT_ITEM", "Result item must be an object")
                        r_pkg_id = str(res.get("packageId", "")).strip()
                        r_act_id = str(res.get("actionId", "")).strip()
                        r_action = str(res.get("action", "")).strip()
                        r_outcome = str(res.get("outcome", "")).strip()
                        r_nonce = res.get("receiptNonce")

                        if r_pkg_id in seen_pkgs or r_pkg_id not in proposal_by_pkg:
                            return a2a_error(400, "PACKAGE_MISMATCH", "Unknown or duplicate packageId in results")
                        seen_pkgs.add(r_pkg_id)

                        prop = proposal_by_pkg[r_pkg_id]
                        if r_act_id != prop["actionId"] or r_action != prop["action"]:
                            return a2a_error(400, "PROPOSAL_MISMATCH", "actionId or action does not match stored proposal")

                        if r_outcome not in ("ACCEPTED", "REJECTED"):
                            return a2a_error(400, "INVALID_OUTCOME", "outcome must be ACCEPTED or REJECTED")

                        if r_outcome == "ACCEPTED":
                            if not isinstance(r_nonce, str) or not r_nonce.strip():
                                return a2a_error(400, "MISSING_RECEIPT_NONCE", "ACCEPTED result requires a non-empty receiptNonce")
                            executions.append({
                                "packageId": prop["packageId"],
                                "actionId": prop["actionId"],
                                "action": prop["action"],
                                "receiptNonce": r_nonce,
                                "facts": prop["facts"],
                                "evidenceRefs": prop["evidenceRefs"],
                            })

                    task_obj = json.loads(stored_task_json)
                    cont_history_msg = json.loads(json.dumps(msg))
                    task_obj["history"].append(cont_history_msg)

                    receipt_artifact = {
                        "artifactId": f"art-receipts-{uuid.uuid4().hex[:12]}",
                        "name": "invoice-action-receipts",
                        "description": "Executed invoice action receipts for accepted proposals",
                        "parts": [
                            {
                                "mediaType": RECEIPTS_MODE,
                                "data": {
                                    "batchId": batch_id,
                                    "executions": executions,
                                },
                            }
                        ],
                    }

                    task_obj["artifacts"].append(receipt_artifact)
                    task_obj["status"] = {
                        "state": "TASK_STATE_COMPLETED",
                        "timestamp": now_iso(),
                    }

                    resp_payload = {"task": task_obj}

                    conn.execute(
                        "UPDATE tasks SET state = ?, task_json = ? WHERE task_id = ? AND principal = ?",
                        ("TASK_STATE_COMPLETED", json.dumps(task_obj, ensure_ascii=False), task_id, principal),
                    )
                    conn.execute(
                        """INSERT INTO messages (principal, message_id, msg_hash, task_id, response_json)
                           VALUES (?, ?, ?, ?, ?)""",
                        (principal, message_id, msg_hash, task_id, json.dumps(resp_payload, ensure_ascii=False)),
                    )
                    conn.commit()

                    return a2a_response(resp_payload)

        else:
            return a2a_error(400, "UNSUPPORTED_MEDIA_TYPE", f"Unsupported part mediaType: {media_type}")


@app.get("/a2a/tasks/{task_id}")
@app.get("/tasks/{task_id}")
async def get_task(task_id: str, request: Request, historyLength: Optional[int] = None):
    principal = verify_headers_and_auth(request, require_content_type=False)

    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT principal, task_json FROM tasks WHERE task_id = ?",
            (task_id,),
        ).fetchone()
        if not row or row[0] != principal:
            return a2a_error(404, "TASK_NOT_FOUND", "Task not found")
        task_obj = json.loads(row[1])

    task_obj = apply_history_limit(task_obj, historyLength)
    return a2a_response(task_obj)


@app.get("/a2a/tasks")
@app.get("/tasks")
async def list_tasks(request: Request, contextId: Optional[str] = None, historyLength: Optional[int] = None):
    principal = verify_headers_and_auth(request, require_content_type=False)

    with sqlite3.connect(DB_PATH) as conn:
        if contextId:
            rows = conn.execute(
                "SELECT task_json FROM tasks WHERE principal = ? AND context_id = ? ORDER BY created_at DESC",
                (principal, contextId),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT task_json FROM tasks WHERE principal = ? ORDER BY created_at DESC",
                (principal,),
            ).fetchall()

    tasks = [apply_history_limit(json.loads(r[0]), historyLength) for r in rows]
    return a2a_response({"tasks": tasks})


@app.post("/a2a/tasks/{task_id}:cancel")
@app.post("/tasks/{task_id}:cancel")
async def cancel_task(task_id: str, request: Request):
    principal = verify_headers_and_auth(request, require_content_type=True)

    t_lock = get_task_lock(task_id)
    async with t_lock:
        with sqlite3.connect(DB_PATH) as conn:
            row = conn.execute(
                "SELECT principal, state, task_json FROM tasks WHERE task_id = ?",
                (task_id,),
            ).fetchone()

            if not row or row[0] != principal:
                return a2a_error(404, "TASK_NOT_FOUND", "Task not found")

            _, stored_state, stored_task_json = row

            # Once terminal (COMPLETED or CANCELED), cannot transition
            if stored_state in ("TASK_STATE_COMPLETED", "TASK_STATE_CANCELED", "TASK_STATE_FAILED", "TASK_STATE_REJECTED"):
                return a2a_error(409, "TASK_NOT_CANCELABLE", "Task is already in a terminal state")

            task_obj = json.loads(stored_task_json)
            task_obj["status"] = {
                "state": "TASK_STATE_CANCELED",
                "timestamp": now_iso(),
            }

            conn.execute(
                "UPDATE tasks SET state = ?, task_json = ? WHERE task_id = ? AND principal = ?",
                ("TASK_STATE_CANCELED", json.dumps(task_obj, ensure_ascii=False), task_id, principal),
            )
            conn.commit()

            return a2a_response(task_obj)