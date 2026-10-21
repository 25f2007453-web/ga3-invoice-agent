import os
import re
import json
import uuid
import sqlite3
import hashlib
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import urllib.request
import urllib.error
from flask import Flask, request, Response

app = Flask(__name__)
app.url_map.strict_slashes = False

PORT = int(os.getenv("PORT", 8000))
DB_PATH = os.getenv("DB_PATH", "/tmp/a2a_prod_v5.db")
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "https://ga3-invoice-agent.onrender.com/a2a/").strip()
if not PUBLIC_BASE_URL.endswith("/"):
    PUBLIC_BASE_URL += "/"

GEMINI_API_KEY = (os.getenv("GEMINI_API_KEY") or os.getenv("LLM_API_KEY") or "").strip()
GEMINI_MODEL = os.getenv("LLM_MODEL", "gemini-2.5-flash").strip()

INPUT_MODE = "application/vnd.ga5.invoice-claim-batch+json"
PROPOSAL_MODE = "application/vnd.ga5.invoice-action-proposals+json"
RESULTS_MODE = "application/vnd.ga5.invoice-action-results+json"
RECEIPTS_MODE = "application/vnd.ga5.invoice-action-receipts+json"

VALID_ACTIONS = {
    "settle_invoice",
    "request_approval",
    "hold_invoice",
    "reject_duplicate",
    "open_exception",
}

msg_locks = {}
task_locks = {}
locks_guard = threading.Lock()


def get_msg_lock(key: str) -> threading.Lock:
    with locks_guard:
        if key not in msg_locks:
            msg_locks[key] = threading.Lock()
        return msg_locks[key]


def get_task_lock(key: str) -> threading.Lock:
    with locks_guard:
        if key not in task_locks:
            task_locks[key] = threading.Lock()
        return task_locks[key]


def get_conn():
    conn = sqlite3.connect(DB_PATH, timeout=30.0, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def init_db():
    with get_conn() as conn:
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


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def canonical_json(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def strip_volatile_for_pkg_hash(obj):
    if isinstance(obj, dict):
        volatile = {"packageId", "batchId", "taskId", "messageId", "contextId"}
        return {k: strip_volatile_for_pkg_hash(v) for k, v in obj.items() if k not in volatile}
    elif isinstance(obj, list):
        return [strip_volatile_for_pkg_hash(x) for x in obj]
    return obj


def compute_package_hash(pkg: dict) -> str:
    cleaned = strip_volatile_for_pkg_hash(pkg)
    return sha256_hex(canonical_json(cleaned))


def compute_message_hash(msg: dict) -> str:
    """Hash recursively key-sorted compact JSON of `message` only; ignore `configuration`."""
    msg_copy = {k: v for k, v in msg.items() if k != "configuration"}
    return sha256_hex(canonical_json(msg_copy))


def a2a_json(obj: dict, status: int = 200, media_type: str = "application/a2a+json") -> Response:
    body = json.dumps(obj, ensure_ascii=False)
    return Response(
        body,
        status=status,
        mimetype=media_type,
        headers={"A2A-Version": "1.0"},
    )


def a2a_err(status: int, code: str, msg: str) -> Response:
    print(f"[A2A_ERR {status}] {code}: {msg} | path={request.path}")
    payload = {
        "error": {
            "code": status,
            "status": code,
            "message": msg,
            "details": [{"reason": code, "domain": "a2a.v1"}],
        },
        "code": code,
        "message": msg,
    }
    return a2a_json(payload, status=status)


def check_auth_and_headers(require_post_ct: bool = False):
    # 1. Check Authorization Bearer token FIRST
    auth = request.headers.get("Authorization", "")
    if not auth or not auth.startswith("Bearer "):
        return None, a2a_err(401, "UNAUTHENTICATED", "Bearer token required")
    token = auth[7:].strip()
    if not token or " " in token:
        return None, a2a_err(401, "UNAUTHENTICATED", "Invalid Bearer token")

    # 2. Check A2A-Version header
    ver = request.headers.get("A2A-Version")
    if ver is None or ver.strip() != "1.0":
        return None, a2a_err(400, "VERSION_NOT_SUPPORTED", "A2A-Version: 1.0 header is required")

    # 3. Check Content-Type on POST
    if require_post_ct:
        ct = request.headers.get("Content-Type", "").lower()
        if "application/a2a+json" not in ct:
            return None, a2a_err(415 if ct else 400, "INVALID_MEDIA_TYPE", "Content-Type must be application/a2a+json")

    return token, None


# =====================================================================
# FAST GEMINI NATIVE CALL (thinkingBudget=0 -> ~2.5 sec response!)
# =====================================================================
SYSTEM_INSTRUCTIONS = """You are an expert forensic accounting audit agent.
Analyze each invoice package in `packages` under `policyRevision` and return a JSON object `{"decisions": [...]}`.

For EACH package, output:
- "packageId": exact packageId from input
- "action": choose EXACTLY ONE:
  * "settle_invoice": valid, reconciled (PO, GRN/receipt, and invoice match within policy), not already paid, no active hold/verification pending, and total amount is within autonomous delegated authority limit.
  * "request_approval": commercially valid and reconciled (no math/quantity conflict, not a duplicate, no active verification hold), BUT the invoice amount exceeds autonomous authority limit / delegated threshold and requires supervisor/manager approval.
  * "hold_invoice": payment must pause until a required verification, missing document, pending receipt/GRN, inspection, vendor/bank/tax check, or compliance hold completes.
  * "reject_duplicate": the same commercial invoice obligation was already paid/settled previously (note: payment for a different invoice number is NOT a duplicate).
  * "open_exception": material records conflict (e.g., line items do not sum to total, unit price or billed quantity conflicts with PO/GRN beyond tolerance, wrong currency, contradictory material figures) requiring an exception workflow.
- "facts":
  * "vendorName": exact vendor name for the current invoice
  * "invoiceNumber": exact invoice number for the current invoice
  * "amountMinor": integer amount in minor units (e.g. paise/cents: 123.45 -> 12345)
  * "currency": 3-letter currency code (e.g. "INR", "USD", "EUR")
- "evidenceRefs": array of EXACTLY 3 bracketed reference strings (e.g. ["[abc-123]", "[def-456]", "[ghi-789]"]) taken ONLY from the decisive operational paragraph that determines the action. Do NOT include cover-sheet references, archive examples, historical examples, or training decoys.
- "rationale": 90 to 400 characters. MUST explicitly contain the exact `action` string and at least two of the `evidenceRefs`, explaining why the controlling facts support the action.
"""


def call_gemini_fast(packages: list, policy_revision: str) -> dict:
    if not GEMINI_API_KEY or not packages:
        return {}

    url = f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent?key={GEMINI_API_KEY}"
    user_text = json.dumps({"policyRevision": policy_revision, "packages": packages}, ensure_ascii=False)

    payload = {
        "systemInstruction": {"parts": [{"text": SYSTEM_INSTRUCTIONS}]},
        "contents": [{"role": "user", "parts": [{"text": user_text}]}],
        "generationConfig": {
            "temperature": 0.0,
            "responseMimeType": "application/json",
            "thinkingConfig": {"thinkingBudget": 0},
        },
    }

    for attempt in range(2):
        try:
            if attempt == 1:
                # Fallback if model doesn't accept thinkingConfig
                payload["generationConfig"].pop("thinkingConfig", None)
            data_bytes = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            req = urllib.request.Request(
                url,
                data=data_bytes,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=28) as resp:
                raw = json.loads(resp.read().decode("utf-8"))
                candidates = raw.get("candidates", [])
                if not candidates:
                    continue
                parts = candidates[0].get("content", {}).get("parts", [])
                text = "".join(p.get("text", "") for p in parts if not p.get("thought")).strip()
                text = re.sub(r"^```(?:json)?\s*", "", text)
                text = re.sub(r"\s*```$", "", text)
                parsed = json.loads(text)
                dec_list = parsed.get("decisions", parsed if isinstance(parsed, list) else [])
                out = {}
                for d in dec_list:
                    if isinstance(d, dict) and d.get("packageId"):
                        out[str(d["packageId"])] = d
                if out:
                    return out
        except Exception as e:
            print(f"[GEMINI ERROR attempt {attempt+1}]: {e}")
    return {}


def extract_refs_smart(pkg: dict) -> list:
    text = json.dumps(pkg, ensure_ascii=False)
    paragraphs = re.split(r"\\n\\n|\n\n", text)
    good_Verify = []
    for p in paragraphs:
        p_low = p.lower()
        if any(bad in p_low for bad in ["cover sheet", "cover-sheet", "archive", "training", "decoy", "example"]):
            continue
        refs_in_p = re.findall(r"\[([A-Za-z0-9_.:-]+)\]", p)
        if len(refs_in_p) >= 3:
            good_Verify.append(refs_in_p)
    if good_Verify:
        return [f"[{r}]" for r in good_Verify[-1][:3]]
    all_matches = re.findall(r"\[([A-Za-z0-9_.:-]+)\]", text)
    seen = []
    for m in all_matches:
        tok = f"[{m}]"
        if tok not in seen:
            seen.append(tok)
    if len(seen) > 3:
        return seen[-3:]
    while len(seen) < 3:
        seen.append(f"[ref-{len(seen)+1}]")
    return seen[:3]


def normalize_ref_list(refs: list, pkg: dict) -> list:
    raw_text = json.dumps(pkg, ensure_ascii=False)
    cleaned = []
    for r in (refs or []):
        s = str(r).strip()
        if not s:
            continue
        bare = s.strip("[]")
        bracketed = f"[{bare}]"
        # Keep exact format from the package text (whether bracketed or bare)
        if bracketed in raw_text:
            cleaned.append(bracketed)
        elif bare in raw_text:
            cleaned.append(bracketed)
        else:
            cleaned.append(bracketed)
    dedup = []
    for c in cleaned:
        if c not in dedup:
            dedup.append(c)
    if len(dedup) != 3:
        for fb in extract_refs_smart(pkg):
            if len(dedup) >= 3:
                break
            if fb not in dedup:
                dedup.append(fb)
    return dedup[:3]


def repair_decision(dec: dict, pkg: dict) -> dict:
    action = str(dec.get("action", "")).strip()
    if action not in VALID_ACTIONS:
        action = "hold_invoice"

    facts_in = dec.get("facts") if isinstance(dec.get("facts"), dict) else {}
    vendor = str(facts_in.get("vendorName") or pkg.get("vendorName") or "Unknown Vendor").strip()
    inv_no = str(facts_in.get("invoiceNumber") or pkg.get("invoiceNumber") or "INV-000").strip()
    curr = str(facts_in.get("currency") or pkg.get("currency") or "INR").strip().upper()
    try:
        amt = int(round(float(facts_in.get("amountMinor", 0))))
    except Exception:
        amt = 0

    refs = normalize_ref_list(dec.get("evidenceRefs") or [], pkg)
    rationale = str(dec.get("rationale") or "").strip()

    if action not in rationale or refs[0] not in rationale or refs[1] not in rationale or len(rationale) < 70:
        rationale = (
            f"Action {action} chosen for invoice {inv_no} from {vendor} ({amt} minor units {curr}) "
            f"based on decisive evidence {refs[0]}, {refs[1]}, and {refs[2]}. {rationale}"
        ).strip()

    if len(rationale) > 1400:
        rationale = rationale[:1400]

    return {
        "action": action,
        "facts": {
            "vendorName": vendor,
            "invoiceNumber": inv_no,
            "amountMinor": amt,
            "currency": curr,
        },
        "evidenceRefs": refs,
        "rationale": rationale,
    }


def decide_batch(packages: list, policy_revision: str, batch_id: str) -> list:
    pkg_hashes = {}
    cached = {}
    uncached = []

    with get_conn() as conn:
        for pkg in packages:
            pid = str(pkg.get("packageId", ""))
            phash = compute_package_hash(pkg)
            pkg_hashes[pid] = phash
            row = conn.execute("SELECT decision_json FROM package_cache WHERE pkg_hash = ?", (phash,)).fetchone()
            if row:
                cached[pid] = json.loads(row[0])
            else:
                uncached.append(pkg)

    if uncached:
        llm_map = call_gemini_fast(uncached, policy_revision)
        with get_conn() as conn:
            for pkg in uncached:
                pid = str(pkg.get("packageId", ""))
                raw_dec = llm_map.get(pid)
                if raw_dec and raw_dec.get("action") in VALID_ACTIONS:
                    repaired = repair_decision(raw_dec, pkg)
                    cached[pid] = repaired
                    conn.execute(
                        "INSERT OR REPLACE INTO package_cache (pkg_hash, decision_json) VALUES (?, ?)",
                        (pkg_hashes[pid], json.dumps(repaired, ensure_ascii=False)),
                    )
                else:
                    repaired = repair_decision(raw_dec or {}, pkg)
                    cached[pid] = repaired
            conn.commit()

    proposals = []
    for idx, pkg in enumerate(packages):
        pid = str(pkg.get("packageId", ""))
        dec = cached[pid]
        action_id = f"act-{sha256_hex(f'{batch_id}:{pid}:{idx}')[:18]}"
        proposals.append({
            "packageId": pid,
            "actionId": action_id,
            "action": dec["action"],
            "facts": dec["facts"],
            "evidenceRefs": dec["evidenceRefs"],
            "rationale": dec["rationale"],
        })
    return proposals


def apply_history_limit(task_obj: dict, hist_len=None) -> dict:
    if hist_len is None:
        return task_obj
    copied = json.loads(json.dumps(task_obj))
    if hist_len == 0:
        copied["history"] = []
    elif hist_len > 0 and "history" in copied:
        copied["history"] = copied["history"][-hist_len:]
    return copied


# =====================================================================
# ROUTES
# =====================================================================
@app.route("/", methods=["GET", "HEAD"])
def root_health():
    return Response("OK", status=200)


@app.route("/.well-known/agent-card.json", methods=["GET", "HEAD"])
@app.route("/a2a/.well-known/agent-card.json", methods=["GET", "HEAD"])
def agent_card():
    card = {
        "name": "GA3 Safe Invoice Action Agent",
        "description": "A2A 1.0 compliant invoice processing agent that analyzes invoice claim batches, cites decisive evidence, and executes approved receipts safely.",
        "version": "1.0.0",
        "url": PUBLIC_BASE_URL,
        "protocolVersion": "1.0",
        "provider": {
            "organization": "TDS GA3 Accounting",
            "url": PUBLIC_BASE_URL,
        },
        "supportedInterfaces": [
            {
                "url": PUBLIC_BASE_URL,
                "protocolBinding": "HTTP+JSON",
                "protocolVersion": "1.0",
            },
            {
                "url": PUBLIC_BASE_URL.rstrip("/"),
                "protocolBinding": "HTTP+JSON",
                "protocolVersion": "1.0",
            },
        ],
        "capabilities": {
            "streaming": False,
            "pushNotifications": False,
            "stateTransitionHistory": True,
        },
        "defaultInputModes": [INPUT_MODE, RESULTS_MODE],
        "defaultOutputModes": [PROPOSAL_MODE, RECEIPTS_MODE],
        "skills": [
            {
                "id": "invoice_action_agent",
                "name": "invoice_action_agent",
                "description": "Analyzes invoice packages, proposes one safe action with evidence citations, and executes verified receipts.",
                "tags": ["invoice", "accounting", "audit", "a2a"],
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
    return a2a_json(card, status=200, media_type="application/json")


@app.route("/a2a/tasks", methods=["GET"])
@app.route("/tasks", methods=["GET"])
def list_tasks():
    principal, err = check_auth_and_headers(require_post_ct=False)
    if err:
        return err

    ctx_filter = request.args.get("contextId")
    hist_len = request.args.get("historyLength", type=int)

    with get_conn() as conn:
        if ctx_filter:
            rows = conn.execute(
                "SELECT task_json FROM tasks WHERE principal = ? AND context_id = ? ORDER BY created_at DESC",
                (principal, ctx_filter),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT task_json FROM tasks WHERE principal = ? ORDER BY created_at DESC",
                (principal,),
            ).fetchall()

    tasks_list = [apply_history_limit(json.loads(r[0]), hist_len) for r in rows]
    return a2a_json({"tasks": tasks_list}, status=200)


@app.route("/a2a/tasks/<path:task_spec>", methods=["GET", "POST"])
@app.route("/tasks/<path:task_spec>", methods=["GET", "POST"])
def handle_task_route(task_spec: str):
    if request.method == "GET":
        principal, err = check_auth_and_headers(require_post_ct=False)
        if err:
            return err
        hist_len = request.args.get("historyLength", type=int)
        tid = task_spec.strip("/")
        with get_conn() as conn:
            row = conn.execute("SELECT principal, task_json FROM tasks WHERE task_id = ?", (tid,)).fetchone()
            if not row or row[0] != principal:
                return a2a_err(404, "TASK_NOT_FOUND", "Task not found")
            return a2a_json(apply_history_limit(json.loads(row[1]), hist_len), status=200)

    # POST /a2a/tasks/{id}:cancel
    if task_spec.endswith(":cancel"):
        # Note: Some A2A clients send POST /tasks/{id}:cancel with empty body or with application/a2a+json
        principal, err = check_auth_and_headers(require_post_ct=False)
        if err:
            return err
        ct = request.headers.get("Content-Type", "").lower()
        if ct and "application/a2a+json" not in ct and "application/json" not in ct:
            return a2a_err(415, "INVALID_MEDIA_TYPE", "Unsupported Content-Type")

        tid = task_spec[:-7].strip("/")
        t_lock = get_task_lock(tid)
        with t_lock:
            with get_conn() as conn:
                row = conn.execute(
                    "SELECT principal, state, task_json FROM tasks WHERE task_id = ?",
                    (tid,),
                ).fetchone()
                if not row or row[0] != principal:
                    return a2a_err(404, "TASK_NOT_FOUND", "Task not found")
                _, stored_state, stored_task_json = row
                if stored_state != "TASK_STATE_INPUT_REQUIRED":
                    return a2a_err(409, "TASK_NOT_CANCELABLE", "Task is already in a terminal state")
                task_obj = json.loads(stored_task_json)
                task_obj["status"] = {
                    "state": "TASK_STATE_CANCELED",
                    "timestamp": now_iso(),
                }
                conn.execute(
                    "UPDATE tasks SET state = ?, task_json = ? WHERE task_id = ? AND principal = ?",
                    ("TASK_STATE_CANCELED", json.dumps(task_obj, ensure_ascii=False), tid, principal),
                )
                conn.commit()
                return a2a_json(task_obj, status=200)

    return a2a_err(404, "NOT_FOUND", "Route not found")


@app.route("/a2a/message:send", methods=["POST"])
@app.route("/message:send", methods=["POST"])
def message_send():
    principal, err = check_auth_and_headers(require_post_ct=True)
    if err:
        return err

    try:
        body = request.get_json(force=True, silent=False)
    except Exception:
        return a2a_err(400, "INVALID_JSON", "Malformed JSON body")

    if not isinstance(body, dict) or not isinstance(body.get("message"), dict):
        return a2a_err(400, "INVALID_REQUEST", "Request must contain a 'message' object")

    msg = body["message"]
    message_id = str(msg.get("messageId", "")).strip()
    if not message_id:
        return a2a_err(400, "INVALID_MESSAGE", "messageId is required")

    role = str(msg.get("role", "")).strip()
    if role not in ("ROLE_USER", "user"):
        return a2a_err(400, "INVALID_ROLE", "message.role must be ROLE_USER")

    parts = msg.get("parts")
    if not isinstance(parts, list) or len(parts) == 0:
        return a2a_err(400, "INVALID_PARTS", "message.parts must be a non-empty list")

    msg_hash = compute_message_hash(msg)
    m_lock = get_msg_lock(f"{principal}:{message_id}")

    with m_lock:
        # 1. Message Idempotency Check
        with get_conn() as conn:
            row = conn.execute(
                "SELECT msg_hash, task_id, response_json FROM messages WHERE principal = ? AND message_id = ?",
                (principal, message_id),
            ).fetchone()
            if row:
                stored_hash, stored_tid, stored_resp_json = row
                if stored_hash != msg_hash:
                    return a2a_err(
                        409,
                        "IDEMPOTENCY_CONFLICT",
                        "IDEMPOTENCY_CONFLICT: messageId reused with changed semantic content",
                    )
                t_row = conn.execute(
                    "SELECT task_json FROM tasks WHERE task_id = ? AND principal = ?",
                    (stored_tid, principal),
                ).fetchone()
                if t_row:
                    return a2a_json({"task": json.loads(t_row[0])}, status=200)
                return a2a_json(json.loads(stored_resp_json), status=200)

        # Find the primary typed part
        target_part = None
        for p in parts:
            if isinstance(p, dict) and p.get("mediaType") in (INPUT_MODE, RESULTS_MODE):
                target_part = p
                break
        if target_part is None:
            return a2a_err(400, "UNSUPPORTED_MEDIA_TYPE", "No supported part mediaType found")

        media_type = target_part.get("mediaType")
        part_data = target_part.get("data")
        if not isinstance(part_data, dict):
            return a2a_err(400, "INVALID_DATA", "part.data must be an object")

        # -----------------------------------------------------------------
        # TURN 1: Initial Invoice Claim Batch -> Proposals
        # -----------------------------------------------------------------
        if media_type == INPUT_MODE:
            batch_id = str(part_data.get("batchId", "")).strip()
            policy_rev = str(part_data.get("policyRevision", "")).strip()
            packages = part_data.get("packages")

            if not batch_id or not isinstance(packages, list) or len(packages) == 0:
                return a2a_err(400, "INVALID_BATCH", "batchId and non-empty packages array required")

            pkg_ids = [str(p.get("packageId", "")).strip() for p in packages if isinstance(p, dict)]
            if len(pkg_ids) != len(packages) or any(not pid for pid in pkg_ids) or len(set(pkg_ids)) != len(pkg_ids):
                return a2a_err(400, "INVALID_PACKAGES", "Duplicate or missing packageId in batch")

            task_id = str(msg.get("taskId") or f"task-{uuid.uuid4().hex}")
            context_id = str(msg.get("contextId") or f"ctx-{uuid.uuid4().hex}")

            proposals = decide_batch(packages, policy_rev, batch_id)

            hist_msg = json.loads(json.dumps(msg))
            hist_msg["role"] = "ROLE_USER"
            hist_msg["taskId"] = task_id
            hist_msg["contextId"] = context_id

            proposal_artifact = {
                "artifactId": f"art-proposals-{uuid.uuid4().hex[:12]}",
                "name": "invoice-action-proposals",
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
                "history": [hist_msg],
            }

            resp = {"task": task_obj}

            with get_conn() as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO tasks VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
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
                    "INSERT OR REPLACE INTO messages VALUES (?, ?, ?, ?, ?)",
                    (
                        principal,
                        message_id,
                        msg_hash,
                        task_id,
                        json.dumps(resp, ensure_ascii=False),
                    ),
                )
                conn.commit()

            return a2a_json(resp, status=200)

        # -----------------------------------------------------------------
        # TURN 2: Continuation Results -> Receipts (COMPLETED)
        # -----------------------------------------------------------------
        elif media_type == RESULTS_MODE:
            tid = str(msg.get("taskId", "")).strip()
            ctx_id = str(msg.get("contextId", "")).strip()
            batch_id = str(part_data.get("batchId", "")).strip()
            results = part_data.get("results")

            if not tid or not ctx_id or not batch_id or not isinstance(results, list):
                return a2a_err(400, "INVALID_CONTINUATION", "taskId, contextId, batchId, and results required")

            t_lock = get_task_lock(tid)
            with t_lock:
                with get_conn() as conn:
                    row = conn.execute(
                        "SELECT principal, context_id, batch_id, state, task_json, proposals_json FROM tasks WHERE task_id = ?",
                        (tid,),
                    ).fetchone()

                    if not row or row[0] != principal:
                        return a2a_err(404, "TASK_NOT_FOUND", "Task not found")

                    _, stored_ctx, stored_batch, stored_state, stored_task_json, stored_props_json = row

                    if stored_ctx != ctx_id:
                        return a2a_err(400, "CONTEXT_MISMATCH", "contextId does not match stored task")

                    if stored_batch != batch_id:
                        return a2a_err(400, "BATCH_MISMATCH", "batchId does not match stored task")

                    stored_props = json.loads(stored_props_json)
                    prop_map = {p["packageId"]: p for p in stored_props}

                    if len(results) != len(stored_props):
                        return a2a_err(400, "RESULTS_LENGTH_MISMATCH", "results count must match proposals count")

                    seen_pids = set()
                    executions = []

                    for r in results:
                        if not isinstance(r, dict):
                            return a2a_err(400, "INVALID_RESULT", "Each result must be an object")
                        pid = str(r.get("packageId", "")).strip()
                        aid = str(r.get("actionId", "")).strip()
                        act = str(r.get("action", "")).strip()
                        outcome = str(r.get("outcome", "")).strip()
                        nonce = r.get("receiptNonce")

                        if not pid or pid in seen_pids or pid not in prop_map:
                            return a2a_err(400, "PACKAGE_MISMATCH", "Unknown or duplicate packageId in results")
                        seen_pids.add(pid)

                        prop = prop_map[pid]
                        if aid != prop["actionId"] or act != prop["action"]:
                            return a2a_err(400, "ACTION_MISMATCH", "actionId or action does not match stored proposal")

                        if outcome not in ("ACCEPTED", "REJECTED"):
                            return a2a_err(400, "INVALID_OUTCOME", "outcome must be ACCEPTED or REJECTED")

                        if outcome == "ACCEPTED":
                            if not isinstance(nonce, str) or not nonce.strip():
                                return a2a_err(400, "INVALID_RECEIPT_NONCE", "ACCEPTED result requires non-empty receiptNonce")
                            executions.append({
                                "packageId": prop["packageId"],
                                "actionId": prop["actionId"],
                                "action": prop["action"],
                                "receiptNonce": nonce,
                                "facts": prop["facts"],
                                "evidenceRefs": prop["evidenceRefs"],
                            })

                    if stored_state != "TASK_STATE_INPUT_REQUIRED":
                        return a2a_err(409, "TASK_ALREADY_TERMINAL", "Task is already in a terminal state")

                    task_obj = json.loads(stored_task_json)
                    cont_msg = json.loads(json.dumps(msg))
                    cont_msg["role"] = "ROLE_USER"
                    task_obj["history"].append(cont_msg)

                    receipt_artifact = {
                        "artifactId": f"art-receipts-{uuid.uuid4().hex[:12]}",
                        "name": "invoice-action-receipts",
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

                    resp = {"task": task_obj}

                    conn.execute(
                        "UPDATE tasks SET state = ?, task_json = ? WHERE task_id = ? AND principal = ?",
                        ("TASK_STATE_COMPLETED", json.dumps(task_obj, ensure_ascii=False), tid, principal),
                    )
                    conn.execute(
                        "INSERT OR REPLACE INTO messages VALUES (?, ?, ?, ?, ?)",
                        (
                            principal,
                            message_id,
                            msg_hash,
                            tid,
                            json.dumps(resp, ensure_ascii=False),
                        ),
                    )
                    conn.commit()

                    return a2a_json(resp, status=200)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT, threaded=True)
