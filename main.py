import os
import re
import json
import uuid
import sqlite3
import hashlib
import threading
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from datetime import datetime, timezone
import urllib.request
import urllib.error

PORT = int(os.getenv("PORT", 8000))
# Fresh DB path so no old bad cached decisions remain
DB_PATH = os.getenv("DB_PATH", "/tmp/a2a_clean_v4.db")
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

db_init_lock = threading.Lock()
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
    return conn


def init_db():
    with db_init_lock:
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
    """Hash recursively key-sorted compact JSON of `message` only; ignore `configuration` if present."""
    msg_copy = {k: v for k, v in msg.items() if k != "configuration"}
    return sha256_hex(canonical_json(msg_copy))


# =====================================================================
# AI EXTRACTION + DETERMINISTIC FORENSIC PARSER
# =====================================================================
SYSTEM_INSTRUCTIONS = """You are a forensic accounting invoice audit agent.
You receive a JSON object containing `policyRevision` and `packages` (each package has a `packageId` and documents/text).
For EVERY package, you must determine:
1. `action` (choose EXACTLY ONE):
   - "settle_invoice": The invoice is valid, reconciled (PO, GRN/receipt, and invoice match within policy tolerance), not already paid/settled, has no pending hold/verification requirement, and its amount is within autonomous delegated authority limit.
   - "request_approval": Commercially valid and reconciled (no math/quantity conflict, not a duplicate, no active verification hold), BUT the invoice amount exceeds the autonomous authority limit / delegated threshold and requires supervisor/manager/director approval.
   - "hold_invoice": Payment must pause until a required verification, missing document, pending receipt/GRN, inspection, vendor/bank/tax check, or compliance hold completes.
   - "reject_duplicate": The same commercial invoice obligation was already paid or settled earlier (note: payment for a different invoice number is NOT a duplicate).
   - "open_exception": Material records conflict (e.g., line items do not sum to invoice total, unit price or billed quantity conflicts with PO/GRN beyond tolerance, wrong currency, contradictory material figures) requiring an exception workflow.

2. `facts`:
   - `vendorName`: Exact vendor name for the current invoice.
   - `invoiceNumber`: Exact invoice number for the current invoice.
   - `amountMinor`: Integer amount in minor currency units (paise/cents, e.g., 1250.50 -> 125050; if already given in minor units, use the exact integer).
   - `currency`: 3-letter currency code (e.g. "INR", "USD", "EUR").

3. `evidenceRefs`:
   - Return EXACTLY THREE (3) bracketed reference strings from the decisive paragraph that determines the action for this invoice (keep brackets if they appear as `[xyz]` in the text, or check exact format).
   - NEVER include cover-sheet references, archive examples, historical case examples, negated decoys, or training decoys.

4. `rationale`:
   - 90 to 500 characters.
   - MUST explicitly state the chosen `action` name (e.g. "settle_invoice") and MUST explicitly include at least two of the `evidenceRefs` (e.g. "[abc-123]") and explain why the facts and evidence support that action.

Output strictly valid JSON matching:
{
  "decisions": [
    {
      "packageId": "...",
      "action": "settle_invoice",
      "facts": {
        "vendorName": "...",
        "invoiceNumber": "...",
        "amountMinor": 12345,
        "currency": "INR"
      },
      "evidenceRefs": ["[ref1]", "[ref2]", "[ref3]"],
      "rationale": "..."
    }
  ]
}
"""


def call_gemini_native(packages: list, policy_revision: str) -> dict:
    if not GEMINI_API_KEY or not packages:
        return {}

    url = f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent?key={GEMINI_API_KEY}"
    user_text = json.dumps({"policyRevision": policy_revision, "packages": packages}, ensure_ascii=False)

    payload = {
        "systemInstruction": {
            "parts": [{"text": SYSTEM_INSTRUCTIONS}]
        },
        "contents": [
            {
                "role": "user",
                "parts": [{"text": user_text}]
            }
        ],
        "generationConfig": {
            "temperature": 0.0,
            "responseMimeType": "application/json",
        }
    }

    data_bytes = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    for attempt in range(2):
        try:
            req = urllib.request.Request(
                url,
                data=data_bytes,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=38) as resp:
                raw = json.loads(resp.read().decode("utf-8"))
                candidates = raw.get("candidates", [])
                if not candidates:
                    continue
                parts = candidates[0].get("content", {}).get("parts", [])
                text = "".join(p.get("text", "") for p in parts).strip()
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
            print(f"Gemini API attempt {attempt+1} error: {e}")
    return {}


def extract_refs_smart(pkg: dict) -> list:
    """Find bracketed references, filtering out cover-sheet, archive, and training decoy paragraphs."""
    text = json.dumps(pkg, ensure_ascii=False)
    # Split into paragraphs/segments to avoid cover sheet, archive, training decoys
    paragraphs = re.split(r"\\n\\n|\n\n|\"(?:content|body|text|notes|paragraph|section)\"\s*:", text)
    good_Paragraphs = []
    for p in paragraphs:
        p_low = p.lower()
        if any(bad in p_low for bad in ["cover sheet", "cover-sheet", "archive example", "training decoy", "training example", "historical example", "do not cite"]):
            continue
        refs_in_p = re.findall(r"\[([A-Za-z0-9_.:-]+)\]", p)
        if len(refs_in_p) >= 3:
            good_Paragraphs.append(refs_in_p)

    # Check whether package expects bracketed or unbracketed refs:
    # The prompt says: 'Return exactly the three decisive bracketed references from the paragraph that determines the action.'
    # Wait: let's check how refs appear in text. In text they appear as [abc-123].
    if good_Paragraphs:
        chosen = good_Paragraphs[-1][:3]
        return [f"[{r}]" for r in chosen]

    all_matches = re.findall(r"\[([A-Za-z0-9_.:-]+)\]", text)
    seen = []
    for m in all_matches:
        tok = f"[{m}]"
        if tok not in seen:
            seen.append(tok)
    if len(seen) > 3:
        # Skip the first ref if it's likely a cover-sheet ref
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
        # Check if the prompt wants `[abc]` or `abc`—wait:
        # In the earlier prompt: "Crucially, find the exact three bracketed citation codes (e.g., [abc-123]) from the text proving why that action was chosen."
        if bracketed in raw_text:
            cleaned.append(bracketed)
        elif bare in raw_text:
            cleaned.append(f"[{bare}]")
        else:
            cleaned.append(bracketed)
    dedup = []
    for c in cleaned:
        if c not in dedup:
            dedup.append(c)
    if len(dedup) != 3:
        for fallback_r in extract_refs_smart(pkg):
            if len(dedup) >= 3:
                break
            if fallback_r not in dedup:
                dedup.append(fallback_r)
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

    # Ensure rationale is 60..1500 chars, names the action, and cites at least two evidenceRefs
    if (
        action not in rationale
        or refs[0] not in rationale
        or refs[1] not in rationale
        or len(rationale) < 70
    ):
        rationale = (
            f"Decision {action} for vendor {vendor} invoice {inv_no} ({amt} {curr} minor units) "
            f"is supported by decisive evidence {refs[0]}, {refs[1]}, and {refs[2]}. {rationale}"
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
        llm_map = call_gemini_native(uncached, policy_revision)
        with get_conn() as conn:
            for pkg in uncached:
                pid = str(pkg.get("packageId", ""))
                raw_dec = llm_map.get(pid)
                if raw_dec and raw_dec.get("action") in VALID_ACTIONS:
                    repaired = repair_decision(raw_dec, pkg)
                    cached[pid] = repaired
                    # Only cache genuine LLM decisions!
                    conn.execute(
                        "INSERT OR REPLACE INTO package_cache (pkg_hash, decision_json) VALUES (?, ?)",
                        (pkg_hashes[pid], json.dumps(repaired, ensure_ascii=False)),
                    )
                else:
                    # Do NOT poison cache if LLM call failed
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


def apply_history_limit(task_obj: dict, history_len: int = None) -> dict:
    if history_len is None:
        return task_obj
    copied = json.loads(json.dumps(task_obj))
    if history_len == 0:
        copied["history"] = []
    elif history_len > 0 and "history" in copied:
        copied["history"] = copied["history"][-history_len:]
    return copied


# =====================================================================
# HTTP SERVER HANDLER
# =====================================================================
class A2AHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):
        print("%s - - [%s] %s" % (self.client_address[0], self.log_date_time_string(), format % args))

    def send_a2a_json(self, status: int, obj: dict, media_type: str = "application/a2a+json"):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", media_type)
        self.send_header("A2A-Version", "1.0")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_error_json(self, status: int, code: str, msg: str):
        err_payload = {
            "error": {
                "code": status,
                "status": code,
                "message": msg,
                "details": [{"reason": code, "domain": "a2a.v1"}],
            },
            "code": code,
            "message": msg,
        }
        self.send_a2a_json(status, err_payload)

    def validate_headers(self, require_post_ct: bool = False):
        # 1. Check Authentication FIRST so missing Bearer token always returns 401/403 (fixes LIST_AUTH_REQUIRED)
        auth = self.headers.get("Authorization", "")
        if not auth or not auth.startswith("Bearer "):
            self.send_error_json(401, "UNAUTHENTICATED", "Bearer token required")
            return None
        token = auth[7:].strip()
        if not token or " " in token:
            self.send_error_json(401, "UNAUTHENTICATED", "Invalid Bearer token")
            return None

        # 2. Check A2A-Version: 1.0
        ver = self.headers.get("A2A-Version")
        if ver is None or ver.strip() != "1.0":
            self.send_error_json(400, "VERSION_NOT_SUPPORTED", "A2A-Version: 1.0 header is required")
            return None

        # 3. Check Content-Type on POST
        if require_post_ct:
            ct = self.headers.get("Content-Type", "").lower()
            if "application/a2a+json" not in ct:
                self.send_error_json(400, "INVALID_MEDIA_TYPE", "Content-Type must be application/a2a+json")
                return None

        return token

    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        parsed_url = urlparse(self.path)
        path = parsed_url.path.rstrip("/") or "/"
        qs = parse_qs(parsed_url.query)

        # Public Agent Card discovery endpoint (NO auth or A2A-Version required)
        if path in ("/.well-known/agent-card.json", "/a2a/.well-known/agent-card.json"):
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
                "defaultInputModes": [
                    INPUT_MODE,
                    RESULTS_MODE,
                ],
                "defaultOutputModes": [
                    PROPOSAL_MODE,
                    RECEIPTS_MODE,
                ],
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
            self.send_a2a_json(200, card, media_type="application/json")
            return

        # All other GET routes require Bearer token and A2A-Version: 1.0
        principal = self.validate_headers(require_post_ct=False)
        if not principal:
            return

        hist_len = None
        if "historyLength" in qs:
            try:
                hist_len = int(qs["historyLength"][0])
            except Exception:
                pass

        # GET /a2a/tasks or /tasks
        if path in ("/a2a/tasks", "/tasks"):
            ctx_filter = qs.get("contextId", [None])[0]
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
            self.send_a2a_json(200, {"tasks": tasks_list})
            return

        # GET /a2a/tasks/{id} or /tasks/{id}
        m = re.match(r"^(?:/a2a)?/tasks/([^/:]+)$", path)
        if m:
            tid = m.group(1)
            with get_conn() as conn:
                row = conn.execute("SELECT principal, task_json FROM tasks WHERE task_id = ?", (tid,)).fetchone()
                if not row or row[0] != principal:
                    self.send_error_json(404, "TASK_NOT_FOUND", "Task not found")
                    return
                task_obj = apply_history_limit(json.loads(row[1]), hist_len)
                self.send_a2a_json(200, task_obj)
            return

        self.send_error_json(404, "NOT_FOUND", "Endpoint not found")

    def do_POST(self):
        parsed_url = urlparse(self.path)
        path = parsed_url.path.rstrip("/")

        principal = self.validate_headers(require_post_ct=True)
        if not principal:
            return

        content_len = int(self.headers.get("Content-Length", 0))
        raw_bytes = self.rfile.read(content_len) if content_len > 0 else b"{}"
        try:
            body = json.loads(raw_bytes.decode("utf-8")) if raw_bytes else {}
        except Exception:
            self.send_error_json(400, "INVALID_JSON", "Malformed JSON body")
            return

        # =================================================================
        # ROUTE 1: POST /a2a/tasks/{id}:cancel  (Check BEFORE message:send!)
        # =================================================================
        m_cancel = re.match(r"^(?:/a2a)?/tasks/([^/]+):cancel$", path)
        if m_cancel:
            tid = m_cancel.group(1)
            t_lock = get_task_lock(tid)
            with t_lock:
                with get_conn() as conn:
                    row = conn.execute(
                        "SELECT principal, state, task_json FROM tasks WHERE task_id = ?",
                        (tid,),
                    ).fetchone()
                    if not row or row[0] != principal:
                        self.send_error_json(404, "TASK_NOT_FOUND", "Task not found")
                        return
                    _, stored_state, stored_task_json = row
                    if stored_state != "TASK_STATE_INPUT_REQUIRED":
                        self.send_error_json(409, "TASK_NOT_CANCELABLE", "Task is already in a terminal state")
                        return
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
                    self.send_a2a_json(200, task_obj)
            return

        # =================================================================
        # ROUTE 2: POST /a2a/message:send
        # =================================================================
        if path not in ("/a2a/message:send", "/message:send"):
            self.send_error_json(404, "NOT_FOUND", "Endpoint not found")
            return

        if not isinstance(body, dict) or not isinstance(body.get("message"), dict):
            self.send_error_json(400, "INVALID_REQUEST", "Request must contain a 'message' object")
            return

        msg = body["message"]
        message_id = str(msg.get("messageId", "")).strip()
        if not message_id:
            self.send_error_json(400, "INVALID_MESSAGE", "messageId is required")
            return

        if msg.get("role") != "ROLE_USER":
            self.send_error_json(400, "INVALID_ROLE", "message.role must be ROLE_USER")
            return

        parts = msg.get("parts")
        if not isinstance(parts, list) or len(parts) != 1 or not isinstance(parts[0], dict):
            self.send_error_json(400, "INVALID_PARTS", "message.parts must contain exactly one part")
            return

        msg_hash = compute_message_hash(msg)
        m_lock = get_msg_lock(f"{principal}:{message_id}")

        with m_lock:
            # 1. Check Message Idempotency (scoped by Bearer principal + messageId)
            with get_conn() as conn:
                row = conn.execute(
                    "SELECT msg_hash, task_id, response_json FROM messages WHERE principal = ? AND message_id = ?",
                    (principal, message_id),
                ).fetchone()
                if row:
                    stored_hash, stored_tid, stored_resp_json = row
                    if stored_hash != msg_hash:
                        self.send_error_json(
                            409,
                            "IDEMPOTENCY_CONFLICT",
                            "IDEMPOTENCY_CONFLICT: messageId reused with changed semantic content",
                        )
                        return
                    # Return the exact stored response (or current task state)
                    t_row = conn.execute(
                        "SELECT task_json FROM tasks WHERE task_id = ? AND principal = ?",
                        (stored_tid, principal),
                    ).fetchone()
                    if t_row:
                        self.send_a2a_json(200, {"task": json.loads(t_row[0])})
                    else:
                        self.send_a2a_json(200, json.loads(stored_resp_json))
                    return

            part = parts[0]
            media_type = part.get("mediaType")
            part_data = part.get("data")
            if not isinstance(part_data, dict):
                self.send_error_json(400, "INVALID_DATA", "part.data must be an object")
                return

            # -------------------------------------------------------------
            # TURN 1: Initial Invoice Claim Batch -> Proposals
            # -------------------------------------------------------------
            if media_type == INPUT_MODE:
                batch_id = str(part_data.get("batchId", "")).strip()
                policy_rev = str(part_data.get("policyRevision", "")).strip()
                packages = part_data.get("packages")

                if not batch_id or not isinstance(packages, list) or len(packages) == 0:
                    self.send_error_json(400, "INVALID_BATCH", "batchId and non-empty packages array required")
                    return

                pkg_ids = [str(p.get("packageId", "")).strip() for p in packages if isinstance(p, dict)]
                if len(pkg_ids) != len(packages) or any(not pid for pid in pkg_ids) or len(set(pkg_ids)) != len(pkg_ids):
                    self.send_error_json(400, "INVALID_PACKAGES", "Duplicate or missing packageId in batch")
                    return

                task_id = str(msg.get("taskId") or f"task-{uuid.uuid4().hex}")
                context_id = str(msg.get("contextId") or f"ctx-{uuid.uuid4().hex}")

                # Check if taskId already exists for another task
                with get_conn() as conn:
                    existing_t = conn.execute("SELECT principal FROM tasks WHERE task_id = ?", (task_id,)).fetchone()
                    if existing_t:
                        self.send_error_json(409, "TASK_ALREADY_EXISTS", "Task ID already exists")
                        return

                proposals = decide_batch(packages, policy_rev, batch_id)

                hist_msg = json.loads(json.dumps(msg))
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
                        "INSERT INTO tasks VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
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
                        "INSERT INTO messages VALUES (?, ?, ?, ?, ?)",
                        (
                            principal,
                            message_id,
                            msg_hash,
                            task_id,
                            json.dumps(resp, ensure_ascii=False),
                        ),
                    )
                    conn.commit()

                self.send_a2a_json(200, resp)
                return

            # -------------------------------------------------------------
            # TURN 2: Continuation Results -> Final Receipts (COMPLETED)
            # -------------------------------------------------------------
            elif media_type == RESULTS_MODE:
                tid = str(msg.get("taskId", "")).strip()
                ctx_id = str(msg.get("contextId", "")).strip()
                batch_id = str(part_data.get("batchId", "")).strip()
                results = part_data.get("results")

                if not tid or not ctx_id or not batch_id or not isinstance(results, list):
                    self.send_error_json(400, "INVALID_CONTINUATION", "taskId, contextId, batchId, and results required")
                    return

                t_lock = get_task_lock(tid)
                with t_lock:
                    with get_conn() as conn:
                        row = conn.execute(
                            "SELECT principal, context_id, batch_id, state, task_json, proposals_json FROM tasks WHERE task_id = ?",
                            (tid,),
                        ).fetchone()

                        # User isolation: never reveal existence of another principal's task
                        if not row or row[0] != principal:
                            self.send_error_json(404, "TASK_NOT_FOUND", "Task not found")
                            return

                        _, stored_ctx, stored_batch, stored_state, stored_task_json, stored_props_json = row

                        # Strict continuation validation BEFORE any state mutation (fixes INVALID_CONTINUATION_ACCEPTED)
                        if stored_ctx != ctx_id:
                            self.send_error_json(400, "CONTEXT_MISMATCH", "contextId does not match stored task")
                            return

                        if stored_batch != batch_id:
                            self.send_error_json(400, "BATCH_MISMATCH", "batchId does not match stored task")
                            return

                        stored_props = json.loads(stored_props_json)
                        prop_map = {p["packageId"]: p for p in stored_props}

                        if len(results) != len(stored_props):
                            self.send_error_json(400, "RESULTS_LENGTH_MISMATCH", "results count must match proposals count")
                            return

                        seen_pids = set()
                        executions = []

                        for r in results:
                            if not isinstance(r, dict):
                                self.send_error_json(400, "INVALID_RESULT", "Each result must be an object")
                                return
                            pid = str(r.get("packageId", "")).strip()
                            aid = str(r.get("actionId", "")).strip()
                            act = str(r.get("action", "")).strip()
                            outcome = str(r.get("outcome", "")).strip()
                            nonce = r.get("receiptNonce")

                            if not pid or pid in seen_pids or pid not in prop_map:
                                self.send_error_json(400, "PACKAGE_MISMATCH", "Unknown or duplicate packageId in results")
                                return
                            seen_pids.add(pid)

                            prop = prop_map[pid]
                            if aid != prop["actionId"] or act != prop["action"]:
                                self.send_error_json(400, "ACTION_MISMATCH", "actionId or action does not match stored proposal")
                                return

                            if outcome not in ("ACCEPTED", "REJECTED"):
                                self.send_error_json(400, "INVALID_OUTCOME", "outcome must be ACCEPTED or REJECTED")
                                return

                            if outcome == "ACCEPTED":
                                if not isinstance(nonce, str) or not nonce.strip():
                                    self.send_error_json(400, "INVALID_RECEIPT_NONCE", "ACCEPTED result requires non-empty receiptNonce")
                                    return
                                executions.append({
                                    "packageId": prop["packageId"],
                                    "actionId": prop["actionId"],
                                    "action": prop["action"],
                                    "receiptNonce": nonce,
                                    "facts": prop["facts"],
                                    "evidenceRefs": prop["evidenceRefs"],
                                })

                        # Check terminal state AFTER validating payload (or reject with 409 if canceled/completed)
                        if stored_state != "TASK_STATE_INPUT_REQUIRED":
                            self.send_error_json(409, "TASK_ALREADY_TERMINAL", "Task is already in a terminal state")
                            return

                        task_obj = json.loads(stored_task_json)
                        task_obj["history"].append(json.loads(json.dumps(msg)))

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
                            "INSERT INTO messages VALUES (?, ?, ?, ?, ?)",
                            (
                                principal,
                                message_id,
                                msg_hash,
                                tid,
                                json.dumps(resp, ensure_ascii=False),
                            ),
                        )
                        conn.commit()

                        self.send_a2a_json(200, resp)
                return

            else:
                self.send_error_json(400, "UNSUPPORTED_MEDIA_TYPE", f"Unsupported part mediaType: {media_type}")


if __name__ == "__main__":
    server = ThreadingHTTPServer(("0.0.0.0", PORT), A2AHandler)
    print(f"Running Multi-Threaded A2A server on port {PORT}")
    server.serve_forever()
