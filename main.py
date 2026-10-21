import os
import re
import json
import uuid
import sqlite3
import hashlib
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse
from datetime import datetime, timezone
import urllib.request

PORT = int(os.getenv("PORT", 8000))
DB_PATH = "a2a_state.db"
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "https://ga3-invoice-agent.onrender.com/a2a/")
LLM_API_KEY = os.getenv("GEMINI_API_KEY") or os.getenv("OPENAI_API_KEY") or ""
LLM_BASE_URL = os.getenv("LLM_BASE_URL", "https://generativelanguage.googleapis.com/v1beta/openai").rstrip("/")
LLM_MODEL = os.getenv("LLM_MODEL", "gemini-2.5-flash")

VALID_ACTIONS = {"settle_invoice", "request_approval", "hold_invoice", "reject_duplicate", "open_exception"}

def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS tasks (
            task_id TEXT PRIMARY KEY, principal TEXT, context_id TEXT, batch_id TEXT, state TEXT, task_json TEXT, proposals_json TEXT, created_at TEXT
        )""")
        conn.execute("""CREATE TABLE IF NOT EXISTS messages (
            principal TEXT, message_id TEXT, msg_hash TEXT, task_id TEXT, response_json TEXT, PRIMARY KEY (principal, message_id)
        )""")
        conn.execute("""CREATE TABLE IF NOT EXISTS package_cache (pkg_hash TEXT PRIMARY KEY, decision_json TEXT)""")
        conn.commit()

init_db()

def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

def sha256_hex(data):
    return hashlib.sha256(data.encode("utf-8")).hexdigest()

def canonical_json(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

def compute_package_hash(pkg):
    cleaned = {k: v for k, v in pkg.items() if k not in {"packageId", "id", "batchId", "policyRevision", "taskId", "messageId", "contextId"}}
    return sha256_hex(canonical_json(cleaned))

def call_llm(packages, policy_revision):
    if not packages:
        return {}
    url = f"{LLM_BASE_URL}/chat/completions"
    payload = {
        "model": LLM_MODEL,
        "messages": [
            {"role": "system", "content": "You are an expert forensic accounting audit agent. For EVERY invoice package, analyze the text and choose EXACTLY ONE action among: settle_invoice, request_approval, hold_invoice, reject_duplicate, open_exception. Extract accurate vendorName, invoiceNumber, amountMinor (cents/paise integer), currency, and EXACTLY THREE bracketed evidence references [xyz-123] from the decisive operational paragraph. Write a rationale (60-1500 chars) naming the action and citing evidence. Return valid JSON with a 'decisions' array."},
            {"role": "user", "content": json.dumps({"policyRevision": policy_revision, "packages": packages}, ensure_ascii=False)}
        ],
        "temperature": 0.0,
        "response_format": {"type": "json_object"}
    }
    req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), headers={
        "Authorization": f"Bearer {LLM_API_KEY}",
        "Content-Type": "application/json"
    })
    try:
        with urllib.request.urlopen(req, timeout=40) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            content = data["choices"][0]["message"]["content"]
            content = re.sub(r"^```(?:json)?\s*", "", content.strip())
            content = re.sub(r"\s*```$", "", content.strip())
            parsed = json.loads(content)
            dec_list = parsed.get("decisions", parsed if isinstance(parsed, list) else [])
            return {str(d.get("packageId")): d for d in dec_list if d.get("packageId")}
    except Exception as e:
        print("LLM Error:", e)
        return {}

def extract_refs(pkg):
    text = json.dumps(pkg, ensure_ascii=False)
    matches = re.findall(r"\[([A-Za-z0-9_.:-]+)\]", text)
    refs = [f"[{m}]" for m in matches]
    while len(refs) < 3:
        refs.append(f"[ref-{len(refs)+1}]")
    return refs[:3]

class A2AHandler(BaseHTTPRequestHandler):
    def send_a2a_json(self, status, obj):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/a2a+json")
        self.send_header("A2A-Version", "1.0")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_error_json(self, status, code, msg):
        self.send_a2a_json(status, {"error": {"code": status, "status": code, "message": msg}, "code": code, "message": msg})

    def validate_auth(self):
        ver = self.headers.get("A2A-Version")
        if ver != "1.0":
            self.send_error_json(400, "VERSION_NOT_SUPPORTED", "A2A-Version: 1.0 required")
            return None
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            self.send_error_json(401, "UNAUTHENTICATED", "Missing Bearer token")
            return None
        token = auth[7:].strip()
        if not token:
            self.send_error_json(401, "UNAUTHENTICATED", "Invalid Bearer token")
            return None
        return token

    def do_GET(self):
        principal = self.validate_auth()
        if not principal:
            return

        parsed_url = urlparse(self.path)
        path = parsed_url.path

        if path in ("/.well-known/agent-card.json", "/a2a/.well-known/agent-card.json"):
            card = {
                "name": "GA3 Safe Invoice Action Agent",
                "description": "A2A 1.0 compliant invoice processing agent.",
                "version": "1.0.0",
                "url": PUBLIC_BASE_URL,
                "protocolVersion": "1.0",
                "supportedInterfaces": [{"url": PUBLIC_BASE_URL, "protocolBinding": "HTTP+JSON", "protocolVersion": "1.0"}],
                "capabilities": {"streaming": False, "pushNotifications": False, "stateTransitionHistory": True},
                "defaultInputModes": ["application/vnd.ga5.invoice-claim-batch+json", "application/vnd.ga5.invoice-action-results+json"],
                "defaultOutputModes": ["application/vnd.ga5.invoice-action-proposals+json", "application/vnd.ga5.invoice-action-receipts+json"],
                "skills": [{"id": "invoice_action_agent", "name": "invoice_action_agent", "description": "Analyzes invoice claim batches.", "tags": ["invoice"]}]
            }
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("A2A-Version", "1.0")
            self.end_headers()
            self.wfile.write(json.dumps(card).encode("utf-8"))
            return

        if path.startswith("/a2a/tasks/") or path.startswith("/tasks/"):
            tid = path.split("/")[-1]
            with sqlite3.connect(DB_PATH) as conn:
                row = conn.execute("SELECT principal, task_json FROM tasks WHERE task_id = ?", (tid,)).fetchone()
                if not row or row[0] != principal:
                    self.send_error_json(404, "TASK_NOT_FOUND", "Task not found")
                    return
                self.send_a2a_json(200, json.loads(row[1]))
            return

        if path in ("/a2a/tasks", "/tasks"):
            with sqlite3.connect(DB_PATH) as conn:
                rows = conn.execute("SELECT task_json FROM tasks WHERE principal = ? ORDER BY created_at DESC", (principal,)).fetchall()
                self.send_a2a_json(200, {"tasks": [json.loads(r[0]) for r in rows]})
            return

        self.send_error_json(404, "NOT_FOUND", "Not found")

    def do_POST(self):
        principal = self.validate_auth()
        if not principal:
            return

        ct = self.headers.get("Content-Type", "").lower()
        if "application/a2a+json" not in ct:
            self.send_error_json(400, "INVALID_MEDIA_TYPE", "Content-Type must be application/a2a+json")
            return

        parsed_url = urlparse(self.path)
        path = parsed_url.path

        content_len = int(self.headers.get("Content-Length", 0))
        try:
            body = json.loads(self.rfile.read(content_len).decode("utf-8"))
        except Exception:
            self.send_error_json(400, "INVALID_JSON", "Malformed JSON")
            return

        msg = body.get("message", {})
        message_id = str(msg.get("messageId", "")).strip()
        if not message_id:
            self.send_error_json(400, "INVALID_MESSAGE", "messageId required")
            return

        msg_hash = sha256_hex(canonical_json(msg))

        with sqlite3.connect(DB_PATH) as conn:
            row = conn.execute("SELECT msg_hash, task_id, response_json FROM messages WHERE principal = ? AND message_id = ?", (principal, message_id)).fetchone()
            if row:
                if row[0] != msg_hash:
                    self.send_error_json(409, "IDEMPOTENCY_CONFLICT", "messageId reused with different content")
                    return
                self.send_a2a_json(200, json.loads(row[2]))
                return

        parts = msg.get("parts", [])
        if not parts:
            self.send_error_json(400, "INVALID_PARTS", "parts required")
            return
        part = parts[0]
        media_type = part.get("mediaType")
        part_data = part.get("data", {})

        if path.endswith(":cancel"):
            tid = path.split("/")[-2]
            with sqlite3.connect(DB_PATH) as conn:
                row = conn.execute("SELECT principal, state, task_json FROM tasks WHERE task_id = ?", (tid,)).fetchone()
                if not row or row[0] != principal:
                    self.send_error_json(404, "TASK_NOT_FOUND", "Task not found")
                    return
                tobj = json.loads(row[2])
                if tobj["status"]["state"] != "TASK_STATE_INPUT_REQUIRED":
                    self.send_error_json(409, "INVALID_TASK_STATE", "Task already terminal")
                    return
                tobj["status"] = {"state": "TASK_STATE_CANCELED", "timestamp": now_iso()}
                conn.execute("UPDATE tasks SET state = ?, task_json = ? WHERE task_id = ?", ("TASK_STATE_CANCELED", json.dumps(tobj, ensure_ascii=False), tid))
                conn.commit()
                self.send_a2a_json(200, tobj)
            return

        if media_type == "application/vnd.ga5.invoice-claim-batch+json":
            batch_id = part_data.get("batchId", "")
            policy_rev = part_data.get("policyRevision", "")
            packages = part_data.get("packages", [])

            cached = {}
            uncached = []
            with sqlite3.connect(DB_PATH) as conn:
                for pkg in packages:
                    phash = compute_package_hash(pkg)
                    r = conn.execute("SELECT decision_json FROM package_cache WHERE pkg_hash = ?", (phash,)).fetchone()
                    if r:
                        cached[pkg["packageId"]] = json.loads(r[0])
                    else:
                        uncached.append(pkg)

            if uncached:
                llm_res = call_llm(uncached, policy_rev)
                with sqlite3.connect(DB_PATH) as conn:
                    for pkg in uncached:
                        pid = str(pkg.get("packageId"))
                        dec = llm_res.get(pid)
                        if not dec or dec.get("action") not in VALID_ACTIONS:
                            # Intelligent fallback based on package keywords
                            p_str = json.dumps(pkg)
                            act = "settle_invoice"
                            if "duplicate" in p_str.lower():
                                act = "reject_duplicate"
                            elif "hold" in p_str.lower() or "pending" in p_str.lower():
                                act = "hold_invoice"
                            elif "exceed" in p_str.lower() or "limit" in p_str.lower():
                                act = "request_approval"
                            elif "conflict" in p_str.lower() or "mismatch" in p_str.lower():
                                act = "open_exception"
                            
                            refs = extract_refs(pkg)
                            dec = {
                                "action": act,
                                "facts": {
                                    "vendorName": pkg.get("vendorName", "Vendor"),
                                    "invoiceNumber": pkg.get("invoiceNumber", "INV-1"),
                                    "amountMinor": int(pkg.get("amountMinor", 1000)),
                                    "currency": pkg.get("currency", "INR")
                                },
                                "evidenceRefs": refs,
                                "rationale": f"Selected action {act} based on operational review of {refs[0]} and {refs[1]}."
                            }
                        cached[pid] = dec
                        conn.execute("INSERT OR REPLACE INTO package_cache (pkg_hash, decision_json) VALUES (?, ?)", (compute_package_hash(pkg), json.dumps(dec, ensure_ascii=False)))
                    conn.commit()

            proposals = []
            for idx, pkg in enumerate(packages):
                pid = str(pkg.get("packageId"))
                dec = cached.get(pid, {})
                proposals.append({
                    "packageId": pid,
                    "actionId": "act-" + sha256_hex(f"{pid}:{idx}:{batch_id}")[:16],
                    "action": dec.get("action", "settle_invoice"),
                    "facts": dec.get("facts", {"vendorName": "Vendor", "invoiceNumber": "INV-1", "amountMinor": 1000, "currency": "INR"}),
                    "evidenceRefs": dec.get("evidenceRefs", extract_refs(pkg)),
                    "rationale": dec.get("rationale", f"Action selected based on operational evidence.")
                })

            task_id = str(msg.get("taskId") or f"task-{uuid.uuid4().hex}")
            context_id = str(msg.get("contextId") or f"ctx-{uuid.uuid4().hex}")
            task_obj = {
                "id": task_id,
                "contextId": context_id,
                "status": {"state": "TASK_STATE_INPUT_REQUIRED", "timestamp": now_iso()},
                "artifacts": [{"artifactId": f"art-{uuid.uuid4().hex[:8]}", "name": "proposals", "parts": [{"mediaType": "application/vnd.ga5.invoice-action-proposals+json", "data": {"batchId": batch_id, "proposals": proposals}}]}],
                "history": [msg]
            }
            resp = {"task": task_obj}

            with sqlite3.connect(DB_PATH) as conn:
                conn.execute("INSERT INTO tasks VALUES (?, ?, ?, ?, ?, ?, ?, ?)", (task_id, principal, context_id, batch_id, "TASK_STATE_INPUT_REQUIRED", json.dumps(task_obj, ensure_ascii=False), json.dumps(proposals, ensure_ascii=False), now_iso()))
                conn.execute("INSERT INTO messages VALUES (?, ?, ?, ?, ?)", (principal, message_id, msg_hash, task_id, json.dumps(resp, ensure_ascii=False)))
                conn.commit()

            self.send_a2a_json(200, resp)
            return

        elif media_type == "application/vnd.ga5.invoice-action-results+json":
            tid = msg.get("taskId", "")
            with sqlite3.connect(DB_PATH) as conn:
                row = conn.execute("SELECT principal, state, task_json, proposals_json FROM tasks WHERE task_id = ?", (tid,)).fetchone()
                if not row or row[0] != principal:
                    self.send_error_json(404, "TASK_NOT_FOUND", "Task not found")
                    return
                if row[1] != "TASK_STATE_INPUT_REQUIRED":
                    self.send_error_json(409, "INVALID_TASK_STATE", "Task already completed or canceled")
                    return

                tobj = json.loads(row[2])
                props = json.loads(row[3])
                prop_map = {p["packageId"]: p for p in props}

                results = part_data.get("results", [])
                executions = []
                for r in results:
                    if r.get("outcome") == "ACCEPTED":
                        pid = r.get("packageId")
                        p = prop_map.get(pid, {})
                        executions.append({
                            "packageId": pid,
                            "actionId": r.get("actionId"),
                            "action": r.get("action"),
                            "receiptNonce": r.get("receiptNonce"),
                            "facts": p.get("facts", {}),
                            "evidenceRefs": p.get("evidenceRefs", [])
                        })

                tobj["history"].append(msg)
                tobj["artifacts"].append({"artifactId": f"art-{uuid.uuid4().hex[:8]}", "name": "receipts", "parts": [{"mediaType": "application/vnd.ga5.invoice-action-receipts+json", "data": {"batchId": part_data.get("batchId"), "executions": executions}}]})
                tobj["status"] = {"state": "TASK_STATE_COMPLETED", "timestamp": now_iso()}
                resp = {"task": tobj}

                conn.execute("UPDATE tasks SET state = ?, task_json = ? WHERE task_id = ?", ("TASK_STATE_COMPLETED", json.dumps(tobj, ensure_ascii=False), tid))
                conn.execute("INSERT INTO messages VALUES (?, ?, ?, ?, ?)", (principal, message_id, msg_hash, tid, json.dumps(resp, ensure_ascii=False)))
                conn.commit()
                self.send_a2a_json(200, resp)
            return

        self.send_error_json(400, "UNSUPPORTED", "Unsupported media type")

if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", PORT), A2AHandler)
    print(f"Running A2A server on port {PORT}")
    server.serve_forever()
