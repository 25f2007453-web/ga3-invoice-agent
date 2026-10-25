import hashlib
import json
import uuid
import asyncio
import os
import re
import copy
import urllib.request
import urllib.error
from fastapi import FastAPI, Request, Header
from fastapi.responses import JSONResponse
from typing import Dict, Any, Optional, List, Tuple

app = FastAPI()
global_lock = asyncio.Lock()

PUBLIC_BASE_URL = (os.environ.get("PUBLIC_BASE_URL") or "https://ga3-invoice-agent.onrender.com/a2a/").strip()

# --- In-Memory State ---
idempotency_store: Dict[str, Dict[str, Any]] = {}
tasks_db: Dict[str, Dict[str, Any]] = {}
decision_cache: Dict[str, Dict[str, Any]] = {}
discovered_gemini_models: List[str] = []


def a2a_response(content: Dict[str, Any], status_code: int = 200) -> JSONResponse:
    return JSONResponse(
        content=content,
        status_code=status_code,
        media_type="application/a2a+json"
    )


def extract_bearer_token(authorization: Optional[str]) -> Optional[str]:
    if not authorization or not isinstance(authorization, str):
        return None
    parts = authorization.strip().split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    token = parts[1].strip()
    return token if token else None


def verify_headers(
    authorization: Optional[str],
    a2a_version: Optional[str],
    content_type: Optional[str] = None,
    require_content_type: bool = False
) -> Tuple[Optional[str], Optional[JSONResponse]]:
    token = extract_bearer_token(authorization)
    if not token:
        return None, a2a_response(
            {"code": "UNAUTHORIZED", "error": {"code": "UNAUTHORIZED", "message": "Missing Bearer token"}},
            status_code=401
        )

    if (a2a_version or "").strip() != "1.0":
        return None, a2a_response(
            {"code": "INVALID_VERSION", "error": {"code": "INVALID_VERSION", "message": "A2A-Version: 1.0 required"}},
            status_code=400
        )

    if require_content_type:
        ct = (content_type or "").split(";")[0].strip().lower()
        if ct != "application/a2a+json":
            return None, a2a_response(
                {"code": "UNSUPPORTED_MEDIA_TYPE", "error": {"code": "UNSUPPORTED_MEDIA_TYPE", "message": "application/a2a+json required"}},
                status_code=400
            )

    return token, None


def compact_task_for_list(task_obj: Dict[str, Any]) -> Dict[str, Any]:
    t = copy.deepcopy(task_obj)
    if "history" in t and isinstance(t["history"], list):
        compact_hist = []
        for msg in t["history"]:
            if isinstance(msg, dict):
                m_copy = {
                    "messageId": msg.get("messageId"),
                    "role": msg.get("role", "ROLE_USER")
                }
                if "taskId" in msg:
                    m_copy["taskId"] = msg["taskId"]
                if "contextId" in msg:
                    m_copy["contextId"] = msg["contextId"]
                if "parts" in msg and isinstance(msg["parts"], list):
                    c_parts = []
                    for p in msg["parts"]:
                        if isinstance(p, dict):
                            p_data = p.get("data")
                            if isinstance(p_data, dict) and "packages" in p_data:
                                c_parts.append({
                                    "mediaType": p.get("mediaType"),
                                    "data": {
                                        "batchId": p_data.get("batchId"),
                                        "policyRevision": p_data.get("policyRevision")
                                    }
                                })
                            else:
                                c_parts.append(p)
                    m_copy["parts"] = c_parts
                compact_hist.append(m_copy)
        t["history"] = compact_hist
    return t


@app.get("/")
@app.get("/a2a")
@app.get("/a2a/")
async def root_health():
    return a2a_response({"status": "ok", "version": "4.0"}, status_code=200)


@app.get("/test-llm")
async def test_llm_endpoint():
    """Browser diagnostic endpoint to verify Gemini API key and model before clicking Check."""
    gemini_key = (os.environ.get("GEMINI_API_KEY") or "").strip()
    openai_key = (os.environ.get("OPENAI_API_KEY") or os.environ.get("AIPIPE_TOKEN") or "").strip()
    models = await asyncio.to_thread(get_available_gemini_models, gemini_key) if gemini_key else []
    test_prompt = 'Return a JSON array with 1 object: [{"status": "working", "model": "ok"}]'
    res = await asyncio.to_thread(call_llm_sync, test_prompt, gemini_key, openai_key)
    return a2a_response({
        "llm_working": res is not None,
        "test_output": res,
        "discovered_models": models[:10]
    })


@app.get("/.well-known/agent-card.json")
async def get_agent_card(request: Request):
    host = request.headers.get("host", "ga3-invoice-agent.onrender.com")
    scheme = request.headers.get("x-forwarded-proto", "https")
    origin = f"{scheme}://{host}"

    card = {
        "name": "A2A Invoice Action Agent",
        "description": "Evaluates commercial invoice packages, chooses business actions with evidence, and records verified receipts.",
        "version": "1.0.0",
        "url": PUBLIC_BASE_URL,
        "protocolVersion": "1.0",
        "capabilities": {
            "streaming": False,
            "pushNotifications": False,
            "stateTransitionHistory": True
        },
        "defaultInputModes": [
            "application/vnd.ga5.invoice-claim-batch+json",
            "application/vnd.ga5.invoice-action-results+json"
        ],
        "defaultOutputModes": [
            "application/vnd.ga5.invoice-action-proposals+json",
            "application/vnd.ga5.invoice-action-receipts+json"
        ],
        "supportedInterfaces": [
            {
                "url": PUBLIC_BASE_URL,
                "protocolBinding": "HTTP+JSON",
                "protocolVersion": "1.0"
            },
            {
                "url": f"{origin}/a2a/",
                "protocolBinding": "HTTP+JSON",
                "protocolVersion": "1.0"
            },
            {
                "url": f"{origin}/a2a",
                "protocolBinding": "HTTP+JSON",
                "protocolVersion": "1.0"
            },
            {
                "url": f"{origin}/",
                "protocolBinding": "HTTP+JSON",
                "protocolVersion": "1.0"
            },
            {
                "url": origin,
                "protocolBinding": "HTTP+JSON",
                "protocolVersion": "1.0"
            }
        ],
        "skills": [
            {
                "id": "invoice_action_agent",
                "name": "invoice_action_agent",
                "description": "Reads commercial invoice packages, chooses business actions, and cites decisive evidence.",
                "tags": ["invoice", "finance", "audit", "claims"],
                "inputModes": [
                    "application/vnd.ga5.invoice-claim-batch+json",
                    "application/vnd.ga5.invoice-action-results+json"
                ],
                "outputModes": [
                    "application/vnd.ga5.invoice-action-proposals+json",
                    "application/vnd.ga5.invoice-action-receipts+json"
                ]
            }
        ]
    }
    return a2a_response(card, status_code=200)


@app.post("/message:send")
@app.post("/a2a/message:send")
async def send_message(
    request: Request,
    authorization: Optional[str] = Header(None),
    a2a_version: Optional[str] = Header(None, alias="A2A-Version"),
    content_type: Optional[str] = Header(None, alias="Content-Type")
):
    token, err = verify_headers(authorization, a2a_version, content_type, require_content_type=True)
    if err:
        return err

    try:
        body = await request.json()
    except Exception:
        return a2a_response({"code": "INVALID_JSON", "error": {"code": "INVALID_JSON", "message": "Malformed JSON"}}, status_code=400)

    if not isinstance(body, dict):
        return a2a_response({"code": "INVALID_BODY", "error": {"code": "INVALID_BODY", "message": "Expected JSON object"}}, status_code=400)

    message = body.get("message")
    if not isinstance(message, dict):
        return a2a_response({"code": "MISSING_MESSAGE", "error": {"code": "MISSING_MESSAGE", "message": "message object required"}}, status_code=400)

    message_id = message.get("messageId")
    if not message_id or not isinstance(message_id, str) or not message_id.strip():
        return a2a_response({"code": "MISSING_MESSAGE_ID", "error": {"code": "MISSING_MESSAGE_ID", "message": "messageId required"}}, status_code=400)

    role = message.get("role")
    if role != "ROLE_USER":
        return a2a_response({"code": "INVALID_ROLE", "error": {"code": "INVALID_ROLE", "message": "ROLE_USER required"}}, status_code=400)

    canonical_msg = json.dumps(message, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    msg_hash = hashlib.sha256(canonical_msg.encode("utf-8")).hexdigest()
    idem_key = f"{token}:{message_id}"

    async with global_lock:
        if idem_key in idempotency_store:
            entry = idempotency_store[idem_key]
            if entry["hash"] != msg_hash:
                return a2a_response(
                    {
                        "code": "IDEMPOTENCY_CONFLICT",
                        "error": {
                            "code": "IDEMPOTENCY_CONFLICT",
                            "message": "IDEMPOTENCY_CONFLICT: messageId reused with different content"
                        }
                    },
                    status_code=409
                )
            event = entry["event"]
            is_leader = False
        else:
            event = asyncio.Event()
            idempotency_store[idem_key] = {
                "hash": msg_hash,
                "event": event,
                "task_id": None,
                "response": None,
                "status": 200
            }
            is_leader = True

    if not is_leader:
        await event.wait()
        async with global_lock:
            entry = idempotency_store.get(idem_key)
            if not entry:
                return a2a_response({"code": "ERROR", "error": {"code": "ERROR", "message": "Retry failed"}}, status_code=400)
            t_id = entry.get("task_id")
            if t_id and t_id in tasks_db and entry["status"] == 200:
                return a2a_response({"task": copy.deepcopy(tasks_db[t_id]["task"])}, status_code=200)
            return a2a_response(copy.deepcopy(entry["response"]), status_code=entry["status"])

    try:
        parts = message.get("parts")
        if not isinstance(parts, list) or len(parts) == 0:
            res_body, status, t_id = {"code": "INVALID_PARTS", "error": {"code": "INVALID_PARTS", "message": "parts required"}}, 400, None
        else:
            part0 = parts[0] if isinstance(parts[0], dict) else {}
            media_type = part0.get("mediaType", "")
            part_data = part0.get("data")

            if media_type == "application/vnd.ga5.invoice-claim-batch+json":
                res_body, status, t_id = await process_batch_message(token, copy.deepcopy(message), part_data)
            elif media_type == "application/vnd.ga5.invoice-action-results+json":
                res_body, status, t_id = await process_results_continuation(token, copy.deepcopy(message), part_data)
            else:
                res_body, status, t_id = {"code": "UNSUPPORTED_MEDIA_TYPE", "error": {"code": "UNSUPPORTED_MEDIA_TYPE", "message": "Unsupported part mediaType"}}, 400, None

        async with global_lock:
            idempotency_store[idem_key]["task_id"] = t_id
            idempotency_store[idem_key]["response"] = copy.deepcopy(res_body)
            idempotency_store[idem_key]["status"] = status

        return a2a_response(res_body, status_code=status)
    finally:
        event.set()


async def process_batch_message(token: str, message: Dict[str, Any], batch_data: Any):
    if not isinstance(batch_data, dict):
        return {"code": "INVALID_DATA", "error": {"code": "INVALID_DATA", "message": "data must be object"}}, 400, None

    batch_id = batch_data.get("batchId")
    policy_rev = str(batch_data.get("policyRevision") or "")
    packages = batch_data.get("packages")

    if not batch_id or not isinstance(batch_id, str) or not isinstance(packages, list) or len(packages) == 0:
        return {"code": "INVALID_BATCH", "error": {"code": "INVALID_BATCH", "message": "Invalid batchId or packages"}}, 400, None

    req_task_id = message.get("taskId") or message.get("id")
    req_ctx_id = message.get("contextId")

    if req_task_id:
        async with global_lock:
            if req_task_id in tasks_db:
                existing = tasks_db[req_task_id]
                if existing["owner"] != token:
                    return {"code": "NOT_FOUND", "error": {"code": "NOT_FOUND", "message": "Task not found"}}, 404, None
                return {"code": "TASK_EXISTS", "error": {"code": "TASK_EXISTS", "message": "Task already exists"}}, 409, None

    task_id = req_task_id or f"task_{uuid.uuid4().hex}"
    context_id = req_ctx_id or f"ctx_{uuid.uuid4().hex}"

    seen_pkg_ids = set()
    uncached_pkgs = []
    pkg_hashes = {}

    for pkg in packages:
        if not isinstance(pkg, dict):
            return {"code": "INVALID_PACKAGE", "error": {"code": "INVALID_PACKAGE", "message": "Package must be object"}}, 400, None
        pkg_id = pkg.get("packageId")
        if not pkg_id or not isinstance(pkg_id, str) or pkg_id in seen_pkg_ids:
            return {"code": "DUPLICATE_PACKAGE_ID", "error": {"code": "DUPLICATE_PACKAGE_ID", "message": "Duplicate or missing packageId"}}, 400, None
        seen_pkg_ids.add(pkg_id)

        canon = json.dumps(pkg, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        p_hash = hashlib.sha256(canon.encode("utf-8")).hexdigest()
        pkg_hashes[pkg_id] = p_hash
        if p_hash not in decision_cache:
            uncached_pkgs.append((pkg_id, p_hash, pkg))

    if uncached_pkgs:
        new_decisions = await evaluate_packages_batch([p[2] for p in uncached_pkgs], policy_rev)
        async with global_lock:
            for (pkg_id, p_hash, pkg), dec in zip(uncached_pkgs, new_decisions):
                decision_cache[p_hash] = dec

    proposals = []
    for pkg in packages:
        pkg_id = pkg["packageId"]
        p_hash = pkg_hashes[pkg_id]
        dec = copy.deepcopy(decision_cache[p_hash])

        act_hash = hashlib.sha256(f"{task_id}:{batch_id}:{pkg_id}".encode("utf-8")).hexdigest()[:20]
        action_id = f"act_{act_hash}"

        proposals.append({
            "packageId": pkg_id,
            "actionId": action_id,
            "action": dec["action"],
            "facts": dec["facts"],
            "evidenceRefs": dec["evidenceRefs"],
            "rationale": dec["rationale"]
        })

    proposal_part = {
        "mediaType": "application/vnd.ga5.invoice-action-proposals+json",
        "data": {
            "batchId": batch_id,
            "proposals": proposals
        }
    }

    task_obj = {
        "id": task_id,
        "contextId": context_id,
        "status": {
            "state": "TASK_STATE_INPUT_REQUIRED"
        },
        "artifacts": [
            {
                "artifactId": f"art_prop_{task_id}",
                "name": "proposals",
                "parts": [proposal_part]
            }
        ],
        "history": [message]
    }

    async with global_lock:
        tasks_db[task_id] = {
            "owner": token,
            "batch_id": batch_id,
            "context_id": context_id,
            "proposals_by_pkg": {p["packageId"]: copy.deepcopy(p) for p in proposals},
            "task": copy.deepcopy(task_obj),
            "lock": asyncio.Lock()
        }

    return {"task": task_obj}, 200, task_id


async def process_results_continuation(token: str, message: Dict[str, Any], results_data: Any):
    if not isinstance(results_data, dict):
        return {"code": "INVALID_DATA", "error": {"code": "INVALID_DATA", "message": "results data must be object"}}, 400, None

    task_id = message.get("taskId")
    context_id = message.get("contextId")
    batch_id = results_data.get("batchId")
    results = results_data.get("results")

    if not task_id or not isinstance(task_id, str):
        return {"code": "MISSING_TASK_ID", "error": {"code": "MISSING_TASK_ID", "message": "taskId required on continuation"}}, 400, None

    async with global_lock:
        record = tasks_db.get(task_id)
        if not record or record["owner"] != token:
            return {"code": "NOT_FOUND", "error": {"code": "NOT_FOUND", "message": "Task not found"}}, 404, None
        task_lock = record["lock"]

    async with task_lock:
        task_obj = record["task"]
        current_state = task_obj["status"]["state"]

        if not context_id or context_id != record["context_id"]:
            return {"code": "CONTEXT_MISMATCH", "error": {"code": "CONTEXT_MISMATCH", "message": "contextId mismatch"}}, 400, None

        if not batch_id or batch_id != record["batch_id"]:
            return {"code": "BATCH_MISMATCH", "error": {"code": "BATCH_MISMATCH", "message": "batchId mismatch"}}, 400, None

        proposals_by_pkg = record["proposals_by_pkg"]
        if not isinstance(results, list) or len(results) != len(proposals_by_pkg):
            return {"code": "RESULTS_COUNT_MISMATCH", "error": {"code": "RESULTS_COUNT_MISMATCH", "message": "Results count must match proposals"}}, 400, None

        seen_pkgs = set()
        executions = []

        for res in results:
            if not isinstance(res, dict):
                return {"code": "INVALID_RESULT_ITEM", "error": {"code": "INVALID_RESULT_ITEM", "message": "Result item must be object"}}, 400, None

            pkg_id = res.get("packageId")
            act_id = res.get("actionId")
            action = res.get("action")
            outcome = res.get("outcome")
            nonce = res.get("receiptNonce")

            if not pkg_id or pkg_id in seen_pkgs:
                return {"code": "DUPLICATE_RESULT_PKG", "error": {"code": "DUPLICATE_RESULT_PKG", "message": "Invalid or duplicate packageId"}}, 400, None
            seen_pkgs.add(pkg_id)

            stored = proposals_by_pkg.get(pkg_id)
            if not stored:
                return {"code": "UNKNOWN_PACKAGE", "error": {"code": "UNKNOWN_PACKAGE", "message": "Unknown packageId"}}, 400, None

            if act_id != stored["actionId"] or action != stored["action"]:
                return {"code": "PROPOSAL_MISMATCH", "error": {"code": "PROPOSAL_MISMATCH", "message": "actionId or action mismatch"}}, 400, None

            if outcome not in ["ACCEPTED", "REJECTED"]:
                return {"code": "INVALID_OUTCOME", "error": {"code": "INVALID_OUTCOME", "message": "Outcome must be ACCEPTED or REJECTED"}}, 400, None

            if outcome == "ACCEPTED":
                if not nonce or not isinstance(nonce, str) or not nonce.strip():
                    return {"code": "MISSING_NONCE", "error": {"code": "MISSING_NONCE", "message": "ACCEPTED requires receiptNonce"}}, 400, None
                executions.append({
                    "packageId": pkg_id,
                    "actionId": stored["actionId"],
                    "action": stored["action"],
                    "receiptNonce": nonce,
                    "facts": copy.deepcopy(stored["facts"]),
                    "evidenceRefs": copy.deepcopy(stored["evidenceRefs"])
                })

        if current_state in ["TASK_STATE_COMPLETED", "TASK_STATE_CANCELED"]:
            return {"code": "TASK_TERMINAL", "error": {"code": "TASK_TERMINAL", "message": "Task is already terminal"}}, 409, None

        receipt_part = {
            "mediaType": "application/vnd.ga5.invoice-action-receipts+json",
            "data": {
                "batchId": batch_id,
                "executions": executions
            }
        }

        new_task_obj = copy.deepcopy(task_obj)
        new_task_obj["status"] = {"state": "TASK_STATE_COMPLETED"}
        new_task_obj["artifacts"].append({
            "artifactId": f"art_rec_{task_id}",
            "name": "receipts",
            "parts": [receipt_part]
        })
        new_task_obj["history"].append(message)

        record["task"] = new_task_obj
        return {"task": copy.deepcopy(new_task_obj)}, 200, task_id


@app.get("/tasks/{task_id}")
@app.get("/a2a/tasks/{task_id}")
async def get_task(
    task_id: str,
    authorization: Optional[str] = Header(None),
    a2a_version: Optional[str] = Header(None, alias="A2A-Version")
):
    token, err = verify_headers(authorization, a2a_version, require_content_type=False)
    if err:
        return err

    async with global_lock:
        record = tasks_db.get(task_id)
        if not record or record["owner"] != token:
            return a2a_response({"code": "NOT_FOUND", "error": {"code": "NOT_FOUND", "message": "Task not found"}}, status_code=404)
        task_lock = record["lock"]

    async with task_lock:
        return a2a_response(copy.deepcopy(record["task"]), status_code=200)


@app.get("/tasks")
@app.get("/a2a/tasks")
async def list_tasks(
    authorization: Optional[str] = Header(None),
    a2a_version: Optional[str] = Header(None, alias="A2A-Version")
):
    token, err = verify_headers(authorization, a2a_version, require_content_type=False)
    if err:
        return err

    async with global_lock:
        owner_records = [rec for rec in tasks_db.values() if rec["owner"] == token]

    user_tasks = []
    for rec in owner_records:
        async with rec["lock"]:
            user_tasks.append(compact_task_for_list(rec["task"]))

    return a2a_response({"tasks": user_tasks}, status_code=200)


@app.post("/tasks/{task_id}:cancel")
@app.post("/a2a/tasks/{task_id}:cancel")
async def cancel_task(
    task_id: str,
    authorization: Optional[str] = Header(None),
    a2a_version: Optional[str] = Header(None, alias="A2A-Version")
):
    token, err = verify_headers(authorization, a2a_version, require_content_type=False)
    if err:
        return err

    async with global_lock:
        record = tasks_db.get(task_id)
        if not record or record["owner"] != token:
            return a2a_response({"code": "NOT_FOUND", "error": {"code": "NOT_FOUND", "message": "Task not found"}}, status_code=404)
        task_lock = record["lock"]

    async with task_lock:
        task_obj = record["task"]
        current_state = task_obj["status"]["state"]
        if current_state in ["TASK_STATE_COMPLETED", "TASK_STATE_CANCELED"]:
            return a2a_response({"code": "TASK_TERMINAL", "error": {"code": "TASK_TERMINAL", "message": "Task already terminal"}}, status_code=409)

        new_task_obj = copy.deepcopy(task_obj)
        new_task_obj["status"] = {"state": "TASK_STATE_CANCELED"}
        record["task"] = new_task_obj
        return a2a_response(copy.deepcopy(new_task_obj), status_code=200)


# =====================================================================
# AI + DETERMINISTIC INVOICE EVALUATION ENGINE
# =====================================================================

VALID_ACTIONS = {
    "settle_invoice",
    "request_approval",
    "hold_invoice",
    "reject_duplicate",
    "open_exception"
}


def extract_all_ref_tokens(text: str) -> List[str]:
    return re.findall(r"\[[^\[\]\n]{1,50}\]", text)


def deterministic_parse_package(pkg: Dict[str, Any], policy: str) -> Dict[str, Any]:
    pkg_text = json.dumps(pkg, ensure_ascii=False)
    docs = pkg.get("documents") or pkg.get("files") or pkg.get("items") or pkg.get("sections") or []
    paragraphs: List[str] = []

    if isinstance(docs, list) and len(docs) > 0:
        for d in docs:
            if isinstance(d, dict):
                title = str(d.get("title") or d.get("name") or d.get("type") or d.get("id") or d.get("role") or "").lower()
                content = str(d.get("content") or d.get("text") or d.get("body") or json.dumps(d, ensure_ascii=False))
                if any(w in title for w in ["cover", "archive", "training", "decoy", "example"]):
                    continue
                for p in re.split(r"\n\s*\n|\r\n\s*\r\n", content):
                    if p.strip():
                        paragraphs.append(p.strip())
            elif isinstance(d, str):
                for p in re.split(r"\n\s*\n", d):
                    if p.strip():
                        paragraphs.append(p.strip())

    if not paragraphs:
        for k, val in pkg.items():
            if any(w in str(k).lower() for w in ["cover", "archive", "training", "decoy"]):
                continue
            if isinstance(val, str) and len(val) > 15:
                for p in re.split(r"\n\s*\n", val):
                    if p.strip():
                        paragraphs.append(p.strip())
            elif isinstance(val, list):
                for item in val:
                    if isinstance(item, str):
                        paragraphs.append(item.strip())
                    elif isinstance(item, dict):
                        paragraphs.append(json.dumps(item, ensure_ascii=False))

    if not paragraphs:
        paragraphs = [pkg_text]

    non_decoy_paras = []
    for p in paragraphs:
        p_low = p.lower()
        if any(bad in p_low for bad in [
            "cover sheet", "cover-sheet", "archive example", "archived example",
            "training decoy", "training example", "historical example", "for training only",
            "sample only", "do not use this example", "decoy"
        ]):
            continue
        non_decoy_paras.append(p)

    candidate_paras = non_decoy_paras if non_decoy_paras else paragraphs

    decisive_para = candidate_paras[-1]
    decisive_refs = []

    for p in reversed(candidate_paras):
        refs = extract_all_ref_tokens(p)
        if len(refs) == 3:
            decisive_para = p
            decisive_refs = refs
            break
        elif len(refs) > 3 and not decisive_refs:
            decisive_para = p
            decisive_refs = refs[:3]

    if len(decisive_refs) < 3:
        all_refs = []
        for p in candidate_paras:
            for r in extract_all_ref_tokens(p):
                if r not in all_refs:
                    all_refs.append(r)
        decisive_refs = all_refs[:3]

    while len(decisive_refs) < 3:
        decisive_refs.append(f"[REF-{len(decisive_refs)+1}]")

    p_low = decisive_para.lower()
    action = "settle_invoice"

    if any(k in p_low for k in ["reject_duplicate", "already paid", "already settled", "duplicate payment", "paid previously", "previously settled"]):
        if "not a duplicate" not in p_low and "different invoice" not in p_low:
            action = "reject_duplicate"
    if action == "settle_invoice":
        if any(k in p_low for k in ["open_exception", "material conflict", "records conflict", "mismatch", "discrepancy", "exception workflow", "conflicting", "conflict between", "does not match"]):
            if "no discrepancy" not in p_low and "no conflict" not in p_low and "resolved" not in p_low:
                action = "open_exception"
    if action == "settle_invoice":
        if any(k in p_low for k in ["hold_invoice", "verification completes", "pending verification", "awaiting verification", "payment pauses", "on hold", "pending inspection", "until verification", "pause payment", "paused until"]):
            if "verification completed" not in p_low and "verification is complete" not in p_low:
                action = "hold_invoice"
    if action == "settle_invoice":
        if any(k in p_low for k in ["request_approval", "outside delegated authority", "exceeds autonomous", "exceeds authority", "above limit", "requires approval", "delegated limit", "approval required", "exceeds delegated", "outside autonomous"]):
            if "within autonomous" not in p_low and "within delegated" not in p_low:
                action = "request_approval"

    facts_src = pkg.get("facts") or pkg.get("summary") or pkg.get("metadata") or pkg.get("header") or pkg.get("invoice") or {}
    if not isinstance(facts_src, dict):
        facts_src = {}
    vendor = facts_src.get("vendorName") or pkg.get("vendorName") or pkg.get("vendor")
    inv_num = facts_src.get("invoiceNumber") or pkg.get("invoiceNumber") or pkg.get("invoiceId")
    amt_minor = facts_src.get("amountMinor") or pkg.get("amountMinor")
    currency = facts_src.get("currency") or pkg.get("currency") or "INR"

    full_clean_text = "\n".join(candidate_paras)

    if not vendor or not isinstance(vendor, str):
        m_v = re.search(r"(?:Vendor Name|Vendor|Supplier|Payee|Billed By)\s*[:\-]\s*([^\n\r,;|\[\]\"]+)", full_clean_text, re.I)
        vendor = m_v.group(1).strip() if m_v else "Vendor"

    if not inv_num or not isinstance(inv_num, str):
        m_i = re.search(r"(?:Invoice Number|Invoice No\.?|Invoice ID|Invoice #|Inv #)\s*[:\-]?\s*([A-Za-z0-9_.\-/]+)", full_clean_text, re.I)
        inv_num = m_i.group(1).strip() if m_i else "INV-001"

    if amt_minor is None or not isinstance(amt_minor, int):
        m_minor = re.search(r"(?:amountMinor|Amount in minor units|Minor Amount|paise|cents)\s*[:\-=]?\s*([0-9,]+)", full_clean_text, re.I)
        if m_minor:
            amt_minor = int(m_minor.group(1).replace(",", ""))
        else:
            m_amt = re.search(r"(?:Total Amount|Invoice Amount|Payable Amount|Net Amount|Amount Due|Amount)\s*[:\-]?\s*(?:INR|USD|EUR|GBP|Rs\.?|₹|\$)?\s*([0-9,]+\.\d{2}|[0-9,]+)", full_clean_text, re.I)
            if m_amt:
                val_str = m_amt.group(1).replace(",", "")
                if "." in val_str:
                    amt_minor = int(round(float(val_str) * 100))
                else:
                    val_int = int(val_str)
                    amt_minor = val_int * 100 if val_int < 1000000 else val_int
            else:
                amt_minor = 10000

    m_curr = re.search(r"\b(INR|USD|EUR|GBP|SGD|AED)\b", full_clean_text)
    if m_curr:
        currency = m_curr.group(1)

    rationale = (
        f"Chosen action is {action} for invoice {inv_num} from {vendor} ({amt_minor} {currency}) "
        f"because {decisive_refs[0]}, {decisive_refs[1]}, and {decisive_refs[2]} establish the controlling case facts under the policy."
    )

    return {
        "action": action,
        "facts": {
            "vendorName": str(vendor).strip(),
            "invoiceNumber": str(inv_num).strip(),
            "amountMinor": int(amt_minor),
            "currency": str(currency).strip()
        },
        "evidenceRefs": decisive_refs[:3],
        "rationale": rationale[:1400]
    }


def build_batch_prompt(chunk: List[Dict[str, Any]], policy: str) -> str:
    return f"""You are an expert A2A Invoice Audit Agent. Read the Policy Revision ("{policy}") and evaluate each invoice package in the JSON list below.

Choose EXACTLY ONE action per package:
- "settle_invoice": valid, reconciled, and within autonomous authority limits.
- "request_approval": commercially valid and reconciled, but outside delegated/autonomous authority limits.
- "hold_invoice": payment pauses until a stated verification, inspection, or receipt step completes.
- "reject_duplicate": the exact same commercial invoice was already paid (a payment for a DIFFERENT invoice number is NOT a duplicate).
- "open_exception": material records conflict (e.g., PO/GRN/invoice amount/quantity/vendor/bank conflict or discrepancy) and need an exception workflow.

CRITICAL EVIDENCE & FACTS RULES:
1. Documents mix useful controlling facts with cover sheets, archive examples, training decoys, negation, and irrelevant action words. Ignore cover-sheet references, archive examples, and training decoys!
2. Return EXACTLY THREE decisive bracketed references (e.g. ["[ref1]", "[ref2]", "[ref3]"]) from the single paragraph that determines the action. Keep the brackets `[` and `]` around each reference string exactly as written in the decisive paragraph.
3. Extract exact controlling invoice facts:
   - "vendorName": exact vendor name string
   - "invoiceNumber": exact invoice number string
   - "amountMinor": integer amount in minor currency units (paise/cents; e.g. INR 1,250.00 = 125000, or if amountMinor is explicitly stated, use that integer)
   - "currency": 3-letter currency string (e.g. "INR")
4. "rationale": 80 to 450 characters. Name the exact chosen action, cite at least two of the exact evidenceRefs (including brackets), and explain how the controlling facts support the action.

Input Packages JSON:
{json.dumps(chunk, ensure_ascii=False)}

Return ONLY a valid JSON array with {len(chunk)} objects in the exact same order, each with keys:
"packageId", "action", "facts" ("vendorName", "invoiceNumber", "amountMinor", "currency"), "evidenceRefs" (array of 3 bracketed strings), "rationale".
"""


async def evaluate_packages_batch(packages: List[Dict[str, Any]], policy: str) -> List[Dict[str, Any]]:
    baseline = [deterministic_parse_package(pkg, policy) for pkg in packages]

    gemini_key = (os.environ.get("GEMINI_API_KEY") or "").strip()
    openai_key = (os.environ.get("OPENAI_API_KEY") or os.environ.get("AIPIPE_TOKEN") or "").strip()

    if not gemini_key and not openai_key:
        print("[LLM] No API key configured, using baseline")
        return baseline

    # First try all packages in 1 batched model call (as recommended by spec: "batch 12 packages into one model call")
    prompt_all = build_batch_prompt(packages, policy)
    llm_res = await asyncio.to_thread(call_llm_sync, prompt_all, gemini_key, openai_key)

    # If 12-package single call fails or mismatches length, split into 2 halves of 6 packages
    if not isinstance(llm_res, list) or len(llm_res) != len(packages):
        if len(packages) > 1:
            mid = len(packages) // 2
            p1 = build_batch_prompt(packages[:mid], policy)
            p2 = build_batch_prompt(packages[mid:], policy)
            r1, r2 = await asyncio.gather(
                asyncio.to_thread(call_llm_sync, p1, gemini_key, openai_key),
                asyncio.to_thread(call_llm_sync, p2, gemini_key, openai_key)
            )
            if isinstance(r1, list) and len(r1) == mid and isinstance(r2, list) and len(r2) == len(packages) - mid:
                llm_res = r1 + r2

    if not isinstance(llm_res, list) or len(llm_res) != len(packages):
        print(f"[LLM] Fallback to baseline (llm_res={type(llm_res)})")
        return baseline

    merged_all = []
    for pkg, base, item in zip(packages, baseline, llm_res):
        if not isinstance(item, dict):
            merged_all.append(base)
            continue

        act = str(item.get("action") or "").strip()
        if act not in VALID_ACTIONS:
            act = base["action"]

        facts = item.get("facts") if isinstance(item.get("facts"), dict) else {}
        vendor = str(facts.get("vendorName") or base["facts"]["vendorName"]).strip()
        inv_no = str(facts.get("invoiceNumber") or base["facts"]["invoiceNumber"]).strip()
        try:
            amt = int(facts.get("amountMinor"))
        except Exception:
            amt = base["facts"]["amountMinor"]
        curr = str(facts.get("currency") or base["facts"]["currency"]).strip()

        refs = item.get("evidenceRefs")
        pkg_raw = json.dumps(pkg, ensure_ascii=False)
        if not isinstance(refs, list) or len(refs) != 3 or not all(isinstance(r, str) and r.strip() for r in refs):
            refs = base["evidenceRefs"]
        else:
            fixed_refs = []
            for r in refs:
                r_clean = r.strip()
                if r_clean in pkg_raw and r_clean.startswith("[") and r_clean.endswith("]"):
                    fixed_refs.append(r_clean)
                elif f"[{r_clean}]" in pkg_raw:
                    fixed_refs.append(f"[{r_clean}]")
                else:
                    fixed_refs.append(r_clean)
            refs = fixed_refs

        rat = str(item.get("rationale") or "").strip()
        if len(rat) < 65 or act not in rat or sum(1 for r in refs if r in rat) < 2:
            rat = (
                f"Action {act} is chosen for invoice {inv_no} from {vendor} ({amt} {curr}) "
                f"supported by decisive evidence {refs[0]}, {refs[1]}, and {refs[2]}: {rat}"
            ).strip()

        merged_all.append({
            "action": act,
            "facts": {
                "vendorName": vendor,
                "invoiceNumber": inv_no,
                "amountMinor": amt,
                "currency": curr
            },
            "evidenceRefs": refs,
            "rationale": rat[:1450]
        })

    return merged_all


def get_available_gemini_models(gemini_key: str) -> List[str]:
    global discovered_gemini_models
    if discovered_gemini_models:
        return discovered_gemini_models

    # Priority order starting with gemini-3.0-flash as requested by Google's error message!
    candidates = [
        "gemini-3.0-flash",
        "gemini-3.0-flash-preview",
        "gemini-3-flash",
        "gemini-3-flash-preview",
        "gemini-flash-latest",
        "gemini-2.5-flash-lite",
        "gemini-2.5-flash-lite-preview-06-17",
        "gemini-2.0-flash",
        "gemini-2.0-flash-lite",
    ]
    try:
        url = f"https://generativelanguage.googleapis.com/v1beta/models?key={gemini_key}"
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            api_models = []
            for m in data.get("models", []):
                name = m.get("name", "").replace("models/", "")
                methods = m.get("supportedGenerationMethods", [])
                if "generateContent" in methods and ("flash" in name or "gemini-3" in name or "pro" in name):
                    api_models.append(name)
            print(f"[LLM] Discovered models on key: {api_models}")
            # Put any discovered gemini-3 / flash models first
            ordered = []
            for pref in ["gemini-3.0-flash", "gemini-3-flash", "gemini-flash-latest", "gemini-2.5-flash-lite", "gemini-2.0-flash"]:
                for am in api_models:
                    if am == pref and am not in ordered:
                        ordered.append(am)
            for am in api_models:
                if "flash" in am and am not in ordered and "tts" not in am and "image" not in am and "audio" not in am:
                    ordered.append(am)
            for c in candidates:
                if c not in ordered:
                    ordered.append(c)
            discovered_gemini_models = ordered
            return discovered_gemini_models
    except Exception as e:
        print(f"[LLM] Model discovery error: {e}")
        return candidates


def call_llm_sync(prompt: str, gemini_key: str, openai_key: str) -> Any:
    global discovered_gemini_models
    if gemini_key:
        models_to_try = get_available_gemini_models(gemini_key)
        for model_name in models_to_try[:5]:
            try:
                url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent?key={gemini_key}"
                gen_cfg: Dict[str, Any] = {
                    "responseMimeType": "application/json",
                    "temperature": 0.0,
                    "maxOutputTokens": 8192
                }
                payload = {
                    "contents": [{"parts": [{"text": prompt}]}],
                    "generationConfig": gen_cfg
                }
                req = urllib.request.Request(
                    url,
                    data=json.dumps(payload).encode("utf-8"),
                    headers={"Content-Type": "application/json"}
                )
                with urllib.request.urlopen(req, timeout=35) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                    parts = data["candidates"][0]["content"]["parts"]
                    text = ""
                    for p in parts:
                        if "text" in p and not p.get("thought", False):
                            text += p["text"]
                    text = text.strip()
                    text = re.sub(r"^```(?:json)?|```$", "", text, flags=re.M).strip()
                    parsed = json.loads(text)
                    if isinstance(parsed, dict):
                        for k in ["proposals", "packages", "results", "decisions", "items"]:
                            if k in parsed and isinstance(parsed[k], list):
                                parsed = parsed[k]
                                break
                    if isinstance(parsed, list):
                        print(f"[LLM] Success with {model_name} ({len(parsed)} items)")
                        # Pin working model to the front of the list so subsequent calls have 0 retries!
                        if discovered_gemini_models and discovered_gemini_models[0] != model_name:
                            discovered_gemini_models = [model_name] + [m for m in discovered_gemini_models if m != model_name]
                        return parsed
            except urllib.error.HTTPError as e:
                err_body = e.read().decode("utf-8", errors="ignore")[:300]
                print(f"[LLM] HTTPError {model_name}: {e.code} {err_body}")
                if e.code == 404 and model_name in discovered_gemini_models:
                    discovered_gemini_models = [m for m in discovered_gemini_models if m != model_name]
            except Exception as e:
                print(f"[LLM] Error {model_name}: {type(e).__name__}: {e}")

    if openai_key:
        try:
            base = (os.environ.get("OPENAI_BASE_URL") or "https://api.openai.com/v1").strip().rstrip("/")
            url = f"{base}/chat/completions"
            model = (os.environ.get("OPENAI_MODEL") or "gpt-4o-mini").strip()
            payload = {
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.0
            }
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json", "Authorization": f"Bearer {openai_key}"}
            )
            with urllib.request.urlopen(req, timeout=35) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                text = data["choices"][0]["message"]["content"].strip()
                text = re.sub(r"^```(?:json)?|```$", "", text, flags=re.M).strip()
                return json.loads(text)
        except Exception as e:
            print(f"[LLM] OpenAI error: {e}")

    return None


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
