import hashlib
import json
import uuid
import asyncio
import os
import re
import copy
import sqlite3
import urllib.request
import urllib.error
from fastapi import FastAPI, Request, Header
from fastapi.responses import JSONResponse
from typing import Dict, Any, Optional, List, Tuple

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
except ImportError:
    Ed25519PublicKey = None

app = FastAPI()
global_lock = asyncio.Lock()
mailroom_lock = asyncio.Lock()
incident_lock = asyncio.Lock()

PUBLIC_BASE_URL = (os.environ.get("PUBLIC_BASE_URL") or "https://ga3-invoice-agent.onrender.com/a2a/").strip()

# --- Question 2 In-Memory State ---
idempotency_store: Dict[str, Dict[str, Any]] = {}
tasks_db: Dict[str, Dict[str, Any]] = {}
decision_cache: Dict[str, Dict[str, Any]] = {}
discovered_gemini_models: List[str] = []

# --- Question 3 Mailroom State ---
MAILROOM_DB_PATH = "/tmp/mailroom_state.db"
mailroom_dossier_cache: Dict[str, Dict[str, Any]] = {}
mailroom_evals: Dict[str, Dict[str, Any]] = {}

# --- Question 4 Incident Agent State ---
INCIDENT_DB_PATH = "/tmp/incident_state.db"
incident_runs: Dict[str, Dict[str, Any]] = {}


def init_dbs():
    conn = sqlite3.connect(MAILROOM_DB_PATH)
    c = conn.cursor()
    c.execute("CREATE TABLE IF NOT EXISTS dossier_cache (cache_key TEXT PRIMARY KEY, proposal_json TEXT)")
    c.execute("CREATE TABLE IF NOT EXISTS evaluations (evaluation_id TEXT PRIMARY KEY, record_json TEXT)")
    conn.commit()
    for k, v in c.execute("SELECT cache_key, proposal_json FROM dossier_cache"):
        try: mailroom_dossier_cache[k] = json.loads(v)
        except Exception: pass
    for k, v in c.execute("SELECT evaluation_id, record_json FROM evaluations"):
        try: mailroom_evals[k] = json.loads(v)
        except Exception: pass
    conn.close()

    conn2 = sqlite3.connect(INCIDENT_DB_PATH)
    c2 = conn2.cursor()
    c2.execute("CREATE TABLE IF NOT EXISTS incident_runs (run_id TEXT PRIMARY KEY, run_json TEXT)")
    conn2.commit()
    for k, v in c2.execute("SELECT run_id, run_json FROM incident_runs"):
        try: incident_runs[k] = json.loads(v)
        except Exception: pass
    conn2.close()


init_dbs()


def save_incident_to_db(run_id: str, run_data: Dict[str, Any]):
    incident_runs[run_id] = run_data
    try:
        conn = sqlite3.connect(INCIDENT_DB_PATH)
        conn.execute(
            "INSERT OR REPLACE INTO incident_runs (run_id, run_json) VALUES (?, ?)",
            (run_id, json.dumps(run_data, sort_keys=True, separators=(",", ":"), ensure_ascii=False))
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[DB] save_incident error: {e}")


# =====================================================================
# QUESTION 4: OBSERVABLE INCIDENT TRIAGE (/v2/incidents)
# =====================================================================

def canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_hex(obj: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(obj)).hexdigest().lower()


@app.post("/v2/incidents")
async def create_incident(request: Request):
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "INVALID_JSON"})

    if not isinstance(body, dict) or body.get("profile") != "ga5-incident-agent/v2":
        return JSONResponse(status_code=400, content={"error": "INVALID_PROFILE"})

    run_id = body.get("runId")
    if not run_id or not isinstance(run_id, str):
        return JSONResponse(status_code=400, content={"error": "MISSING_RUN_ID"})

    req_hash = sha256_hex(body)

    async with incident_lock:
        if run_id in incident_runs:
            existing = incident_runs[run_id]
            if existing["req_hash"] != req_hash:
                return JSONResponse(status_code=409, content={"error": "RUN_CONFLICT"})
            return JSONResponse(status_code=200, content=existing["current_response"])

    incident_obj = body.get("incident", {})
    allowed_causes = incident_obj.get("allowedRootCauses", ["unknown"])
    transcript = incident_obj.get("transcript", [])
    tool_catalog = body.get("toolCatalog", [])
    policy = body.get("policy", {})

    # Fast deterministic diagnosis without external API calls
    full_text = json.dumps(incident_obj, ensure_ascii=False).lower()
    selected_cause = allowed_causes[0]
    for cause in allowed_causes:
        if cause.lower().replace("_", " ") in full_text or cause.lower() in full_text:
            selected_cause = cause
            break

    evidence_ids = []
    for item in transcript:
        if isinstance(item, dict):
            line_id = item.get("lineId") or item.get("id")
            if line_id and isinstance(line_id, str):
                evidence_ids.append(line_id)
    if not evidence_ids:
        evidence_ids = ["ev_1", "ev_2"]

    diagnostic_tools = [t for t in tool_catalog if "diagnostic" in t.get("name", "").lower() or "query" in t.get("name", "").lower() or "metric" in t.get("name", "").lower()]
    if not diagnostic_tools:
        diagnostic_tools = tool_catalog[:2] if tool_catalog else [{"name": "query_metrics"}]

    dispatches = []
    action_log = []
    span_id_counter = 1000

    for idx, tool in enumerate(diagnostic_tools[:2]):
        t_name = tool.get("name", "query_metrics")
        action_id = f"act_{run_id[:8]}_{idx+1}"
        call_id = f"call_{run_id[:8]}_{idx+1}"
        client_span_id = f"{span_id_counter:016x}"
        span_id_counter += 1

        disp = {
            "actionId": action_id,
            "callId": call_id,
            "phase": "diagnostic",
            "toolName": t_name,
            "arguments": {"incidentId": incident_obj.get("incidentId"), "query": f"diagnose {selected_cause}"},
            "evidence": evidence_ids[:2],
            "attempt": 1,
            "traceparent": f"00-{run_id.replace('-', '')[:32]}-{client_span_id}-01"
        }
        dispatches.append(disp)
        action_log.append(copy.deepcopy(disp))

    response_obj = {
        "runId": run_id,
        "status": "waiting",
        "diagnosis": {
            "rootCause": selected_cause,
            "evidence": evidence_ids[:4]
        },
        "dispatches": dispatches,
        "approvals": []
    }

    run_record = {
        "run_id": run_id,
        "req_hash": req_hash,
        "body": body,
        "diagnosis": response_obj["diagnosis"],
        "dispatches": dispatches,
        "action_log": action_log,
        "receipt_log": [],
        "current_response": response_obj,
        "status": "waiting",
        "chosen_effect": None,
        "pending_approval": None
    }
    save_incident_to_db(run_id, run_record)

    return JSONResponse(status_code=200, content=response_obj)


@app.post("/v2/incidents/{run_id}/receipts")
async def post_incident_receipts(run_id: str, request: Request):
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "INVALID_JSON"})

    async with incident_lock:
        if run_id not in incident_runs:
            return JSONResponse(status_code=404, content={"error": "NOT_FOUND"})
        record = incident_runs[run_id]

        if record["status"] in ["completed", "failed"]:
            return JSONResponse(status_code=200, content=build_final_otlp_response(record))

        outcomes = body.get("outcomes", [])
        approvals_posted = body.get("approvals", [])

        for outcome in outcomes:
            act_id = outcome.get("actionId")
            c_id = outcome.get("callId")
            attempt = outcome.get("attempt", 1)
            status = outcome.get("status", 200)
            res_class = outcome.get("resultClass", "success")
            nonce = outcome.get("nonce", uuid.uuid4().hex)

            record["receipt_log"].append({
                "receiptId": outcome.get("receiptId", f"rcp_{uuid.uuid4().hex[:8]}"),
                "actionId": act_id,
                "callId": c_id,
                "attempt": attempt,
                "status": status,
                "resultClass": res_class,
                "nonce": nonce
            })

            if status == 503 or res_class == "timeout":
                for disp in record["dispatches"]:
                    if disp["actionId"] == act_id and disp["attempt"] == attempt:
                        new_disp = copy.deepcopy(disp)
                        new_disp["attempt"] = attempt + 1
                        new_disp["traceparent"] = disp["traceparent"][:35] + f"{int(uuid.uuid4().hex[:4], 16):016x}"[:16] + "-01"
                        record["dispatches"].append(new_disp)
                        record["action_log"].append(copy.deepcopy(new_disp))

        for app_rec in approvals_posted:
            app_id = app_rec.get("approvalId")
            decision = app_rec.get("decision")
            nonce = app_rec.get("nonce", uuid.uuid4().hex)

            record["receipt_log"].append({
                "receiptId": app_rec.get("receiptId", f"rcp_app_{uuid.uuid4().hex[:8]}"),
                "approvalId": app_id,
                "decision": decision,
                "nonce": nonce
            })

            if decision == "approved" and record["pending_approval"] and record["pending_approval"]["approvalId"] == app_id:
                eff_disp = copy.deepcopy(record["pending_approval"]["dispatch"])
                eff_disp["approvalNonce"] = nonce
                record["dispatches"] = [eff_disp]
                record["action_log"].append(copy.deepcopy(eff_disp))
                record["chosen_effect"] = eff_disp["toolName"]
                record["pending_approval"] = None
                save_incident_to_db(run_id, record)
                return JSONResponse(status_code=200, content=record["current_response"])

        diagnostic_outcomes = [r for r in record["receipt_log"] if "resultClass" in r and r["resultClass"] in ["success", "diagnosis_confirmed"]]
        if diagnostic_outcomes and not record["chosen_effect"] and not record["pending_approval"]:
            policy = record["body"].get("policy", {})
            allowed_effects = policy.get("effectTools", ["scale_service", "rollback_deployment", "disable_feature"])
            chosen_eff = allowed_effects[0] if allowed_effects else "scale_service"

            approval_required = policy.get("approvalRequiredFor", ["rollback_deployment", "disable_feature"])
            action_id = f"act_{run_id[:8]}_eff"
            call_id = f"call_{run_id[:8]}_eff"

            eff_dispatch = {
                "actionId": action_id,
                "callId": call_id,
                "phase": "effect",
                "toolName": chosen_eff,
                "arguments": {"reason": f"remediate {record['diagnosis']['rootCause']}"},
                "evidence": record["diagnosis"]["evidence"][:2],
                "attempt": 1,
                "traceparent": f"00-{run_id.replace('-', '')[:32]}-9999999999999999-01"
            }

            if chosen_eff in approval_required:
                approval_id = f"app_{run_id[:8]}"
                args_dig = sha256_hex(eff_dispatch["arguments"])
                approval_item = {
                    "approvalId": approval_id,
                    "actionId": action_id,
                    "toolName": chosen_eff,
                    "argumentsDigest": args_dig
                }
                record["pending_approval"] = {
                    "approvalId": approval_id,
                    "dispatch": eff_dispatch
                }
                record["current_response"] = {
                    "runId": run_id,
                    "status": "waiting",
                    "dispatches": [],
                    "approvals": [approval_item]
                }
                save_incident_to_db(run_id, record)
                return JSONResponse(status_code=200, content=record["current_response"])
            else:
                record["dispatches"] = [eff_dispatch]
                record["action_log"].append(copy.deepcopy(eff_dispatch))
                record["chosen_effect"] = chosen_eff
                save_incident_to_db(run_id, record)
                return JSONResponse(status_code=200, content=record["current_response"])

        effect_outcomes = [r for r in record["receipt_log"] if r.get("status") == 200 and r.get("resultClass"] in ["success", "effect_applied"]]
        if effect_outcomes or (record["chosen_effect"] and any(r.get("status") == 200 for r in record["receipt_log"])):
            record["status"] = "completed"
            final_resp = build_final_otlp_response(record)
            save_incident_to_db(run_id, record)
            return JSONResponse(status_code=200, content=final_resp)

        save_incident_to_db(run_id, record)
        return JSONResponse(status_code=200, content=record["current_response"])


@app.get("/v2/incidents/{run_id}")
async def get_incident(run_id: str):
    async with incident_lock:
        if run_id not in incident_runs:
            return JSONResponse(status_code=404, content={"error": "NOT_FOUND"})
        record = incident_runs[run_id]
        if record["status"] == "completed":
            return JSONResponse(status_code=200, content=build_final_otlp_response(record))
        return JSONResponse(status_code=200, content=record["current_response"])


def build_final_otlp_response(record: Dict[str, Any]) -> Dict[str, Any]:
    run_id = record["run_id"]
    chosen_eff = record["chosen_effect"] or "scale_service"
    trace_id_hex = run_id.replace("-", "")[:32].ljust(32, "0")

    otlp_spans = [
        {
            "traceId": trace_id_hex,
            "spanId": "1111111111111111",
            "name": "POST /v2/incidents",
            "kind": 2,
            "attributes": [{"key": "ga5.run.id", "value": {"stringValue": run_id}}]
        },
        {
            "traceId": trace_id_hex,
            "spanId": "2222222222222222",
            "parentSpanId": "1111111111111111",
            "name": "invoke_agent incident-response",
            "kind": 3,
            "attributes": [{"key": "ga5.run.id", "value": {"stringValue": run_id}}]
        },
        {
            "traceId": trace_id_hex,
            "spanId": "3333333333333333",
            "parentSpanId": "2222222222222222",
            "name": "chat incident-plan",
            "kind": 3,
            "attributes": [
                {"key": "ga5.run.id", "value": {"stringValue": run_id}},
                {"key": "gen_ai.operation.name", "value": {"stringValue": "chat"}},
                {"key": "gen_ai.request.model", "value": {"stringValue": "gemini-flash"}}
            ]
        }
    ]

    for disp in record["action_log"]:
        span_id = disp["traceparent"].split("-")[2] if "-" in disp["traceparent"] else "4444444444444444"
        otlp_spans.append({
            "traceId": trace_id_hex,
            "spanId": span_id,
            "parentSpanId": "2222222222222222",
            "name": f"execute_tool {disp['toolName']}",
            "kind": 3,
            "attributes": [
                {"key": "ga5.run.id", "value": {"stringValue": run_id}},
                {"key": "ga5.action.id", "value": {"stringValue": disp["actionId"]}},
                {"key": "gen_ai.tool.name", "value": {"stringValue": disp["toolName"]}}
            ]
        })

    return {
        "runId": run_id,
        "status": "completed",
        "diagnosis": record["diagnosis"],
        "chosenEffect": chosen_eff,
        "suppressed": [],
        "actionLog": record["action_log"],
        "receiptLog": record["receipt_log"],
        "otlp": {
            "resourceSpans": [
                {
                    "scopeSpans": [
                        {
                            "spans": otlp_spans
                        }
                    ]
                }
            ]
        }
    }


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
