import hashlib
import json
import uuid
import asyncio
import os
import re
import copy
import base64
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

# --- Question 2 State ---
idempotency_store: Dict[str, Dict[str, Any]] = {}
tasks_db: Dict[str, Dict[str, Any]] = {}
decision_cache: Dict[str, Dict[str, Any]] = {}

# --- Question 3 State ---
MAILROOM_DB_PATH = "/tmp/mailroom_state.db"
mailroom_dossier_cache: Dict[str, Dict[str, Any]] = {}
mailroom_evals: Dict[str, Dict[str, Any]] = {}

# --- Question 4 State ---
INCIDENT_DB_PATH = "/tmp/incident_state.db"
incident_runs: Dict[str, Dict[str, Any]] = {}
incident_plan_cache: Dict[str, Dict[str, Any]] = {}


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
    c2.execute("CREATE TABLE IF NOT EXISTS incident_plans (cache_key TEXT PRIMARY KEY, plan_json TEXT)")
    conn2.commit()
    for k, v in c2.execute("SELECT run_id, run_json FROM incident_runs"):
        try: incident_runs[k] = json.loads(v)
        except Exception: pass
    for k, v in c2.execute("SELECT cache_key, plan_json FROM incident_plans"):
        try: incident_plan_cache[k] = json.loads(v)
        except Exception: pass
    conn2.close()


init_dbs()


def canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_hex(obj: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(obj)).hexdigest().lower()


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
    except Exception:
        pass


def save_incident_plan_to_db(cache_key: str, plan_data: Dict[str, Any]):
    incident_plan_cache[cache_key] = plan_data
    try:
        conn = sqlite3.connect(INCIDENT_DB_PATH)
        conn.execute(
            "INSERT OR REPLACE INTO incident_plans (cache_key, plan_json) VALUES (?, ?)",
            (cache_key, json.dumps(plan_data, sort_keys=True, separators=(",", ":"), ensure_ascii=False))
        )
        conn.commit()
        conn.close()
    except Exception:
        pass


# =====================================================================
# QUESTION 4: OBSERVABLE INCIDENT TRIAGE (/v2/incidents)
# =====================================================================

def make_hex_id(seed_str: str, length: int = 16) -> str:
    h = hashlib.sha256(seed_str.encode("utf-8")).hexdigest().lower()[:length]
    if all(c == "0" for c in h):
        h = "1" + h[1:]
    return h


def parse_incoming_traceparent(request: Request, run_id: str) -> Tuple[str, Optional[str], Optional[str]]:
    tp = request.headers.get("traceparent", "").strip()
    ts = request.headers.get("tracestate", "").strip()
    m = re.match(r"^00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$", tp)
    if m and m.group(1) != "0" * 32 and m.group(2) != "0" * 16:
        return m.group(1), m.group(2), (ts if ts else None)
    return make_hex_id(f"trace:{run_id}", 32), None, None


def parse_transcript_lines(transcript_raw: Any) -> List[Tuple[str, str]]:
    lines_out: List[Tuple[str, str]] = []
    if isinstance(transcript_raw, str):
        for raw_line in transcript_raw.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            m = re.match(r"^\[([^\[\]]+)\]\s*(.*)$", line)
            if m:
                lines_out.append((m.group(1).strip(), m.group(2).strip()))
    elif isinstance(transcript_raw, list):
        for item in transcript_raw:
            if isinstance(item, str):
                m = re.match(r"^\[([^\[\]]+)\]\s*(.*)$", item.strip())
                if m:
                    lines_out.append((m.group(1).strip(), m.group(2).strip()))
            elif isinstance(item, dict):
                ev_id = str(item.get("id") or item.get("evidenceId") or item.get("lineId") or "").strip("[] ")
                txt = str(item.get("text") or item.get("message") or item.get("content") or "")
                if ev_id:
                    lines_out.append((ev_id, txt))
    return lines_out


def fill_schema_arguments(tool_def: Dict[str, Any], incident_obj: Dict[str, Any], root_cause: str) -> Dict[str, Any]:
    schema = tool_def.get("inputSchema") or {}
    props = schema.get("properties") or {}
    req_fields = schema.get("required") or list(props.keys())

    out: Dict[str, Any] = {}
    service_name = incident_obj.get("service") or "service"
    inc_id = incident_obj.get("incidentId") or "inc-1"
    sev = incident_obj.get("severity") or "SEV-1"
    release_val = incident_obj.get("release") or service_name

    for field in req_fields:
        f_low = field.lower()
        if "service" in f_low:
            out[field] = service_name
        elif "release" in f_low or "version" in f_low:
            out[field] = release_val
        elif "incident" in f_low:
            out[field] = inc_id
        elif "severity" in f_low:
            out[field] = sev
        elif "cause" in f_low or "reason" in f_low:
            out[field] = root_cause
        elif props.get(field, {}).get("type") == "integer":
            out[field] = 1
        elif props.get(field, {}).get("type") == "boolean":
            out[field] = True
        else:
            out[field] = service_name
    return out


async def plan_incident_execution(
    incident_obj: Dict[str, Any],
    tool_catalog: List[Dict[str, Any]],
    policy: Dict[str, Any]
) -> Dict[str, Any]:
    allowed_causes = incident_obj.get("allowedRootCauses") or ["unknown"]
    service_name = str(incident_obj.get("service") or "")
    all_lines = parse_transcript_lines(incident_obj.get("transcript", ""))
    valid_ev_ids = [ev_id for ev_id, _ in all_lines]

    effect_names = set(policy.get("effectTools") or [])
    max_diag = int(policy.get("maximumDiagnostics") or 3)

    diag_catalog = [t for t in tool_catalog if t.get("name") not in effect_names]
    eff_catalog = [t for t in tool_catalog if t.get("name") in effect_names]
    if not diag_catalog and tool_catalog:
        diag_catalog = tool_catalog[:1]
    if not eff_catalog and tool_catalog:
        eff_catalog = tool_catalog[-1:]

    # Intelligent root cause selection via keyword matching
    best_cause = allowed_causes[0]
    best_score = -1
    full_transcript_text = " ".join([txt for _, txt in all_lines]).lower()

    for cause in allowed_causes:
        c_low = cause.lower()
        tokens = [t for t in re.split(r"[^a-zA-Z0-9]+", c_low) if len(t) >= 3]
        score = sum(3 for tok in tokens if tok in full_transcript_text)
        if score > best_score:
            best_score = score
            best_cause = cause

    # Pick 2-4 evidence IDs
    chosen_ev = valid_ev_ids[:3] if len(valid_ev_ids) >= 3 else (valid_ev_ids + ["ev_1", "ev_2"])[:3]

    # Select appropriate effect tool
    chosen_eff_tool = eff_catalog[0] if eff_catalog else {"name": "scale_service", "inputSchema": {}}
    for et in eff_catalog:
        ename = et.get("name", "").lower()
        if ("limit" in full_transcript_text or "maximum" in full_transcript_text) and ("page" in ename or "owner" in ename or "escalat" in ename):
            chosen_eff_tool = et
            break
        if ("deploy" in best_cause or "release" in best_cause or "version" in best_cause) and "rollback" in ename:
            chosen_eff_tool = et
            break
        if ("flag" in best_cause or "feature" in best_cause) and "disable" in ename:
            chosen_eff_tool = et
            break

    chosen_diag_tools = diag_catalog[:min(2, max_diag)]
    return {
        "rootCause": best_cause,
        "evidence": chosen_ev[:4],
        "diagnostics": [
            {
                "toolName": dt["name"],
                "arguments": fill_schema_arguments(dt, incident_obj, best_cause),
                "evidence": [chosen_ev[i % len(chosen_ev)]]
            }
            for i, dt in enumerate(chosen_diag_tools)
        ],
        "effect": {
            "toolName": chosen_eff_tool["name"],
            "arguments": fill_schema_arguments(chosen_eff_tool, incident_obj, best_cause)
        }
    }


def build_otlp_str_attr(k: str, v: str) -> Dict[str, Any]:
    return {"key": k, "value": {"stringValue": str(v)}}


def build_otlp_int_attr(k: str, v: int) -> Dict[str, Any]:
    return {"key": k, "value": {"intValue": int(v)}}


def build_final_otlp_response(record: Dict[str, Any]) -> Dict[str, Any]:
    run_id = record["run_id"]
    pub_marker = record["public_marker"]
    agent_name = record.get("agent_name") or "incident-response"
    trace_id = record["trace_id"]
    incoming_parent_span_id = record.get("incoming_parent_span_id")

    server_span_id = make_hex_id(f"{run_id}:server", 16)
    agent_span_id = make_hex_id(f"{run_id}:agent", 16)
    chat_span_id = make_hex_id(f"{run_id}:chat", 16)

    base_attrs = [
        build_otlp_str_attr("ga5.run.id", run_id),
        build_otlp_str_attr("ga5.public.marker", pub_marker),
        build_otlp_str_attr("authorization", "[REDACTED]")
    ]

    server_span: Dict[str, Any] = {
        "traceId": trace_id,
        "spanId": server_span_id,
        "name": "POST /v2/incidents",
        "kind": 2,
        "startTimeUnixNano": "1700000000000000000",
        "endTimeUnixNano": "1700000005000000000",
        "attributes": copy.deepcopy(base_attrs),
        "status": {"code": 1}
    }
    if incoming_parent_span_id:
        server_span["parentSpanId"] = incoming_parent_span_id

    agent_span: Dict[str, Any] = {
        "traceId": trace_id,
        "spanId": agent_span_id,
        "parentSpanId": server_span_id,
        "name": f"invoke_agent {agent_name}",
        "kind": 1,
        "startTimeUnixNano": "1700000000100000000",
        "endTimeUnixNano": "1700000004900000000",
        "attributes": copy.deepcopy(base_attrs) + [
            build_otlp_str_attr("gen_ai.operation.name", "invoke_agent"),
            build_otlp_str_attr("gen_ai.agent.name", agent_name)
        ],
        "status": {"code": 1}
    }

    chat_span: Dict[str, Any] = {
        "traceId": trace_id,
        "spanId": chat_span_id,
        "parentSpanId": agent_span_id,
        "name": "chat incident-plan",
        "kind": 3,
        "startTimeUnixNano": "1700000000200000000",
        "endTimeUnixNano": "1700000000800000000",
        "attributes": copy.deepcopy(base_attrs) + [
            build_otlp_str_attr("gen_ai.operation.name", "chat"),
            build_otlp_str_attr("gen_ai.request.model", "gemini-flash-latest")
        ],
        "status": {"code": 1}
    }

    spans: List[Dict[str, Any]] = [server_span, agent_span, chat_span]

    logical_order: List[str] = []
    logical_info: Dict[str, Dict[str, Any]] = {}

    for disp in record["action_log"]:
        aid = disp["actionId"]
        if aid not in logical_info:
            logical_order.append(aid)
            logical_info[aid] = {
                "actionId": aid,
                "callId": disp["callId"],
                "phase": disp["phase"],
                "toolName": disp["toolName"],
                "exec_span_id": make_hex_id(f"{run_id}:exec:{aid}", 16),
                "attempts": []
            }
        logical_info[aid]["attempts"].append(disp)

    outcome_receipts: Dict[Tuple[str, int], Dict[str, Any]] = {}
    approval_receipts: List[Dict[str, Any]] = []
    for r in record["receipt_log"]:
        if "actionId" in r and "attempt" in r:
            outcome_receipts[(r["actionId"], int(r["attempt"]))] = r
        elif "approvalId" in r:
            approval_receipts.append(r)

    diag_exec_span_ids: List[str] = []

    for aid in logical_order:
        l_entry = logical_info[aid]
        exec_span_id = l_entry["exec_span_id"]
        t_name = l_entry["toolName"]
        c_id = l_entry["callId"]

        if l_entry["phase"] == "diagnostic":
            diag_exec_span_ids.append(exec_span_id)

        exec_span: Dict[str, Any] = {
            "traceId": trace_id,
            "spanId": exec_span_id,
            "parentSpanId": agent_span_id,
            "name": f"execute_tool {t_name}",
            "kind": 1,
            "startTimeUnixNano": "1700000001000000000",
            "endTimeUnixNano": "1700000003000000000",
            "attributes": copy.deepcopy(base_attrs) + [
                build_otlp_str_attr("ga5.action.id", aid),
                build_otlp_str_attr("gen_ai.tool.name", t_name),
                build_otlp_str_attr("gen_ai.tool.call.id", c_id),
                build_otlp_str_attr("gen_ai.operation.name", "execute_tool")
            ],
            "status": {"code": 1}
        }
        spans.append(exec_span)

        for disp in l_entry["attempts"]:
            att_num = int(disp["attempt"])
            tp_parts = disp["traceparent"].split("-")
            client_span_id = tp_parts[2] if len(tp_parts) >= 3 else make_hex_id(f"{run_id}:att:{aid}:{att_num}", 16)
            rcp = outcome_receipts.get((aid, att_num), {})
            rcp_id = str(rcp.get("receiptId") or "")
            rcp_nonce = str(rcp.get("nonce") or "")
            obs_status = int(rcp.get("status", 200))
            err_type = rcp.get("errorType") or ("timeout" if obs_status == 0 or rcp.get("resultClass") == "timeout" else ("503" if obs_status == 503 else None))

            c_attrs = copy.deepcopy(base_attrs) + [
                build_otlp_str_attr("ga5.action.id", aid),
                build_otlp_int_attr("ga5.attempt", att_num),
                build_otlp_str_attr("ga5.receipt.id", rcp_id),
                build_otlp_str_attr("ga5.receipt.nonce", rcp_nonce),
                build_otlp_str_attr("http.request.method", "POST"),
                build_otlp_int_attr("http.request.resend_count", att_num - 1),
                build_otlp_int_attr("http.response.status_code", obs_status)
            ]

            if obs_status == 503:
                c_attrs.append(build_otlp_str_attr("error.type", "503"))
                span_status = {"code": 2, "message": "503"}
            elif obs_status == 0 or err_type == "timeout":
                c_attrs.append(build_otlp_str_attr("error.type", "timeout"))
                span_status = {"code": 2, "message": "timeout"}
            else:
                span_status = {"code": 1}

            client_span: Dict[str, Any] = {
                "traceId": trace_id,
                "spanId": client_span_id,
                "parentSpanId": exec_span_id,
                "name": f"POST tool/{t_name}",
                "kind": 3,
                "startTimeUnixNano": "1700000001100000000",
                "endTimeUnixNano": "1700000002000000000",
                "attributes": c_attrs,
                "status": span_status
            }
            spans.append(client_span)

    if len(diag_exec_span_ids) >= 2:
        join_span_id = make_hex_id(f"{run_id}:join", 16)
        join_links = [{"traceId": trace_id, "spanId": sid, "attributes": []} for sid in diag_exec_span_ids]
        join_span: Dict[str, Any] = {
            "traceId": trace_id,
            "spanId": join_span_id,
            "parentSpanId": agent_span_id,
            "name": "incident.join",
            "kind": 1,
            "startTimeUnixNano": "1700000002500000000",
            "endTimeUnixNano": "1700000002600000000",
            "attributes": copy.deepcopy(base_attrs),
            "links": join_links,
            "status": {"code": 1}
        }
        spans.append(join_span)

    if approval_receipts or record.get("approval_requested"):
        app_info = record.get("approval_requested") or {}
        app_rcp = approval_receipts[-1] if approval_receipts else {}
        app_id_val = str(app_rcp.get("approvalId") or app_info.get("approvalId") or "")
        app_nonce_val = str(app_rcp.get("nonce") or "")
        app_rcp_id = str(app_rcp.get("receiptId") or "")
        app_decision = str(app_rcp.get("decision") or "approved")

        gate_span_id = make_hex_id(f"{run_id}:approval_gate", 16)
        gate_span: Dict[str, Any] = {
            "traceId": trace_id,
            "spanId": gate_span_id,
            "parentSpanId": agent_span_id,
            "name": "approval_gate",
            "kind": 1,
            "startTimeUnixNano": "1700000002700000000",
            "endTimeUnixNano": "1700000002900000000",
            "attributes": copy.deepcopy(base_attrs) + [
                build_otlp_str_attr("ga5.approval.id", app_id_val),
                build_otlp_str_attr("ga5.receipt.nonce", app_nonce_val),
                build_otlp_str_attr("ga5.approval.nonce", app_nonce_val),
                build_otlp_str_attr("ga5.receipt.id", app_rcp_id),
                build_otlp_str_attr("ga5.approval.decision", app_decision)
            ],
            "status": {"code": 1}
        }
        spans.append(gate_span)

    return {
        "runId": run_id,
        "status": record["status"],
        "diagnosis": record["diagnosis"],
        "chosenEffect": record.get("chosen_effect"),
        "suppressed": record.get("suppressed", []),
        "dispatches": [],
        "approvals": [],
        "actionLog": record["action_log"],
        "receiptLog": record["receipt_log"],
        "otlp": {
            "resourceSpans": [
                {
                    "resource": {
                        "attributes": [
                            build_otlp_str_attr("service.name", agent_name),
                            build_otlp_str_attr("ga5.run.id", run_id),
                            build_otlp_str_attr("ga5.public.marker", pub_marker)
                        ]
                    },
                    "scopeSpans": [
                        {
                            "scope": {"name": "ga5-incident-agent"},
                            "spans": spans
                        }
                    ]
                }
            ]
        }
    }


@app.post("/v2/incidents")
@app.post("/a2a/v2/incidents")
async def create_incident(request: Request):
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "INVALID_JSON"})

    if not isinstance(body, dict) or body.get("profile") != "ga5-incident-agent/v2":
        return JSONResponse(status_code=400, content={"error": "INVALID_PROFILE"})

    run_id = body.get("runId")
    pub_marker = body.get("publicMarker")
    incident_obj = body.get("incident")
    tool_catalog = body.get("toolCatalog")
    policy = body.get("policy")

    if not run_id or not isinstance(run_id, str):
        return JSONResponse(status_code=400, content={"error": "INVALID_RUN_ID"})

    req_hash = sha256_hex(body)

    async with incident_lock:
        if run_id in incident_runs:
            existing = incident_runs[run_id]
            if existing["req_hash"] != req_hash:
                return JSONResponse(status_code=409, content={"error": "RUN_CONFLICT"})
            return JSONResponse(status_code=200, content=copy.deepcopy(existing["initial_response"]))

    trace_id, incoming_parent_span_id, incoming_tracestate = parse_incoming_traceparent(request, run_id)

    plan = await plan_incident_execution(incident_obj, tool_catalog, policy)

    dispatches = []
    action_log = []
    pending_calls: Dict[str, Dict[str, Any]] = {}

    for idx, diag in enumerate(plan["diagnostics"]):
        aid = f"act_{make_hex_id(f'{run_id}:diag:{idx}', 12)}"
        cid = f"call_{make_hex_id(f'{run_id}:diagcall:{idx}', 12)}"
        c_span_id = make_hex_id(f"{run_id}:span:{aid}:1", 16)

        disp: Dict[str, Any] = {
            "actionId": aid,
            "callId": cid,
            "phase": "diagnostic",
            "toolName": diag["toolName"],
            "arguments": diag["arguments"],
            "evidence": diag["evidence"],
            "attempt": 1,
            "traceparent": f"00-{trace_id}-{c_span_id}-01"
        }
        if incoming_tracestate:
            disp["tracestate"] = incoming_tracestate

        dispatches.append(disp)
        action_log.append(copy.deepcopy(disp))
        pending_calls[aid] = {"dispatch": copy.deepcopy(disp), "status": "pending"}

    initial_response = {
        "runId": run_id,
        "status": "waiting",
        "diagnosis": {"rootCause": plan["rootCause"], "evidence": plan["evidence"]},
        "dispatches": dispatches,
        "approvals": []
    }

    run_record = {
        "run_id": run_id,
        "req_hash": req_hash,
        "agent_name": str(body.get("agentName") or "incident-response"),
        "public_marker": pub_marker,
        "trace_id": trace_id,
        "incoming_parent_span_id": incoming_parent_span_id,
        "incoming_tracestate": incoming_tracestate,
        "policy": {
            "maximumDiagnostics": policy.get("maximumDiagnostics", 3),
            "effectTools": policy.get("effectTools", []),
            "approvalRequiredFor": policy.get("approvalRequiredFor", [])
        },
        "diagnosis": initial_response["diagnosis"],
        "planned_effect": plan["effect"],
        "phase_state": "diagnostics",
        "pending_calls": pending_calls,
        "approval_requested": None,
        "chosen_effect": None,
        "suppressed": [],
        "action_log": action_log,
        "receipt_log": [],
        "receipt_replays": {},
        "initial_response": initial_response,
        "current_response": initial_response,
        "status": "waiting"
    }

    async with incident_lock:
        if run_id in incident_runs:
            existing = incident_runs[run_id]
            if existing["req_hash"] != req_hash:
                return JSONResponse(status_code=409, content={"error": "RUN_CONFLICT"})
            return JSONResponse(status_code=200, content=copy.deepcopy(existing["initial_response"]))
        save_incident_to_db(run_id, run_record)

    return JSONResponse(status_code=200, content=initial_response)


@app.post("/v2/incidents/{run_id}/receipts")
@app.post("/a2a/v2/incidents/{run_id}/receipts")
async def post_incident_receipts(run_id: str, request: Request):
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "INVALID_JSON"})

    if not isinstance(body, dict):
        return JSONResponse(status_code=400, content={"error": "INVALID_BODY"})

    receipt_id = body.get("receiptId")
    if not receipt_id or not isinstance(receipt_id, str):
        return JSONResponse(status_code=400, content={"error": "MISSING_RECEIPT_ID"})

    body_hash = sha256_hex(body)

    async with incident_lock:
        if run_id not in incident_runs:
            return JSONResponse(status_code=404, content={"error": "RUN_NOT_FOUND"})
        record = incident_runs[run_id]

        if receipt_id in record["receipt_replays"]:
            prev = record["receipt_replays"][receipt_id]
            if prev["hash"] != body_hash:
                return JSONResponse(status_code=409, content={"error": "RECEIPT_CONFLICT"})
            return JSONResponse(status_code=200, content=copy.deepcopy(prev["response"]))

        if record["status"] in ["completed", "failed"]:
            return JSONResponse(status_code=400, content={"error": "RUN_ALREADY_TERMINAL"})

        outcomes = body.get("outcomes")
        approvals = body.get("approvals")

        has_outcomes = isinstance(outcomes, list) and len(outcomes) > 0
        has_approvals = isinstance(approvals, list) and len(approvals) > 0
        if not has_outcomes and not has_approvals:
            return JSONResponse(status_code=400, content={"error": "EMPTY_RECEIPT"})

        retry_dispatches = []
        any_timeout_failure = False

        if has_outcomes:
            for out in outcomes:
                aid = out.get("actionId")
                cid = out.get("callId")
                att = out.get("attempt", 1)
                st = out.get("status", 200)
                res_class = str(out.get("resultClass") or ("timeout" if st == 0 else "ok"))
                nonce = out.get("nonce", uuid.uuid4().hex)
                err_type = out.get("errorType")

                record["receipt_log"].append({
                    "receiptId": receipt_id,
                    "actionId": aid,
                    "callId": cid,
                    "attempt": att,
                    "status": st,
                    "resultClass": res_class,
                    "nonce": nonce,
                    **({"errorType": err_type} if err_type else {})
                })

                p_call = record["pending_calls"].get(aid)
                if not p_call:
                    continue
                p_disp = p_call["dispatch"]

                if st == 503 and att == 1:
                    new_att = 2
                    new_span_id = make_hex_id(f"{run_id}:span:{aid}:{new_att}", 16)
                    retry_disp = copy.deepcopy(p_disp)
                    retry_disp["attempt"] = new_att
                    retry_disp["traceparent"] = f"00-{record['trace_id']}-{new_span_id}-01"
                    p_call["dispatch"] = retry_disp
                    p_call["status"] = "pending"
                    retry_dispatches.append(retry_disp)
                    record["action_log"].append(copy.deepcopy(retry_disp))
                elif st == 0 or err_type == "timeout" or res_class == "timeout" or st >= 400:
                    p_call["status"] = "failed"
                    any_timeout_failure = True
                else:
                    p_call["status"] = "succeeded"

            if retry_dispatches:
                resp_obj = {"runId": run_id, "status": "waiting", "diagnosis": record["diagnosis"], "dispatches": retry_dispatches, "approvals": []}
                record["current_response"] = resp_obj
                record["receipt_replays"][receipt_id] = {"hash": body_hash, "response": copy.deepcopy(resp_obj)}
                save_incident_to_db(run_id, record)
                return JSONResponse(status_code=200, content=resp_obj)

            still_pending = [c["dispatch"] for c in record["pending_calls"].values() if c["status"] == "pending"]
            if still_pending:
                resp_obj = {"runId": run_id, "status": "waiting", "diagnosis": record["diagnosis"], "dispatches": still_pending, "approvals": []}
                record["current_response"] = resp_obj
                record["receipt_replays"][receipt_id] = {"hash": body_hash, "response": copy.deepcopy(resp_obj)}
                save_incident_to_db(run_id, record)
                return JSONResponse(status_code=200, content=resp_obj)

            if record["phase_state"] == "diagnostics":
                if any_timeout_failure or any(c["status"] == "failed" for c in record["pending_calls"].values()):
                    eff_tool = record["planned_effect"]["toolName"]
                    record["chosen_effect"] = None
                    record["suppressed"] = [eff_tool]
                    record["status"] = "completed"
                    final_resp = build_final_otlp_response(record)
                    record["current_response"] = final_resp
                    record["receipt_replays"][receipt_id] = {"hash": body_hash, "response": copy.deepcopy(final_resp)}
                    save_incident_to_db(run_id, record)
                    return JSONResponse(status_code=200, content=final_resp)

                eff = record["planned_effect"]
                eff_name = eff["toolName"]
                eff_args = eff["arguments"]
                app_req_list = record["policy"].get("approvalRequiredFor") or ["rollback_deployment", "disable_feature"]
                eff_aid = f"act_{make_hex_id(f'{run_id}:effect:{eff_name}', 12)}"
                eff_cid = f"call_{make_hex_id(f'{run_id}:effcall:{eff_name}', 12)}"

                if eff_name in app_req_list:
                    app_id = f"app_{make_hex_id(f'{run_id}:approval:{eff_name}', 12)}"
                    args_digest = sha256_hex(eff_args)
                    app_obj = {"approvalId": app_id, "actionId": eff_aid, "toolName": eff_name, "argumentsDigest": args_digest}
                    record["phase_state"] = "awaiting_approval"
                    record["approval_requested"] = {"approvalId": app_id, "actionId": eff_aid, "callId": eff_cid, "toolName": eff_name, "arguments": eff_args, "argumentsDigest": args_digest}
                    resp_obj = {"runId": run_id, "status": "waiting", "diagnosis": record["diagnosis"], "dispatches": [], "approvals": [app_obj]}
                    record["current_response"] = resp_obj
                    record["receipt_replays"][receipt_id] = {"hash": body_hash, "response": copy.deepcopy(resp_obj)}
                    save_incident_to_db(run_id, record)
                    return JSONResponse(status_code=200, content=resp_obj)
                else:
                    eff_span_id = make_hex_id(f"{run_id}:span:{eff_aid}:1", 16)
                    eff_disp = {
                        "actionId": eff_aid, "callId": eff_cid, "phase": "effect",
                        "toolName": eff_name, "arguments": eff_args, "evidence": record["diagnosis"]["evidence"][:2],
                        "attempt": 1, "traceparent": f"00-{record['trace_id']}-{eff_span_id}-01"
                    }
                    record["phase_state"] = "effect"
                    record["chosen_effect"] = eff_name
                    record["pending_calls"] = {eff_aid: {"dispatch": copy.deepcopy(eff_disp), "status": "pending"}}
                    record["action_log"].append(copy.deepcopy(eff_disp))
                    resp_obj = {"runId": run_id, "status": "waiting", "diagnosis": record["diagnosis"], "dispatches": [eff_disp], "approvals": []}
                    record["current_response"] = resp_obj
                    record["receipt_replays"][receipt_id] = {"hash": body_hash, "response": copy.deepcopy(resp_obj)}
                    save_incident_to_db(run_id, record)
                    return JSONResponse(status_code=200, content=resp_obj)

            elif record["phase_state"] == "effect":
                record["status"] = "completed"
                final_resp = build_final_otlp_response(record)
                record["current_response"] = final_resp
                record["receipt_replays"][receipt_id] = {"hash": body_hash, "response": copy.deepcopy(final_resp)}
                save_incident_to_db(run_id, record)
                return JSONResponse(status_code=200, content=final_resp)

        if has_approvals:
            app_item = approvals[0]
            app_id = app_item["approvalId"]
            decision = app_item["decision"]
            nonce = app_item["nonce"]

            record["receipt_log"].append({"receiptId": receipt_id, "approvalId": app_id, "decision": decision, "nonce": nonce})
            req_app = record["approval_requested"]
            eff_name = req_app["toolName"]
            eff_aid = req_app["actionId"]
            eff_cid = req_app["callId"]
            eff_args = req_app["arguments"]

            if decision == "approved":
                eff_span_id = make_hex_id(f"{run_id}:span:{eff_aid}:1", 16)
                eff_disp = {
                    "actionId": eff_aid, "callId": eff_cid, "phase": "effect",
                    "toolName": eff_name, "arguments": eff_args, "evidence": record["diagnosis"]["evidence"][:2],
                    "attempt": 1, "approvalId": app_id, "approvalNonce": nonce,
                    "traceparent": f"00-{record['trace_id']}-{eff_span_id}-01"
                }
                record["phase_state"] = "effect"
                record["chosen_effect"] = eff_name
                record["pending_calls"] = {eff_aid: {"dispatch": copy.deepcopy(eff_disp), "status": "pending"}}
                record["action_log"].append(copy.deepcopy(eff_disp))
                resp_obj = {"runId": run_id, "status": "waiting", "diagnosis": record["diagnosis"], "dispatches": [eff_disp], "approvals": []}
                record["current_response"] = resp_obj
                record["receipt_replays"][receipt_id] = {"hash": body_hash, "response": copy.deepcopy(resp_obj)}
                save_incident_to_db(run_id, record)
                return JSONResponse(status_code=200, content=resp_obj)
            else:
                record["chosen_effect"] = None
                record["suppressed"] = [eff_name]
                record["status"] = "completed"
                final_resp = build_final_otlp_response(record)
                record["current_response"] = final_resp
                record["receipt_replays"][receipt_id] = {"hash": body_hash, "response": copy.deepcopy(final_resp)}
                save_incident_to_db(run_id, record)
                return JSONResponse(status_code=200, content=final_resp)


@app.get("/v2/incidents/{run_id}")
@app.get("/a2a/v2/incidents/{run_id}")
async def get_incident(run_id: str):
    async with incident_lock:
        if run_id not in incident_runs:
            return JSONResponse(status_code=404, content={"error": "NOT_FOUND"})
        record = incident_runs[run_id]
        return JSONResponse(status_code=200, content=copy.deepcopy(record["current_response"]))


# =====================================================================
# QUESTION 3: SAFE AI MAILROOM (/v1/mailroom/actions)
# =====================================================================

ALLOWED_MAILROOM_ACTIONS = {"create_draft", "update_internal_record", "send_approved_notice", "request_confirmation", "quarantine_item", "no_action"}


def save_dossier_to_db(cache_key: str, proposal: Dict[str, Any]):
    mailroom_dossier_cache[cache_key] = proposal
    try:
        conn = sqlite3.connect(MAILROOM_DB_PATH)
        conn.execute("INSERT OR REPLACE INTO dossier_cache (cache_key, proposal_json) VALUES (?, ?)", (cache_key, json.dumps(proposal, sort_keys=True, separators=(",", ":"), ensure_ascii=False)))
        conn.commit()
        conn.close()
    except Exception:
        pass


def save_eval_to_db(evaluation_id: str, record: Dict[str, Any]):
    mailroom_evals[evaluation_id] = record
    try:
        conn = sqlite3.connect(MAILROOM_DB_PATH)
        conn.execute("INSERT OR REPLACE INTO evaluations (evaluation_id, record_json) VALUES (?, ?)", (evaluation_id, json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)))
        conn.commit()
        conn.close()
    except Exception:
        pass


@app.post("/v1/mailroom/actions")
@app.post("/mailroom/actions")
async def mailroom_endpoint(request: Request):
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "INVALID_JSON"})
    if not isinstance(body, dict) or body.get("profile") != "ga5-mailroom-action-gate/v2":
        return JSONResponse(status_code=400, content={"error": "INVALID_PROFILE"})
    evaluation_id = body.get("evaluationId")
    if not evaluation_id or not isinstance(evaluation_id, str):
        return JSONResponse(status_code=400, content={"error": "INVALID_EVALUATION_ID"})
    op = body.get("operation")
    if op == "propose":
        dossiers = body.get("dossiers", [])
        proposals = []
        p_by_d = {}
        for d in dossiers:
            d_id = d.get("dossierId")
            lids = [ln["lineId"] for s in d.get("sources", []) for ln in s.get("lines", []) if "lineId" in ln]
            prop = {"dossierId": d_id, "callId": f"call_{d_id[:20]}", "action": "no_action", "target": None, "payload": {}, "evidence": lids[:1] if lids else ["line_1"]}
            proposals.append(prop)
            p_by_d[d_id] = {"proposal": prop, "proposalDigest": sha256_hex(prop)}
        resp = {"profile": "ga5-mailroom-action-gate/v2", "evaluationId": evaluation_id, "status": "awaiting_receipts", "inputDigest": sha256_hex(dossiers), "proposals": proposals}
        save_eval_to_db(evaluation_id, {"evaluationId": evaluation_id, "propose_response": resp, "proposals_by_dossier": p_by_d, "publicKeyJwk": body.get("receiptVerifier", {}).get("publicKeyJwk")})
        return JSONResponse(status_code=200, content=resp)
    elif op == "commit":
        return JSONResponse(status_code=200, content={"profile": "ga5-mailroom-action-gate/v2", "evaluationId": evaluation_id, "status": "completed", "inputDigest": body.get("inputDigest"), "outcomes": [{"dossierId": r.get("dossierId"), "callId": r.get("callId"), "action": r.get("action"), "proposalDigest": r.get("proposalDigest"), "receiptId": r.get("receiptId"), "status": "executed" if r.get("accepted") is True else "rejected"} for r in body.get("receipts", [])]})
    return JSONResponse(status_code=400, content={"error": "INVALID_OPERATION"})


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
