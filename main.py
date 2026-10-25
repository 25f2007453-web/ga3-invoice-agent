import hashlib
import json
import uuid
import asyncio
import os
from fastapi import FastAPI, Request, Header, HTTPException, Depends
from fastapi.responses import JSONResponse
from typing import Dict, Any, Optional

app = FastAPI()
global_lock = asyncio.Lock()

# --- In-Memory State ---
idempotency_store: Dict[str, str] = {} 
tasks_db: Dict[str, Dict[str, Any]] = {}
decision_cache: Dict[str, Dict[str, Any]] = {}

async def verify_a2a_protocol(
    request: Request,
    authorization: Optional[str] = Header(None),
    a2a_version: Optional[str] = Header(None, alias="A2A-Version"),
    content_type: Optional[str] = Header(None, alias="Content-Type")
) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Bearer token")
    if a2a_version != "1.0":
        raise HTTPException(status_code=400, detail="A2A-Version must be 1.0")
    if content_type != "application/a2a+json":
        raise HTTPException(status_code=400, detail="Invalid Content-Type")
    return authorization.split(" ")[1]

@app.get("/.well-known/agent-card.json")
async def get_agent_card():
    return {
        "name": "Invoice Action Agent",
        "description": "Evaluates commercial invoice packages.",
        "version": "1.0.0",
        "capabilities": {
            "invoice_action_agent": {
                "name": "Invoice Skill",
                "description": "Reads invoices and determines actions.",
                "tags": ["finance", "invoice"],
                "supportedInterfaces": [{
                    "protocolBinding": "HTTP+JSON",
                    "protocolVersion": "1.0",
                    "defaultInputModes": ["application/vnd.ga5.invoice-claim-batch+json"],
                    "defaultOutputModes": [
                        "application/vnd.ga5.invoice-action-proposals+json",
                        "application/vnd.ga5.invoice-action-receipts+json"
                    ]
                }]
            }
        }
    }

@app.post("/message:send")
async def send_message(request: Request, token: str = Depends(verify_a2a_protocol)):
    body = await request.json()
    message = body.get("message", {})
    message_id = message.get("messageId")
    
    if not message_id:
        raise HTTPException(status_code=400, detail="Missing messageId")

    message_json = json.dumps(message, sort_keys=True, separators=(',', ':'))
    message_hash = hashlib.sha256(message_json.encode()).hexdigest()
    idem_key = f"{token}_{message_id}"

    async with global_lock:
        if idem_key in idempotency_store:
            if idempotency_store[idem_key] != message_hash:
                return JSONResponse(status_code=409, content={"error": "IDEMPOTENCY_CONFLICT"})
            task_id = message.get("taskId") or message_id 
            return JSONResponse(content={"task": tasks_db[f"{token}_{task_id}"]})

        idempotency_store[idem_key] = message_hash
        # FIXED: Use the messageId for the task_id to ensure idempotency lookups succeed
        task_id = message.get("taskId") or message_id
        
        parts = message.get("parts", [])
        proposals = []
        batch_id = ""
        
        if parts and parts[0].get("mediaType") == "application/vnd.ga5.invoice-claim-batch+json":
            batch_data = parts[0].get("data", {})
            batch_id = batch_data.get("batchId", "")
            packages = batch_data.get("packages", [])
            
            for pkg in packages:
                pkg_hash = hashlib.sha256(json.dumps(pkg, sort_keys=True).encode()).hexdigest()
                
                if pkg_hash in decision_cache:
                    decision = decision_cache[pkg_hash]
                else:
                    decision = await evaluate_package_with_llm(pkg, batch_data.get("policyRevision", ""))
                    decision_cache[pkg_hash] = decision
                
                proposals.append({
                    "packageId": pkg.get("packageId"),
                    "actionId": str(uuid.uuid4()).replace("-", ""),
                    "action": decision["action"],
                    "facts": decision["facts"],
                    "evidenceRefs": decision["evidenceRefs"],
                    "rationale": decision["rationale"]
                })
        
        task = {
            "taskId": task_id,
            "state": "TASK_STATE_INPUT_REQUIRED",
            "history": [message],
            "parts": [{
                "mediaType": "application/vnd.ga5.invoice-action-proposals+json",
                "data": {
                    "batchId": batch_id,
                    "proposals": proposals
                }
            }]
        }
        
        tasks_db[f"{token}_{task_id}"] = task
        return JSONResponse(content={"task": task}, media_type="application/a2a+json")

@app.post("/tasks/{task_id}")
async def process_continuation(task_id: str, request: Request, token: str = Depends(verify_a2a_protocol)):
    body = await request.json()
    
    async with global_lock:
        task_key = f"{token}_{task_id}"
        if task_key not in tasks_db:
            raise HTTPException(status_code=404, detail="Task not found")
            
        task = tasks_db[task_key]
        parts = body.get("parts", [])
        new_executions = []
        
        for part in parts:
            if part.get("mediaType") == "application/vnd.ga5.invoice-action-results+json":
                results = part.get("data", {}).get("results", [])
                for res in results:
                    if res.get("outcome") == "ACCEPTED":
                        new_executions.append({
                            "packageId": res.get("packageId"),
                            "actionId": res.get("actionId"),
                            "action": res.get("action"),
                            "receiptNonce": res.get("receiptNonce"),
                            "facts": {"vendorName": "Vendor", "invoiceNumber": "123", "amountMinor": 12345, "currency": "INR"},
                            "evidenceRefs": ["[1]"]
                        })

        if new_executions:
            task["state"] = "COMPLETED"
            task["parts"].append({
                "mediaType": "application/vnd.ga5.invoice-action-receipts+json",
                "data": {
                    "batchId": body.get("message", {}).get("parts")[0].get("data", {}).get("batchId"),
                    "executions": new_executions
                }
            })
            
        task["history"].append(body.get("message"))
        return JSONResponse(content={"task": task}, media_type="application/a2a+json")

@app.post("/tasks/{task_id}:cancel")
async def cancel_task(task_id: str, token: str = Depends(verify_a2a_protocol)):
    async with global_lock:
        task_key = f"{token}_{task_id}"
        if task_key not in tasks_db:
            raise HTTPException(status_code=404, detail="Task not found")
            
        task = tasks_db[task_key]
        if task["state"] in ["COMPLETED", "CANCELED"]:
            return JSONResponse(status_code=409, content={"error": "TASK_ALREADY_TERMINAL"})
            
        task["state"] = "CANCELED"
        return JSONResponse(content={"task": task}, media_type="application/a2a+json")

@app.get("/tasks")
async def list_tasks(token: str = Depends(verify_a2a_protocol)):
    user_tasks = [task for key, task in tasks_db.items() if key.startswith(f"{token}_")]
    return JSONResponse(content={"tasks": user_tasks}, media_type="application/a2a+json")

@app.get("/tasks/{task_id}")
async def get_task(task_id: str, token: str = Depends(verify_a2a_protocol)):
    task_key = f"{token}_{task_id}"
    if task_key not in tasks_db:
        raise HTTPException(status_code=404, detail="Task not found")
    return JSONResponse(content={"task": tasks_db[task_key]}, media_type="application/a2a+json")

async def evaluate_package_with_llm(package: Dict, policy: str) -> Dict:
    # Replace this block with your actual GenAI/LLM call before the final submission
    return {
        "action": "settle_invoice",
        "facts": {"vendorName": "Vendor X", "invoiceNumber": "INV-1", "amountMinor": 12345, "currency": "INR"},
        "evidenceRefs": ["[3]", "[4]", "[7]"],
        "rationale": "The invoice is valid, commercially reconciled, and within autonomous authority limits as referenced in [3] and [4]. [7] confirms no discrepancies."
    }

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
