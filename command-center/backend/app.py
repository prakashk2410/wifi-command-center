"""
app.py — Wi-Fi Command Center backend (FastAPI).  100% local, authorized-only.

Run:
    cd "/Users/macbook/Ai agent /wifi-lab/command-center/backend"
    python3 -m venv .venv && source .venv/bin/activate
    pip install -r requirements.txt
    uvicorn app:app --host 127.0.0.1 --port 8787 --reload
    # then open http://localhost:8787

WHAT IT EXPOSES
    GET  /health                              liveness + a quick Kali/Ollama/allowlist summary
    GET  /actions                             action catalogue (names, gated flag) for the UI
    GET  /allowlist                           list authorized BSSIDs
    POST /allowlist/add                       {bssid,label?}             -> add one
    POST /allowlist/add_from_scan             {index?|bssid?}            -> authorize a scan row
    POST /allowlist/authorize_all_scanned     {confirm:true}            -> authorize the whole last scan
    POST /action/{name}                       {...params}  (non-stream, returns {logs,result})
    POST /ai                                  {prompt}     (non-stream, returns {logs,reply,executed})
    WS   /ws                                  streaming: {type:"run"|"ai"|"stop", ...}
    /*                                         static files from ../ui  (the console UI)

BINDS TO LOOPBACK ONLY (127.0.0.1). This console runs gated attack tooling; never expose it
on a routable interface. The allowlist gate lives in actions.py and is re-checked on every call.
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

import actions as A

app = FastAPI(title="Wi-Fi Command Center", version="1.0",
              description="Local, authorized-only Wi-Fi audit console. Allowlist-gated. 100% local.")

# UI lives beside the backend at ../ui (env-overridable). Served as static at the end.
UI_DIR = Path(os.environ.get("WIFI_UI_DIR", str(Path(__file__).resolve().parent.parent / "ui")))

# Same-origin in normal use; allow localhost origins so the page also works if opened from file://.
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"^https?://(localhost|127\.0\.0\.1)(:\d+)?$",
    allow_methods=["*"], allow_headers=["*"], allow_credentials=False,
)


@app.middleware("http")
async def _no_cache_ui(request, call_next):
    """Serve the console UI with no-store so a code update ALWAYS shows on refresh. Without this
    the browser serves a stale app.js/index.html (a 304), which looks like 'nothing changed'."""
    resp = await call_next(request)
    path = request.url.path or "/"
    if path == "/" or path.endswith((".html", ".js", ".css")):
        resp.headers["Cache-Control"] = "no-store, must-revalidate"
        resp.headers["Pragma"] = "no-cache"
    return resp


# ----------------------------------------------------------------------------- models
class AddBody(BaseModel):
    bssid: str
    label: Optional[str] = None
    essid: Optional[str] = None


class AddFromScanBody(BaseModel):
    index: Optional[int] = None
    bssid: Optional[str] = None


class ConfirmBody(BaseModel):
    confirm: bool = False


class AiBody(BaseModel):
    prompt: str


# --- /api/* request bodies (the shapes the console UI sends) ---
class ResetBody(BaseModel):
    hard: bool = False


class AuthorizeBody(BaseModel):
    bssid: str
    essid: Optional[str] = None
    label: Optional[str] = None


class DeauthorizeBody(BaseModel):
    bssid: str


class AuthorizeAllBody(BaseModel):
    confirm: bool = False
    bssids: Optional[List[str]] = None


class AttackBody(BaseModel):
    bssid: Optional[str] = None
    ch: Optional[int] = None
    channel: Optional[int] = None
    mode: Optional[str] = None
    seconds: Optional[int] = None
    client: Optional[str] = None
    ssid: Optional[str] = None


class CrackBody(BaseModel):
    level: Optional[int] = 1
    bssid: Optional[str] = None
    capfile: Optional[str] = None
    mask: Optional[str] = None
    single: Optional[bool] = False


class ChatBody(BaseModel):
    message: str


# ----------------------------------------------------------------------------- health / catalogue
@app.get("/health")
async def health() -> Dict[str, Any]:
    return {
        "ok": True,
        "service": "wifi-command-center",
        "kali_reachable": await A.ssh_ok(timeout=5),
        "kali_host": A.KALI_HOST,
        "ollama_url": A.OLLAMA_URL,
        "ollama_model": A.OLLAMA_MODEL,
        "allowlist_count": len(A.load_authorized()),
        "last_scan_count": len(A.STATE.last_scan),
        "ai_can_authorize": A.ALLOW_AI_AUTHORIZE,
        "auth_file": str(A.AUTH_FILE),
    }


@app.get("/actions")
async def actions_catalogue() -> Dict[str, Any]:
    return {
        "actions": [
            {"name": name, "gated": spec["needs_bssid"],
             "needs_bssid": spec["needs_bssid"]}
            for name, spec in A.ACTIONS.items()
        ],
        "note": "Every needs_bssid action is refused unless the BSSID is in the allowlist.",
    }


# ----------------------------------------------------------------------------- allowlist
@app.get("/allowlist")
async def allowlist_get() -> Dict[str, Any]:
    items = A.allowlist_list()
    return {"ok": True, "count": len(items), "allowlist": items}


@app.post("/allowlist/add")
async def allowlist_add(body: AddBody) -> JSONResponse:
    res = A.allowlist_add(body.bssid, label=body.label, essid=body.essid, source="manual")
    return JSONResponse(res, status_code=200 if res.get("ok") else 400)


@app.post("/allowlist/add_from_scan")
async def allowlist_add_from_scan(body: AddFromScanBody) -> JSONResponse:
    res = A.allowlist_add_from_scan(index=body.index, bssid=body.bssid)
    return JSONResponse(res, status_code=200 if res.get("ok") else 400)


@app.post("/allowlist/authorize_all_scanned")
async def allowlist_authorize_all(body: ConfirmBody) -> JSONResponse:
    res = A.allowlist_authorize_all_scanned(confirm=body.confirm)
    return JSONResponse(res, status_code=200 if res.get("ok") else 400)


# ----------------------------------------------------------------------------- non-streaming action/ai
@app.post("/action/{name}")
async def run_action_http(name: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Convenience: run an action and return collected logs + result. For long/streaming
    actions (crack, capture) prefer the /ws WebSocket, which streams live and supports STOP."""
    logs: List[str] = []

    async def emit(line: str) -> None:
        logs.append(line)

    result = await A.run_action(name, params or {}, emit)
    return {"ok": result.get("ok", False), "logs": logs, "result": result}


@app.post("/ai")
async def run_ai_http(body: AiBody) -> Dict[str, Any]:
    """Non-streaming NL command. Streams live over /ws instead when you want the console feed."""
    logs: List[str] = []
    ai_text: List[str] = []

    async def emit(line: str) -> None:
        logs.append(line)

    async def ai_emit(text: str) -> None:
        ai_text.append(text)

    res = await A.run_ai(body.prompt, emit, ai_emit=ai_emit)
    return {"ok": res.get("ok", False), "logs": logs, "reply": res.get("reply", ""),
            "ai_text": ai_text, "executed": res.get("executed", [])}


# ============================================================================= /api/* CONTRACT
# This is the ONE contract the console UI (ui/app.js) speaks. Each route maps to the gated
# action core in actions.py and returns shapes the UI parses directly. HTTP actions carry their
# streamed output back as {"logs": [...]} (the UI renders d.logs line-by-line); the /ws socket
# below remains available as a live stream but is not required for the UI to work end-to-end.
async def _api_action(name: str, params: Dict[str, Any]) -> Dict[str, Any]:
    """Run one gated action over HTTP and return {ok, logs, result}. The allowlist gate in
    actions.run_action() is applied exactly as on the WebSocket path — this adds no bypass."""
    logs: List[str] = []

    async def emit(line: str) -> None:
        logs.append(line)

    result = await A.run_action(name, params or {}, emit)
    return {"ok": result.get("ok", False), "logs": logs, "result": result}


# ---- health ----
@app.get("/api/health")
async def api_health() -> Dict[str, Any]:
    return await health()


# ---- doctor (GET = read-only snapshot; POST /checks = full self-heal; POST /reset = soft/hard) ----
@app.get("/api/doctor")
async def api_doctor() -> Dict[str, Any]:
    # Read-only: safe to poll. Returns {vm,wlan0,monitor,injection,band,aps} with status strings.
    return await A.doctor_status()


@app.post("/api/doctor/checks")
async def api_doctor_checks() -> Dict[str, Any]:
    logs: List[str] = []

    async def emit(line: str) -> None:
        logs.append(line)

    res = await A.action_doctor({"level": "auto"}, emit)
    return {**res.get("status", {}), "ok": res.get("ok", False), "logs": logs}


@app.post("/api/doctor/reset")
async def api_doctor_reset(body: ResetBody) -> Dict[str, Any]:
    logs: List[str] = []

    async def emit(line: str) -> None:
        logs.append(line)

    res = await A.action_doctor({"level": "hard" if body.hard else "soft"}, emit)
    return {**res.get("status", {}), "ok": res.get("ok", False), "logs": logs}


# ---- scan ----
@app.post("/api/scan")
async def api_scan() -> Dict[str, Any]:
    logs: List[str] = []

    async def emit(line: str) -> None:
        logs.append(line)

    res = await A.run_action("scan", {}, emit)
    targets = [
        {"bssid": ap.get("bssid"), "ch": ap.get("channel"), "pwr": ap.get("power"),
         "clients": ap.get("clients"), "essid": ap.get("essid"),
         "authorized": ap.get("authorized", False)}
        for ap in res.get("aps", [])
    ]
    return {"ok": res.get("ok", False), "targets": targets, "logs": logs}


# ---- allowlist ----
@app.get("/api/authorized")
async def api_authorized() -> Dict[str, Any]:
    items = A.allowlist_list()
    return {"list": [it["bssid"] for it in items], "detail": items}


@app.post("/api/authorize")
async def api_authorize(body: AuthorizeBody) -> JSONResponse:
    res = A.allowlist_add(body.bssid, label=body.label, essid=body.essid, source="ui")
    return JSONResponse(res, status_code=200 if res.get("ok") else 400)


@app.delete("/api/authorize")
async def api_deauthorize(body: DeauthorizeBody) -> JSONResponse:
    res = A.allowlist_remove(body.bssid)
    return JSONResponse(res, status_code=200 if res.get("ok") else 400)


@app.post("/api/authorize/all")
async def api_authorize_all(body: AuthorizeAllBody) -> JSONResponse:
    res = A.allowlist_authorize_all_scanned(confirm=body.confirm)
    return JSONResponse(res, status_code=200 if res.get("ok") else 400)


# ---- attack modules (all gated except recon=gated, spoof=own-adapter, rogue=detector) ----
@app.post("/api/attack/recon")
async def api_recon(body: AttackBody) -> Dict[str, Any]:
    params: Dict[str, Any] = {"bssid": body.bssid}
    if body.ch or body.channel:
        params["channel"] = body.ch or body.channel
    return await _api_action("recon", params)


@app.post("/api/attack/spoof")
async def api_spoof(body: AttackBody) -> Dict[str, Any]:
    return await _api_action("spoof", {"mode": body.mode})


@app.post("/api/attack/rogue")
async def api_rogue(body: AttackBody) -> Dict[str, Any]:
    return await _api_action("rogue_detect", {"ssid": body.ssid})


@app.post("/api/attack/deauth")
async def api_deauth(body: AttackBody) -> Dict[str, Any]:
    # UI sends mode "one"|"all"; map to the action's "targeted"|"broadcast".
    mode = "broadcast" if (body.mode or "").lower() in ("all", "broadcast") else "targeted"
    params: Dict[str, Any] = {"bssid": body.bssid, "mode": mode, "duration": body.seconds}
    if body.client:
        params["client"] = body.client
    if body.ch or body.channel:
        params["channel"] = body.ch or body.channel
    return await _api_action("deauth", params)


@app.post("/api/attack/stop")
async def api_stop() -> Dict[str, Any]:
    # HTTP actions run as independent async requests, so STOP best-effort frees the radio by
    # killing any capture/injection tools on Kali and any local Mac-side crack.
    logs: List[str] = []

    async def emit(line: str) -> None:
        logs.append(line)

    await A.stop_remote_radio(emit)
    await A.stop_local_crack(emit)
    return {"ok": True, "logs": logs}


@app.post("/api/attack/capture")
async def api_capture(body: AttackBody) -> Dict[str, Any]:
    params: Dict[str, Any] = {"bssid": body.bssid}
    if body.ch or body.channel:
        params["channel"] = body.ch or body.channel
    return await _api_action("capture_handshake", params)


@app.post("/api/attack/pmkid")
async def api_pmkid(body: AttackBody) -> Dict[str, Any]:
    params: Dict[str, Any] = {"bssid": body.bssid}
    if body.ch or body.channel:
        params["channel"] = body.ch or body.channel
    return await _api_action("pmkid", params)


@app.post("/api/attack/wps")
async def api_wps(body: AttackBody) -> Dict[str, Any]:
    params: Dict[str, Any] = {"bssid": body.bssid}
    if body.ch or body.channel:
        params["channel"] = body.ch or body.channel
    return await _api_action("wps", params)


# ---- crack (Mac GPU; not an on-air attack) ----
@app.post("/api/crack")
async def api_crack(body: CrackBody) -> Dict[str, Any]:
    return await _api_action("crack", {"level": body.level or 1, "capfile": body.capfile,
                                       "bssid": body.bssid, "mask": body.mask, "single": body.single})


@app.post("/api/attack/triage")
async def api_triage(body: AttackBody) -> Dict[str, Any]:
    return await _api_action("triage", {"bssid": body.bssid})


# ---- saved-password vault (cracked keys — password, not hash) ----
@app.get("/api/passwords")
async def api_passwords() -> Dict[str, Any]:
    return {"ok": True, "passwords": A.vault_list()}


@app.post("/api/passwords/clear")
async def api_passwords_clear() -> JSONResponse:
    res = A.vault_clear()
    return JSONResponse(res, status_code=200 if res.get("ok") else 400)


# ---- AI chat ----
@app.post("/api/ai/chat")
async def api_ai_chat(body: ChatBody) -> Dict[str, Any]:
    logs: List[str] = []

    async def emit(line: str) -> None:
        logs.append(line)

    res = await A.run_ai(body.message, emit)
    return {"ok": res.get("ok", False), "reply": res.get("reply", ""),
            "logs": logs, "executed": res.get("executed", [])}


# ----------------------------------------------------------------------------- WebSocket (streaming + STOP)
@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket) -> None:
    """
    Client -> server messages (JSON):
        {"type":"run", "action":"scan", "params":{...}}
        {"type":"ai",  "prompt":"scan the band and recon #3"}
        {"type":"stop"}                         # kill the current action / deauth burst

    Server -> client frames (JSON):
        {"type":"log",    "line": "..."}         # streamed stdout / status
        {"type":"ai",     "text": "..."}         # model's natural-language reply
        {"type":"result", "action": "...", "result": {...}}
        {"type":"ai_done","executed":[...], "reply":"..."}
        {"type":"error",  "message":"..."}
    """
    await ws.accept()
    current: Dict[str, Any] = {"task": None, "proc": None}

    def register(proc: Any) -> None:
        current["proc"] = proc

    async def emit(line: str) -> None:
        await ws.send_json({"type": "log", "line": line})

    async def ai_emit(text: str) -> None:
        await ws.send_json({"type": "ai", "text": text})

    def busy() -> bool:
        t = current.get("task")
        return bool(t and not t.done())

    async def do_stop() -> None:
        A.kill(current.get("proc"))
        t = current.get("task")
        if t and not t.done():
            t.cancel()
        await emit("[*] STOP requested — killing the current process and freeing the radio.")
        # best-effort remote cleanup so the adapter isn't left capturing
        try:
            await A.stop_remote_radio(emit)
        except Exception:
            pass

    try:
        while True:
            msg = await ws.receive_json()
            mtype = msg.get("type")

            if mtype == "stop":
                await do_stop()
                continue

            if mtype == "run":
                if busy():
                    await emit("[!] a task is already running — send STOP first.")
                    continue
                name = msg.get("action", "")
                params = msg.get("params") or {}

                async def job_run(name=name, params=params) -> None:
                    try:
                        res = await A.run_action(name, params, emit, register)
                        await ws.send_json({"type": "result", "action": name, "result": res})
                    except asyncio.CancelledError:
                        await ws.send_json({"type": "result", "action": name,
                                            "result": {"ok": False, "stopped": True, "action": name}})
                    except Exception as e:  # noqa: BLE001
                        await ws.send_json({"type": "error", "message": str(e)})
                    finally:
                        current["proc"] = None

                current["task"] = asyncio.create_task(job_run())

            elif mtype == "ai":
                if busy():
                    await emit("[!] a task is already running — send STOP first.")
                    continue
                prompt = msg.get("prompt", "")

                async def job_ai(prompt=prompt) -> None:
                    try:
                        res = await A.run_ai(prompt, emit, register, ai_emit=ai_emit)
                        await ws.send_json({"type": "ai_done",
                                            "reply": res.get("reply", ""),
                                            "executed": res.get("executed", [])})
                    except asyncio.CancelledError:
                        await ws.send_json({"type": "ai_done", "reply": "", "executed": [], "stopped": True})
                    except Exception as e:  # noqa: BLE001
                        await ws.send_json({"type": "error", "message": str(e)})
                    finally:
                        current["proc"] = None

                current["task"] = asyncio.create_task(job_ai())

            else:
                await ws.send_json({"type": "error", "message": "unknown message type: " + str(mtype)})

    except WebSocketDisconnect:
        # Client went away — stop anything still running and free the radio.
        A.kill(current.get("proc"))
        t = current.get("task")
        if t and not t.done():
            t.cancel()


# ----------------------------------------------------------------------------- static UI (mounted LAST)
# Registered after every API route so explicit routes win; the mount catches everything else
# and serves ../ui/index.html at "/" (html=True).
if UI_DIR.is_dir():
    app.mount("/", StaticFiles(directory=str(UI_DIR), html=True), name="ui")
else:
    @app.get("/")
    async def _no_ui() -> Dict[str, Any]:
        return {"ok": True, "service": "wifi-command-center",
                "note": "UI folder not found at " + str(UI_DIR) + "; API is up. See /health, /actions."}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host=os.environ.get("WIFI_BIND", "127.0.0.1"),
                port=int(os.environ.get("WIFI_PORT", "8787")), reload=False)
