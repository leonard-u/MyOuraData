from fastapi import FastAPI, BackgroundTasks, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.concurrency import run_in_threadpool
from backend.src.api.routes import router
from backend.src.database import init_db

import asyncio
import logging
from datetime import datetime, timedelta
from backend.src.automation import automator
from backend.src.ingestion import OuraParser
from backend.src.database import SessionLocal
from backend.src.config import config_manager
import os
from pydantic import BaseModel

from contextlib import asynccontextmanager

# Configure logging
from backend.src.paths import get_user_data_dir
import logging
import os

log_dir = get_user_data_dir()
log_file = os.path.join(log_dir, "backend_debug.log")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("API")
logger.info(f"API Starting... Logging to {log_file}")

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    init_db()
    
    # Reset status on startup in case it was stuck
    cfg = config_manager.get_config()
    if cfg.get("status") not in ["Idle", "Error"]:
        logger.info("Startup: Resetting stuck status to Idle.")
        config_manager.update_status("Idle")
        
    # Start background worker
    task = asyncio.create_task(background_worker())
    
    yield
    
    # Shutdown (optional cleanup)
    # task.cancel()

app = FastAPI(
    title="Cracked Oura API",
    description="API for accessing Oura Ring data stored in local SQLite database.",
    version="0.1.0",
    lifespan=lifespan
)

# -----------------------------------------------------------------------------
# Access control
#
# The API has no login and serves health data, so it must not be callable by
# arbitrary web pages the user happens to have open. Three layers:
#   1. TrustedHostMiddleware rejects requests whose Host header is not ours,
#      which defeats DNS-rebinding attacks against localhost.
#   2. origin_guard rejects any request that carries a foreign Origin header.
#      Browsers attach Origin to every cross-site POST and every cross-origin
#      fetch, so this blocks both data reads and CSRF-style writes.
#   3. The packaged Electron app loads from file:// (Origin "null"/"file://"),
#      which a sandboxed iframe on any site can also send. Electron therefore
#      passes a random per-launch token (CRACKED_OURA_API_TOKEN) that its main
#      process attaches to every request; "null" origins are only accepted
#      together with that token.
# -----------------------------------------------------------------------------
from fastapi.responses import JSONResponse
from starlette.middleware.trustedhost import TrustedHostMiddleware
import hmac


def _env_list(name: str, default: str) -> list:
    return [item.strip() for item in os.getenv(name, default).split(",") if item.strip()]


ALLOWED_ORIGINS = _env_list(
    "CRACKED_OURA_ALLOWED_ORIGINS",
    "http://localhost:5173,http://127.0.0.1:5173",  # Vite dev server
)
ALLOWED_HOSTS = _env_list("CRACKED_OURA_ALLOWED_HOSTS", "localhost,127.0.0.1")
API_TOKEN = os.getenv("CRACKED_OURA_API_TOKEN", "")
TOKEN_HEADER = "x-cracked-oura-token"
_OPAQUE_ORIGINS = {"null", "file://"}


def _has_valid_token(request: Request) -> bool:
    supplied = request.headers.get(TOKEN_HEADER, "")
    return bool(API_TOKEN) and hmac.compare_digest(supplied, API_TOKEN)


def _is_same_origin(request: Request, origin: str) -> bool:
    host = request.headers.get("host", "")
    return origin in (f"http://{host}", f"https://{host}")


@app.middleware("http")
async def origin_guard(request: Request, call_next):
    # Preflights carry no data and are answered by CORSMiddleware.
    if request.method == "OPTIONS":
        return await call_next(request)

    origin = request.headers.get("origin")
    allowed = (
        origin is None                       # same-origin GET, curl, healthcheck
        or origin in ALLOWED_ORIGINS
        or _is_same_origin(request, origin)  # Docker/web UI served by this app
        or (origin in _OPAQUE_ORIGINS and _has_valid_token(request))  # Electron
    )
    if not allowed:
        logger.warning(f"Blocked request from origin {origin!r} to {request.url.path}")
        return JSONResponse({"detail": "Origin not allowed"}, status_code=403)
    return await call_next(request)


# Opaque origins are listed for CORS only when a token is configured; the
# guard above still requires the token on every actual request from them.
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS + (sorted(_OPAQUE_ORIGINS) if API_TOKEN else []),
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=ALLOWED_HOSTS)

# Include routers
app.include_router(router)

# --- API Models for Automation ---
class AutomationConfig(BaseModel):
    email: str
    schedule_time: str
    is_active: bool
    headless: bool = True

# --- Endpoints ---

@app.get("/api/automation/status")
async def get_automation_status():
    """Returns the current automation configuration and status."""
    return config_manager.get_config()

@app.post("/api/automation/config")
async def update_automation_config(config: AutomationConfig):
    """Updates automation settings."""
    config_manager.update_config(
        email=config.email, 
        schedule_time=config.schedule_time,
        is_active=config.is_active,
        headless=config.headless
    )
    # Configure automator with new email settings immediately
    automator.email = config.email
        
    return {"status": "success", "message": "Configuration updated."}

class OTPRequest(BaseModel):
    otp: str
    action: str = "run" # run, download, test

@app.post("/api/automation/submit-otp")
async def submit_otp(request: OTPRequest, background_tasks: BackgroundTasks):
    """
    Submits OTP code to the running automation session.
    """
    logger.info(f"Received OTP submission. Action: {request.action}")
    config_manager.update_status("Submitting OTP...")
    
    try:
        result = await automator.submit_otp(request.otp)
        if result["status"] == "success":
            if request.action == "run":
                config_manager.update_status("Login Successful! Resuming Full Run...")
                background_tasks.add_task(run_ingestion_task, force=True)
                return {"status": "success", "message": "OTP Accepted. Resuming full automation."}
            
            elif request.action == "download":
                config_manager.update_status("Login Successful! Resuming Download...")
                background_tasks.add_task(run_download_existing_task)
                return {"status": "success", "message": "OTP Accepted. Resuming download."}
            
            elif request.action == "test":
                config_manager.update_status("Login Successful! Session saved.")
                await automator.cleanup()
                return {"status": "success", "message": "OTP Accepted. Login verified."}
            
            else:
                # Default fallback
                config_manager.update_status("Login Successful!")
                return {"status": "success", "message": "OTP Accepted."}

        else:
            config_manager.update_status(f"OTP Error: {result['message']}")
            return {"status": "error", "message": result['message']}
    except Exception as e:
        config_manager.update_status(f"OTP Error: {str(e)}")
        return {"status": "error", "message": str(e)}

@app.post("/api/automation/run-now")
async def run_automation(background_tasks: BackgroundTasks):
    """
    Manually triggers the full "Request New + Download" flow.
    """
    logger.info("Manual automation trigger received.")
    config_manager.update_status("Starting manual run...")
    
    try:
        # Initialize if needed
        cfg = config_manager.get_config()
        await automator.initialize(headless=cfg.get("headless", False))
        automator.email = cfg.get("email", "")

        background_tasks.add_task(run_ingestion_task, force=True)
        return {"status": "started", "message": "Automation started."}

    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.post("/api/automation/clear-session")
async def clear_session():
    """Clears the current automation session."""
    try:
        if await automator.clear_session():
            config_manager.update_status("Session cleared.")
            return {"status": "success", "message": "Session cleared. Please login again."}
        return {"status": "info", "message": "No session found to clear."}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.post("/api/automation/test-login")
async def test_login():
    """Tests the login functionality with current credentials."""
    try:
        config_manager.update_status("Testing Login...")
        cfg = config_manager.get_config()
        await automator.initialize(headless=cfg.get("headless", False))
        automator.email = cfg.get("email", "")
        res = await automator.login()
        if res and res.get("status") == "otp_required":
             config_manager.update_status("Waiting for OTP...")
             return {"status": "otp_required", "message": "OTP Required"}
        
        config_manager.update_status("Login Check Complete.")
        await automator.cleanup() # Close browser if successful
        return res
    except Exception as e:
        config_manager.update_status(f"Login Error: {str(e)}")
        return {"status": "error", "message": str(e)}

async def run_download_existing_task():
    """
    Standalone task for downloading existing export.
    """
    logger.info("Starting download existing task...")
    try:
        cfg = config_manager.get_config()
        # Ensure automator is initialized and configured
        if not automator._is_initialized:
            await automator.initialize(headless=cfg.get("headless", True))
        
        automator.email = cfg.get("email", "")
        
        # Use user data dir for downloads
        from backend.src.paths import get_user_data_dir
        save_dir = str(get_user_data_dir())
        
        result = await automator.download_existing_export(save_dir=save_dir)
        
        if isinstance(result, dict) and result.get("status") == "otp_required":
            config_manager.update_status("Waiting for OTP...")
            return

        file_path = result
        
        if file_path:
            logger.info(f"Export downloaded to {file_path}. Starting ingestion...")
            await process_ingestion(file_path)
        else:
            logger.info("No existing export found.")
        
        # Cleanup on success (if not waiting for OTP)
        await automator.cleanup()

    except Exception as e:
        logger.error(f"Download task failed: {e}")
        await automator.cleanup() # Cleanup on error


@app.post("/api/automation/download-latest")
async def download_latest_existing(background_tasks: BackgroundTasks):
    """Downloads the latest EXISTING export (if any). Does NOT request new."""
    background_tasks.add_task(run_download_existing_task)
    return {"status": "started", "message": "Checking for existing downloads..."}


# --- Background Logic ---

async def run_ingestion_task(force=False):
    """
    The core logic for checking, requesting, and downloading data.
    """
    cfg = config_manager.get_config()
    if not force and not cfg.get("is_active", True):
        return

    logger.info("Background worker: Starting ingestion task...")
    config_manager.update_status("Starting...")
    
    try:
        # 1. Initialize
        config_manager.update_status("Initializing...")
        headless_mode = cfg.get("headless", True)
        await automator.initialize(headless=headless_mode)
        
        # Configure credentials
        automator.email = cfg.get("email", "")
        
        # Check login first
        login_res = await automator.login()
        if login_res and login_res.get("status") == "otp_required":
             logger.info("Background worker: OTP Required.")
             config_manager.update_status("Waiting for OTP...")
             return
        
        # 2. Run Full Automation (Request -> Wait -> Download)
        config_manager.update_status("Running Automation...")
        
        # Use user data dir for downloads
        from backend.src.paths import get_user_data_dir
        save_dir = str(get_user_data_dir())

        # This function handles login, requesting, waiting, and downloading
        result = await automator.request_new_export_and_download(save_dir=save_dir)
        
        if isinstance(result, dict) and result.get("status") == "otp_required":
             config_manager.update_status("Waiting for OTP...")
             return

        file_path = result
        
        if file_path:
            logger.info(f"Background worker status: Downloaded to {file_path}")
            config_manager.update_status("Downloading...")
            
            # 3. Ingest
            await process_ingestion(file_path)
        else:
            logger.info("Background worker: No file downloaded (Timeout or Error).")
            config_manager.update_status("Failed to download export.")
        
        # Cleanup on success
        await automator.cleanup()

    except Exception as e:
        logger.error(f"Background worker error: {e}")
        config_manager.update_status(f"Error: {str(e)}")
        await automator.cleanup() # Cleanup on error

async def process_ingestion(zip_path):
    logger.info(f"Background worker: Downloaded to {zip_path}")
    
    # Ingest
    config_manager.update_status("Ingesting...")
    db = SessionLocal()
    try:
        parser = OuraParser(db)
        # Parsing is CPU/disk bound; keep it off the event loop.
        await run_in_threadpool(parser.parse_zip, zip_path)
        logger.info("Background worker: Ingestion successful.")
        
        # Success!
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        config_manager.update_status("Idle", last_run=now_str)
        
    except Exception as e:
        logger.error(f"Background worker: Ingestion failed: {e}")
        config_manager.update_status(f"Ingestion Failed: {str(e)}")
    finally:
        db.close()


async def background_worker():
    logger.info("Background worker started.")
    while True:
        try:
            # Check every minute if it's time to run
            now = datetime.now()
            cfg = config_manager.get_config()
            
            # Calculate next run time for display
            schedule_time_str = cfg.get("schedule_time", "11:00")
            try:
                sh, sm = map(int, schedule_time_str.split(":"))
                run_today = now.replace(hour=sh, minute=sm, second=0, microsecond=0)
                if now > run_today:
                    next_run = run_today + timedelta(days=1)
                else:
                    next_run = run_today
                
                config_manager.update_status(cfg.get("status", "Idle"), next_run=next_run.strftime("%Y-%m-%d %H:%M:%S"))

                if now.hour == sh and now.minute == sm:
                     await run_ingestion_task()
                
                # If in "Waiting" state, poll every 5 minutes            
                elif "Waiting" in cfg.get("status", ""):
                    if now.minute % 5 == 0:
                        logger.info("Background worker: Polling for export status...")
                        await run_ingestion_task()
                     
            except Exception as e:
                logger.error(f"Scheduler error: {e}")

            # Sleep 60 seconds
            await asyncio.sleep(60)
                    
        except Exception as e:
            logger.error(f"Background worker loop error: {e}")
            await asyncio.sleep(60)

# Mount Static Files
from fastapi.staticfiles import StaticFiles
import os

# Robustly find the frontend/dist directory (env override or relative path)
current_dir = os.path.dirname(os.path.abspath(__file__))
dist_dir = os.getenv("FRONTEND_DIST_DIR") or os.path.join(current_dir, "../../../frontend/dist")

if os.path.exists(dist_dir):
    logger.info(f"Mounting frontend static files from {dist_dir}")
    app.mount("/", StaticFiles(directory=dist_dir, html=True), name="static")
else:
    logger.warning(f"Frontend dist directory not found at {dist_dir}; API-only mode.")


if __name__ == "__main__":
    import uvicorn
    import sys
    
    # Check if running as a PyInstaller bundle
    if getattr(sys, 'frozen', False):
        try:
            # Production (Frozen)
            uvicorn.run(app, host="127.0.0.1", port=8000, reload=False)
        except Exception as e:
            # Emergency logging if startup fails
            from backend.src.paths import get_user_data_dir
            import os
            import traceback
            
            try:
                log_path = os.path.join(get_user_data_dir(), "startup_crash.log")
                with open(log_path, "w", encoding="utf-8") as f:
                    f.write(f"Startup Crash: {e}\n")
                    f.write(traceback.format_exc())
            except:
                pass # Failed to write log
            raise e
    else:
        # Development
        # Run the server with auto-reload
        # Bind to loopback only: the API has no authentication.
        uvicorn.run("backend.src.api.main:app", host="127.0.0.1", port=8000, reload=True, reload_dirs=["backend"])
