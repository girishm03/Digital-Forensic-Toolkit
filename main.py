import os
import uvicorn
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from aegis_forensics.api.routes import router as api_router

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "aegis_forensics", "web", "static")
TEMPLATES_DIR = os.path.join(BASE_DIR, "aegis_forensics", "web", "templates")

app = FastAPI(
    title="Aegis Digital Forensics & Incident Response Toolkit",
    description="Full-stack defensive digital forensics suite with artifact triage, live host analysis, PCAP inspection, and evidence chain of custody.",
    version="1.0.0"
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static and templates
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
templates = Jinja2Templates(directory=TEMPLATES_DIR)

# Mount API
app.include_router(api_router, prefix="/api")

@app.get("/")
async def root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

if __name__ == "__main__":
    print("[*] Starting Aegis Forensics Command Center at http://127.0.0.1:8080")
    uvicorn.run("main:app", host="127.0.0.1", port=8080, reload=True)
