"""FastAPI entrypoint for PhishTriage backend.

Configured with open CORS policy to allow seamless Chrome Extension Side Panel
and content script communication.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.routes import router as api_router

app = FastAPI(
    title="PhishTriage API",
    description="Multi-Agent Phishing Triage Engine Backend & API Service",
    version="0.1.0",
)

# Open CORS configuration for Chrome Extension, side panels, and local tooling
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount core API router
app.include_router(api_router)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)

