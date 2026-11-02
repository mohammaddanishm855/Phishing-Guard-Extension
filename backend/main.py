
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from engine.detection import analyze_url, analyze_email_phishing

app = FastAPI(
    title="Phishing Guard API",
    description="AI-powered browser security backend",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


class URLRequest(BaseModel):
    url: str


class EmailRequest(BaseModel):
    email_content: str


@app.get("/")
def home():
    return {"message": "Phishing Guard API is running"}


@app.get("/health")
def health():
    return {"status": "healthy"}


@app.post("/scan/url")
def scan_url(request: URLRequest):
    return analyze_url(request.url)


@app.post("/scan/email")
def scan_email(request: EmailRequest):
    return analyze_email_phishing(request.email_content)
