from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
import re
from app.auth import init_db, authenticate_user, get_all_users
import httpx
from typing import List
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Initialize the SQLite DB and mock users
    init_db()
    yield
    # Shutdown logic (if any) could go here

app = FastAPI(lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class LoginRequest(BaseModel):
    username: str
    password: str


class AnalyzeRequest(BaseModel):
    code: str

@app.post("/login")
async def login(req: LoginRequest):
    user = authenticate_user(req.username, req.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid username or password")
    return user

@app.get("/users")
async def get_users():
    # In a real app, protect this route so only admins can call it
    return get_all_users()

class IOCItem(BaseModel):
    value: str
    kind: str

class EnrichRequest(BaseModel):
    iocs: List[IOCItem]

@app.post("/enrich")
async def enrich_iocs(req: EnrichRequest):
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post("http://localhost:8081/enrich", json=req.model_dump())
            response.raise_for_status()
            return response.json()
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Go Microservice Error: {str(e)}")

@app.post("/analyze")
async def analyze_code(req: AnalyzeRequest):
    findings = []
    iocs = []
    
    # Split the code into lines
    lines = req.code.split('\n')
    
    # Expanded regex patterns for all 10 vulnerability scenarios
    patterns = {
        "aws_key": {
            "regex": r"(AKIA[0-9A-Z]{16}|AKIA_[A-Z_]+_KEY)",
            "type": "hardcoded_secret",
            "severity": "critical",
            "message": "Found hardcoded AWS Access Key"
        },
        "password": {
            "regex": r"(?i)password\s*=\s*[\"']([^\"']+)[\"']",
            "type": "hardcoded_secret",
            "severity": "critical",
            "message": "Found hardcoded password"
        },
        "sqli": {
            "regex": r"(?i)(SELECT\s+.*?\s+FROM\s+.*?|UNION\s+ALL\s+SELECT|INSERT\s+INTO\s+.*?\s+VALUES|DELETE\s+FROM\s+.*?\s+WHERE\s+.*?\$\{.*?\})",
            "type": "sql_injection",
            "severity": "critical",
            "message": "Potential SQL Injection pattern detected"
        },
        "eval": {
            "regex": r"(\beval\s*\()",
            "type": "dangerous_function",
            "severity": "critical",
            "message": "Use of dangerous function eval()"
        },
        "shell_injection": {
            "regex": r"(\b(?:os\.system|subprocess\.Popen|exec)\s*\()",
            "type": "shell_injection",
            "severity": "critical",
            "message": "Potential shell injection / command execution"
        },
        "open_port": {
            "regex": r"(\b0\.0\.0\.0\b)",
            "type": "risky_bind",
            "severity": "low",
            "message": "Risky bind to all interfaces (0.0.0.0)"
        },
        "xss": {
            "regex": r"(res\.send\s*\(\s*`|innerHTML\s*=\s*|document\.write\s*\()",
            "type": "xss",
            "severity": "high",
            "message": "Potential Cross-Site Scripting (XSS)"
        },
        "insecure_jwt": {
            "regex": r"(jwt\.decode\s*\()",
            "type": "insecure_jwt",
            "severity": "high",
            "message": "Insecure JWT usage: Use jwt.verify() instead of jwt.decode()"
        },
        "file_upload": {
            "regex": r"(move_uploaded_file\s*\()",
            "type": "file_upload",
            "severity": "high",
            "message": "Insecure file upload: move_uploaded_file detected"
        },
        "data_exposure": {
            "regex": r"(process\.env\.[A-Z_]+(?:_KEY|_SECRET|PASSWORD))",
            "type": "data_exposure",
            "severity": "high",
            "message": "Sensitive Data Exposure: Exposing environment secrets"
        },
        "prototype_pollution": {
            "regex": r"(__proto__|constructor\.prototype)",
            "type": "prototype_pollution",
            "severity": "high",
            "message": "Prototype Pollution risk detected"
        },
        "weak_password": {
            "regex": r"(\bpassword\b\s*:\s*\bpassword\b|\bpassword\b\s*:\s*req\.body\.password|users\.push\s*\(\s*\{\s*username,\s*password\s*\}\s*\))",
            "type": "weak_password",
            "severity": "medium",
            "message": "Weak Password Storage: Passwords should be hashed"
        },
        "ipv4": {
            "regex": r"(\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)",
            "type": "suspicious_ip",
            "severity": "medium",
            "message": "Found suspicious IP address"
        },
        "url": {
            "regex": r"(https?://[a-zA-Z0-9.-]+(?:/[a-zA-Z0-9&%_.-]*)*)",
            "type": "suspicious_url",
            "severity": "medium",
            "message": "Found embedded URL/Domain"
        },
        "hash": {
            "regex": r"(\b(?:[A-Fa-f0-9]{32}|[A-Fa-f0-9]{64})\b)",
            "type": "suspicious_hash",
            "severity": "medium",
            "message": "Found embedded MD5/SHA256 hash"
        }
    }
    
    seen_iocs = set()

    for line_num, line in enumerate(lines, start=1):
        for key, pattern_info in patterns.items():
            matches = re.finditer(pattern_info["regex"], line)
            for match in matches:
                artifact = match.group(1)
                findings.append({
                    "line": line_num,
                    "type": pattern_info["type"],
                    "severity": pattern_info["severity"],
                    "artifact": artifact,
                    "message": pattern_info["message"],
                    "startColumn": match.start(1) + 1,
                    "endColumn": match.end(1) + 1
                })
                
                # Add to IOCs if it's an extractable type
                if key in ["ipv4", "url", "hash"] and artifact not in seen_iocs:
                    is_valid = True
                    # Simple filtering for local IPs to avoid noise
                    if key == "ipv4" and (artifact.startswith("127.") or artifact.startswith("192.168.") or artifact.startswith("10.")):
                        is_valid = False
                    
                    if is_valid:
                        kind_map = {"ipv4": "ip", "url": "url", "hash": "hash"}
                        iocs.append({
                            "value": artifact,
                            "kind": kind_map[key]
                        })
                        seen_iocs.add(artifact)

    return {
        "findings": findings,
        "iocs": iocs
    }
