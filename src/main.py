from fastapi import FastAPI
from pydantic import BaseModel
from src.scanner import scan_code

app = FastAPI(title="Security Scanner API")

class ScanRequest(BaseModel):
    code: str

@app.post("/scan")
def scan(req: ScanRequest):
    findings = scan_code(req.code)
    return {
        "total": len(findings),
        "findings": [
            {"severity": f.severity, "rule": f.rule, "line": f.line, "match": f.match}
            for f in findings
        ]
    }

@app.get("/health")
def health():
    return {"status": "ok"}
