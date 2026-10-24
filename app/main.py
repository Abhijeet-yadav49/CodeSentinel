from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from app.analyzer import RULES, analyze_source

BASE_DIR = Path(__file__).resolve().parent
MAX_SOURCE_CHARS = 200_000

app = FastAPI(
    title="CodeSentinel API",
    description="Deterministic AST-based static analysis for Python source code.",
    version="0.1.0",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")


class AnalyzeRequest(BaseModel):
    code: str = Field(..., description="Python source code to analyze", max_length=MAX_SOURCE_CHARS)


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def home() -> str:
    return (BASE_DIR / "static" / "index.html").read_text(encoding="utf-8")


@app.get("/health", include_in_schema=False)
def health() -> dict[str, str]:
    return {"status": "ok", "service": "codesentinel", "version": "0.1.0"}


@app.get("/api/rules", include_in_schema=False)
def rules() -> dict:
    return {"count": len(RULES), "rules": RULES}


@app.post("/api/analyze", include_in_schema=False)
def analyze(request: AnalyzeRequest) -> dict:
    if not request.code.strip():
        raise HTTPException(status_code=422, detail="Provide non-empty Python source code.")
    try:
        return analyze_source(request.code)
    except Exception as exc:  # Defensive API boundary; no source is executed.
        raise HTTPException(status_code=500, detail="Analysis failed unexpectedly.") from exc
