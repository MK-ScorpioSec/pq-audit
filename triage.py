#!/usr/bin/env python3
"""
pq_audit_triage.py — FP triage for pq-audit findings using RAG + CVE context
MK ScorpioSec | 2026-06-04

Uses Qdrant RAG (threat_intel_kb) to validate if a finding is:
- TRUE POSITIVE: pattern confirmed by CVE/NIST/vendor docs in RAG
- NEEDS REVIEW: pattern found but no corroborating evidence in RAG
- LIKELY FP: pattern matches but context indicates it's intentional/test

Usage:
  python3 pq_audit_triage.py --input findings.json --output triage_report.json
  python3 pq_audit_triage.py --findings-dir /tmp/pq_results/ --rag-validate
"""

import json
import os
import sys
import argparse
import urllib.request
from pathlib import Path

QDRANT_URL = os.environ.get("QDRANT_URL", "http://localhost:6333")
OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434")
EMBED_MODEL = os.environ.get("EMBED_MODEL", "nomic-embed-text")

# Patterns that are commonly FPs in test/demo environments
FP_INDICATORS = [
    "test", "demo", "example", "sample", "mock", "fake", "dummy",
    "localhost", "127.0.0.1", "placeholder", "template", "skeleton",
    "vulnerable", "intentionally", "juiceshop", "dvwa", "webgoat",
    "terragoat", "broken-by-design", "lab",
]

# Patterns that validate TRUE positives (production signals)
TP_INDICATORS = [
    "production", "prod", "main", "master", "release", "stable",
    "aws", "azure", "gcp", "cloud", "enterprise", "corp",
]


def embed_text(text: str) -> list[float]:
    """Get embedding from Ollama nomic-embed-text."""
    payload = json.dumps({"model": EMBED_MODEL, "prompt": text[:500]}).encode()
    req = urllib.request.Request(f"{OLLAMA_URL}/api/embeddings",
                                 data=payload, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read()).get("embedding", [])
    except Exception:
        return []


def rag_lookup(query: str, collection: str = "threat_intel_kb", limit: int = 3) -> list[dict]:
    """Semantic search in Qdrant for corroborating evidence."""
    vector = embed_text(query)
    if not vector:
        return []
    payload = json.dumps({"vector": vector, "limit": limit, "with_payload": True}).encode()
    req = urllib.request.Request(
        f"{QDRANT_URL}/collections/{collection}/points/search",
        data=payload, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=8) as r:
            return json.loads(r.read()).get("result", [])
    except Exception:
        return []


def triage_finding(finding: dict, context_path: str = "") -> dict:
    """
    Triage a single pq-audit finding.
    Returns: finding + verdict (TRUE_POSITIVE / NEEDS_REVIEW / LIKELY_FP) + evidence
    """
    risk = finding.get("risk", "UNKNOWN")
    description = finding.get("description", "")
    file_path = finding.get("file", context_path)
    
    # Check FP indicators in file path / context
    path_lower = file_path.lower()
    fp_score = sum(1 for i in FP_INDICATORS if i in path_lower)
    tp_score = sum(1 for i in TP_INDICATORS if i in path_lower)
    
    # RAG validation: search for corroborating evidence
    search_query = f"pq-audit {risk} {description} post-quantum crypto vulnerability"
    rag_results = rag_lookup(search_query)
    rag_score = len([r for r in rag_results if r.get("score", 0) > 0.62])
    
    # Verdict logic
    if fp_score >= 2 and tp_score == 0:
        verdict = "LIKELY_FP"
        reason = f"FP indicators in path ({fp_score}): test/demo/lab context"
    elif risk == "BROKEN_NOW" and rag_score > 0:
        verdict = "TRUE_POSITIVE"
        reason = f"BROKEN_NOW confirmed by RAG ({rag_score} corroborating sources)"
    elif risk in ("SNDL_VULNERABLE", "BROKEN_NOW") and tp_score > 0:
        verdict = "TRUE_POSITIVE"
        reason = f"Production context signals ({tp_score})"
    elif rag_score > 0:
        verdict = "TRUE_POSITIVE"
        reason = f"RAG validation: {rag_score} corroborating sources"
    else:
        verdict = "NEEDS_REVIEW"
        reason = "No corroborating evidence in RAG — manual review recommended"
    
    return {
        **finding,
        "triage_verdict": verdict,
        "triage_reason": reason,
        "fp_indicators_found": fp_score,
        "tp_indicators_found": tp_score,
        "rag_corroboration": rag_score,
        "rag_sources": [r.get("payload", {}).get("source", "?")[:40] for r in rag_results[:2]],
    }


def main():
    parser = argparse.ArgumentParser(description="pq-audit FP triage via RAG")
    parser.add_argument("--input", help="pq-audit JSON output file")
    parser.add_argument("--output", default="triage_report.json", help="Output file")
    parser.add_argument("--context", default="", help="Context path (prod/test/demo)")
    args = parser.parse_args()

    if not args.input:
        print("[!] Usage: pq_audit_triage.py --input findings.json", file=sys.stderr)
        sys.exit(1)

    data = json.loads(Path(args.input).read_text())
    findings = data.get("findings", [])
    real_findings = [f for f in findings if f.get("risk") and f.get("risk") != "INFO"]
    
    print(f"[triage] Processing {len(real_findings)} findings from {args.input}")
    
    triaged = []
    for f in real_findings:
        result = triage_finding(f, context_path=args.context or f.get("file", ""))
        triaged.append(result)
        verdict_icon = {"TRUE_POSITIVE": "🔴", "NEEDS_REVIEW": "🟡", "LIKELY_FP": "⚪"}.get(result["triage_verdict"], "?")
        print(f"  {verdict_icon} [{result['triage_verdict']}] {f.get('description','?')[:50]}")
    
    # Summary
    tp = len([f for f in triaged if f["triage_verdict"] == "TRUE_POSITIVE"])
    fp = len([f for f in triaged if f["triage_verdict"] == "LIKELY_FP"])
    nr = len([f for f in triaged if f["triage_verdict"] == "NEEDS_REVIEW"])
    
    print(f"\n[triage] Summary: {tp} TRUE_POSITIVE | {nr} NEEDS_REVIEW | {fp} LIKELY_FP")
    print(f"[triage] FP rate estimate: {fp/(len(triaged) or 1)*100:.0f}%")
    
    report = {
        "input": args.input,
        "total_findings": len(real_findings),
        "summary": {"true_positive": tp, "needs_review": nr, "likely_fp": fp},
        "fp_rate_estimate": f"{fp/(len(triaged) or 1)*100:.0f}%",
        "triaged_findings": triaged,
    }
    Path(args.output).write_text(json.dumps(report, indent=2))
    print(f"[triage] Report saved: {args.output}")


if __name__ == "__main__":
    main()
