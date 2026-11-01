#!/usr/bin/env python3
"""
pq_audit_triage.py — FP triage for pq-audit findings using RAG + CVE context
MK ScorpioSec | 2026-06-04

Uses Qdrant RAG (optional) to validate if a finding is:
- TRUE POSITIVE: pattern confirmed by CVE/NIST/vendor docs in RAG
- NEEDS REVIEW: pattern found but no corroborating evidence in RAG
- LIKELY FP: pattern matches but context indicates it's intentional/test

Usage:
  python3 pq_audit_triage.py --input findings.json --output triage_report.json
  python3 pq_audit_triage.py --findings-dir /tmp/pq_results/ --rag-validate
  python3 pq_audit_triage.py --input findings.json --compare trivy_report.json
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
DEFAULT_FP_THRESHOLD = 2

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

# Keywords used to pick the crypto-relevant subset out of a generic
# vulnerability scanner report (Trivy) when building the gap matrix
CRYPTO_KEYWORDS = [
    "crypto", "tls", "ssl", "openssl", "libssl", "gnutls", "rsa", "dsa",
    "ecdsa", "ecdh", "cipher", "certificate", "x509", "bouncycastle",
    "libssh", "sha1", "md5", "des", "rc4", "kyber", "dilithium", "sphincs",
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


def rag_lookup(query: str, collection: str = "pq_audit_kb", limit: int = 3) -> list[dict]:
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


def triage_finding(finding: dict, context_path: str = "", fp_threshold: int = DEFAULT_FP_THRESHOLD) -> dict:
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
    if fp_score >= fp_threshold and tp_score == 0:
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


def load_trivy_findings(path: str) -> list[dict]:
    """
    Parse a Trivy JSON report (`trivy ... --format json`) into a flat list of
    {id, pkg, severity, title} dicts, one per vulnerability.
    """
    try:
        data = json.loads(Path(path).read_text())
    except Exception as e:
        print(f"[!] Could not read Trivy report {path}: {e}", file=sys.stderr)
        return []

    flat = []
    for result in data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []) or []:
            flat.append({
                "id": vuln.get("VulnerabilityID", "?"),
                "pkg": vuln.get("PkgName", "?"),
                "severity": vuln.get("Severity", "UNKNOWN"),
                "title": vuln.get("Title") or vuln.get("Description", "")[:80],
            })
    return flat


def build_gap_matrix(pq_findings: list[dict], trivy_findings: list[dict]) -> dict:
    """
    Compare pq-audit findings against a Trivy report, restricted to the
    crypto-relevant subset of Trivy's output (CRYPTO_KEYWORDS), to spot:
      - overlap: crypto CVEs Trivy found that pq-audit's rules already cover
      - trivy_only: crypto CVEs Trivy found with no matching pq-audit finding
        (candidate patterns to add to pq_audit.py)
    """
    def is_crypto_related(v: dict) -> bool:
        haystack = f"{v['pkg']} {v['title']}".lower()
        return any(kw in haystack for kw in CRYPTO_KEYWORDS)

    crypto_vulns = [v for v in trivy_findings if is_crypto_related(v)]
    pq_text = " ".join(f.get("description", "") for f in pq_findings).lower()

    overlap, trivy_only = [], []
    for v in crypto_vulns:
        matched = v["pkg"].lower() in pq_text or v["id"].lower() in pq_text
        (overlap if matched else trivy_only).append(v)

    return {
        "trivy_total_findings": len(trivy_findings),
        "trivy_crypto_related": len(crypto_vulns),
        "overlap_with_pq_audit": len(overlap),
        "gap_candidates": trivy_only,
    }


def main():
    parser = argparse.ArgumentParser(description="pq-audit FP triage via RAG")
    parser.add_argument("--input", help="pq-audit JSON output file")
    parser.add_argument("--output", default="triage_report.json", help="Output file")
    parser.add_argument("--context", default="", help="Context path (prod/test/demo)")
    parser.add_argument("--fp-threshold", type=int, default=DEFAULT_FP_THRESHOLD,
                         help=f"Min FP indicator matches to flag LIKELY_FP (default: {DEFAULT_FP_THRESHOLD})")
    parser.add_argument("--compare", default=None,
                         help="Trivy JSON report to build a crypto-findings gap matrix against")
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
        result = triage_finding(f, context_path=args.context or f.get("file", ""),
                                 fp_threshold=args.fp_threshold)
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
        "fp_threshold": args.fp_threshold,
        "summary": {"true_positive": tp, "needs_review": nr, "likely_fp": fp},
        "fp_rate_estimate": f"{fp/(len(triaged) or 1)*100:.0f}%",
        "triaged_findings": triaged,
    }

    if args.compare:
        trivy_findings = load_trivy_findings(args.compare)
        gap_matrix = build_gap_matrix(real_findings, trivy_findings)
        report["gap_matrix"] = gap_matrix
        print(f"[triage] Gap matrix vs {args.compare}: "
              f"{gap_matrix['trivy_crypto_related']} crypto CVEs in Trivy, "
              f"{gap_matrix['overlap_with_pq_audit']} already covered by pq-audit, "
              f"{len(gap_matrix['gap_candidates'])} gap candidate(s)")

    Path(args.output).write_text(json.dumps(report, indent=2))
    print(f"[triage] Report saved: {args.output}")


if __name__ == "__main__":
    main()
