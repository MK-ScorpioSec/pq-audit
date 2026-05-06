# pq-audit

**Post-Quantum Holistic Security Audit**

[![License](https://img.shields.io/badge/License-Apache_2.0-D62828?style=flat-square)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![Security Scan](https://github.com/mk-scorpiosec/pq-audit/actions/workflows/security-scan.yml/badge.svg)](https://github.com/mk-scorpiosec/pq-audit/actions/workflows/security-scan.yml)

A multi-layer security audit framework that evaluates cryptographic posture, infrastructure configuration, and code against NIST PQC standards (FIPS 203/204/205) — from today's broken algorithms to post-quantum readiness.

*I don't hunt threats. I am the threat.*

---

## Overview

`pq-audit` examines your stack across 9 layers and classifies findings into three risk tiers:

| Risk | Meaning |
|------|---------|
| `BROKEN_NOW` | Cryptography broken today (TLS 1.0/1.1, MD5, SHA-1, weak RSA) — fix immediately |
| `SNDL_VULNERABLE` | Secure Now, Decrypt Later — data safe today but harvestable for future quantum decryption |
| `PQC_READY` | Already using quantum-resistant primitives |

### Audit Layers

| Layer | What It Checks |
|-------|---------------|
| `code` | Python source — cipher imports, key sizes, hash functions, TLS config |
| `cloud` | IaC (Terraform/CloudFormation) — encryption flags, TLS policy, key management |
| `deps` | `requirements.txt`, `pyproject.toml` — cryptographic library versions |
| `config` | `nginx.conf`, `apache2.conf`, `sshd_config`, `openssl.cnf` — protocol/cipher suites |
| `certs` | X.509 certificates — algorithm, key size, validity, SAN coverage |
| `network` | Live TLS handshake — negotiated protocol, cipher, HSTS, OCSP |
| `containers` | Dockerfile, docker-compose — base image crypto, env var leaks |
| `api` | REST/gRPC endpoint responses — TLS version, header security, auth schemes |
| `compliance` | Cross-layer gap analysis against NIST SP 800-131A, DORA, NIS2 |

---

## Installation

> Coming soon — package will be available via `pip install pq-audit`

```bash
# From source
git clone https://github.com/mk-scorpiosec/pq-audit.git
cd pq-audit
pip install -r requirements.txt
```

---

## Usage

```bash
# Scan Python source code
python pq_audit.py --layer code --target ./src

# Scan Terraform IaC
python pq_audit.py --layer cloud --target ./terraform

# Scan TLS configuration files
python pq_audit.py --layer config --target /etc/nginx

# Full audit (all layers)
python pq_audit.py --layer all --target . --output report.json

# CI mode — exit 1 on BROKEN_NOW findings
python pq_audit.py --layer code --target . --ci --fail-on BROKEN_NOW
```

---

## Output

```json
{
  "summary": {
    "target": "./terraform/aws",
    "layer": "cloud",
    "by_risk": {
      "BROKEN_NOW": 1,
      "SNDL_VULNERABLE": 1,
      "PQC_READY": 0
    }
  },
  "findings": [
    {
      "file": "app_service.tf",
      "line": 29,
      "risk": "BROKEN_NOW",
      "finding": "Minimum TLS version set to 1.0 — broken protocol",
      "mitre": "T1040",
      "remediation": "Set minimum_tls_version = \"1.2\" or \"1.3\""
    }
  ]
}
```

---

## Research

This tool was used in live IaC security research against [TerraGoat](https://github.com/bridgecrewio/terragoat) (Bridgecrew's deliberately vulnerable Terraform repo). Results published in [mk-scorpiosec/research](https://github.com/mk-scorpiosec/research).

Key finding from the research: `app_service.tf:29` — Azure minimum TLS 1.0/1.1 — classified as `BROKEN_NOW` by pq-audit but missed by Trivy and Checkov's standard severity tiers, as they lack a quantum/cryptographic readiness dimension.

---

## NIST Alignment

| Standard | Coverage |
|----------|---------|
| NIST FIPS 203 (ML-KEM / Kyber) | Key encapsulation readiness check |
| NIST FIPS 204 (ML-DSA / Dilithium) | Digital signature algorithm audit |
| NIST FIPS 205 (SLH-DSA / SPHINCS+) | Hash-based signature detection |
| NIST SP 800-131A | Deprecated algorithm identification |
| DORA / NIS2 | Cryptographic control gap analysis |

---

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

---

## License

Apache 2.0 — see [LICENSE](LICENSE).

---

<div align="center">
<sub>MK ScorpioSec — AI-Native Security Operations</sub>
</div>
