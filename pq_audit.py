#!/usr/bin/env python3
"""
pq_audit.py — Post-Quantum Holistic Security Audit

Scope: cryptography + code + encryption + systems + dependencies + certificates.

Adaptive defense: not just isolated weak crypto detection, but end-to-end
robustness analysis against the post-quantum era (CRQC ~2030s).

Audit layers:
 1. CRYPTO   — cryptographic primitives in use (RSA/ECDSA/DH/hash/cipher)
 2. CODE     — source code using weak crypto (grep patterns in repos)
 3. SYSTEM   — SSH, TLS, PGP, x509 certs in infrastructure
 4. DEPS     — pip/npm/cargo deps with vulnerable crypto
 5. DOCKER   — images with weak crypto/binaries
 6. NETWORK  — weak protocols (FTP/Telnet/HTTP/SMBv1/LDAP/SNMPv1/etc)
 7. SOFTWARE — digital signatures in binaries/documents (.exe/.dll/.docm/.pdf)
 8. CLOUD    — IaC (Terraform/YAML/JSON) with weak crypto posture
 9. LINK     — phishing URLs + mail headers (SPF/DKIM/DMARC, DKIM-RSA-SHA1)
10. WEB3     — DeFi/blockchain off-chain components (ECDSA/secp256k1, JWT ES256K, CBOM)

Output: JSON report with PQC migration priority + incremental remediation plan.

Reference: CNSA 2.0 (US 2027 mandatory), NIST FIPS 203/204/205

Usage:
    python3 pq_audit.py --layer all --target /path/to/code
    python3 pq_audit.py --layer system --host example.com
    python3 pq_audit.py --layer deps --requirements requirements.txt
    python3 pq_audit.py --layer cert --file cert.pem
    python3 pq_audit.py --layer network --host 10.0.0.5
    python3 pq_audit.py --layer software --file sample.exe
    python3 pq_audit.py --layer cloud --target infra/terraform/
    python3 pq_audit.py --layer link --target https://suspicious.example
    python3 pq_audit.py --layer web3 --host defi-api.example.com
"""
import argparse
import json
import os
import re
import socket
import ssl
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


# ─── PQ Risk Levels ───────────────────────────────────────────────────────────
RISK_PQ = {
    "BROKEN_NOW": "Classically broken today (MD5/SHA-1/RSA<=1024). Fix immediately.",
    "SNDL_VULNERABLE": "Store-Now-Decrypt-Later: harvested today, decrypted with CRQC. High priority for long-lived data.",
    "TRANSITION_REQUIRED": "Secure today but vulnerable to CRQC ~2030s. Migrate medium-term.",
    "PQ_HYBRID_MISSING": "Uses NIST-safe algorithm but lacks hybrid PQC. Consider hybrid scheme.",
    "PQ_SAFE": "Post-Quantum safe (AES-256, SHA-384+, ML-KEM, ML-DSA, SPHINCS+).",
}


# ─── Layer 1: CRYPTO (primitives) ──────────────────────────────────────────────

CRYPTO_CATALOG = {
    # hashes
    "md5": {"risk": "BROKEN_NOW", "replace_with": "SHA-384/SHA-512 or SHA-3"},
    "sha1": {"risk": "BROKEN_NOW", "replace_with": "SHA-384/SHA-512 or SHA-3"},
    "sha256": {"risk": "PQ_SAFE", "note": "Acceptable. SHA-384/512 preferred for forensic long-lived hash chains."},
    "sha384": {"risk": "PQ_SAFE"},
    "sha512": {"risk": "PQ_SAFE"},
    "sha3": {"risk": "PQ_SAFE"},
    "blake3": {"risk": "PQ_SAFE"},
    # symmetric ciphers
    "des": {"risk": "BROKEN_NOW", "replace_with": "AES-256"},
    "3des": {"risk": "BROKEN_NOW", "replace_with": "AES-256"},
    "rc4": {"risk": "BROKEN_NOW", "replace_with": "ChaCha20-Poly1305"},
    "blowfish": {"risk": "BROKEN_NOW", "replace_with": "AES-256"},
    "aes-128": {"risk": "TRANSITION_REQUIRED", "note": "Grover reduces to 64-bit quantum security. Migrate to AES-256."},
    "aes-192": {"risk": "PQ_SAFE", "note": "96-bit quantum. Acceptable."},
    "aes-256": {"risk": "PQ_SAFE"},
    "chacha20": {"risk": "PQ_SAFE"},
    # asymmetric
    "rsa_1024": {"risk": "BROKEN_NOW"},
    "rsa_2048": {"risk": "SNDL_VULNERABLE", "replace_with": "Hybrid X25519+ML-KEM or migrate to pure ML-KEM"},
    "rsa_3072": {"risk": "SNDL_VULNERABLE", "note": "Better than 2048 but not PQ-safe"},
    "rsa_4096": {"risk": "SNDL_VULNERABLE"},
    "ecdsa_p256": {"risk": "SNDL_VULNERABLE"},
    "ecdsa_p384": {"risk": "SNDL_VULNERABLE"},
    "ecdsa_p521": {"risk": "SNDL_VULNERABLE"},
    "ecdsa_secp192": {"risk": "BROKEN_NOW"},
    "ecdsa_secp224": {"risk": "BROKEN_NOW"},
    "ed25519": {"risk": "SNDL_VULNERABLE", "note": "Classically secure. Migrate to hybrid Ed25519+ML-DSA"},
    "x25519": {"risk": "SNDL_VULNERABLE", "note": "Migrate to hybrid X25519+ML-KEM"},
    "dh_512": {"risk": "BROKEN_NOW"},
    "dh_768": {"risk": "BROKEN_NOW"},
    "dh_1024": {"risk": "SNDL_VULNERABLE"},
    "dh_2048": {"risk": "SNDL_VULNERABLE"},
    # PQ safe
    "ml_kem": {"risk": "PQ_SAFE", "note": "CRYSTALS-Kyber / FIPS-203"},
    "ml_dsa": {"risk": "PQ_SAFE", "note": "CRYSTALS-Dilithium / FIPS-204"},
    "slh_dsa": {"risk": "PQ_SAFE", "note": "SPHINCS+ / FIPS-205"},
}


# ─── Layer 2: CODE patterns ─────────────────────────────────────────────────────

CODE_PATTERNS = [
    # Weak hashes in code
    (r'hashlib\.md5\(', "Python hashlib.md5", "BROKEN_NOW"),
    (r'hashlib\.sha1\(', "Python hashlib.sha1", "BROKEN_NOW"),
    (r'MessageDigest\.getInstance\(["\']MD5', "Java MD5", "BROKEN_NOW"),
    (r'MessageDigest\.getInstance\(["\']SHA-?1', "Java SHA-1", "BROKEN_NOW"),
    (r'crypto\.createHash\(["\']md5', "NodeJS md5", "BROKEN_NOW"),
    (r'crypto\.createHash\(["\']sha1', "NodeJS sha1", "BROKEN_NOW"),
    # Weak ciphers in code
    (r'Cipher\.getInstance\(["\'](?:DES|DES/|DES_|Blowfish|RC4)', "Java weak cipher", "BROKEN_NOW"),
    (r'from Crypto\.Cipher import (?:DES|ARC4|Blowfish)', "PyCryptodome weak cipher", "BROKEN_NOW"),
    # Weak RSA in code
    (r'RSA\.generate\(\s*(?:512|768|1024|2048)', "Python RSA.generate<3072", "SNDL_VULNERABLE"),
    (r'keytool.*-keysize\s+(?:512|768|1024|2048)', "keytool RSA weak", "SNDL_VULNERABLE"),
    (r'openssl\s+genrsa\s+(?:512|768|1024|2048)', "openssl RSA weak", "SNDL_VULNERABLE"),
    # insecure random
    (r'\brandom\.random\(\)', "Python random.random (not cryptographic)", "BROKEN_NOW"),
    (r'\bMath\.random\(\)', "JS Math.random (not cryptographic)", "BROKEN_NOW"),
    # JWT alg none
    (r'"alg"\s*:\s*"none"', "JWT alg=none", "BROKEN_NOW"),
    # plaintext passwords
    (r'password\s*=\s*["\'][^"\']+["\']', "Password hardcoded", "BROKEN_NOW"),
    # weak TLS config
    (r'SSLv(?:2|3)|TLSv?1\.0|TLSv?1\.1', "Obsolete TLS version", "BROKEN_NOW"),
    (r'SSL_OP_NO_TLSv1_[23]', "TLS force downgrade", "BROKEN_NOW"),
]


def audit_crypto_primitives(text_or_file):
    """Layer 1: detect cryptographic primitives in use."""
    findings = []
    text = text_or_file if isinstance(text_or_file, str) else Path(text_or_file).read_text(errors="replace")
    text_lower = text.lower()
    for algo, meta in CRYPTO_CATALOG.items():
        if algo.replace("_", "-") in text_lower or algo in text_lower:
            findings.append({
                "layer": "CRYPTO",
                "algorithm": algo,
                "risk": meta["risk"],
                "description": RISK_PQ[meta["risk"]],
                "note": meta.get("note", ""),
                "replace_with": meta.get("replace_with", ""),
            })
    return findings


def audit_code(path):
    """Layer 2: recursive source code scan for weak crypto patterns."""
    p = Path(path)
    if not p.exists():
        return [{"error": f"Path not found: {path}"}]
    findings = []
    files = [p] if p.is_file() else list(p.rglob("*"))
    code_exts = {".py", ".js", ".ts", ".java", ".go", ".rb", ".php", ".cs", ".cpp", ".c", ".h", ".rs", ".sh"}

    for f in files:
        if not f.is_file():
            continue
        if f.suffix.lower() not in code_exts:
            continue
        if f.stat().st_size > 10_000_000:  # skip >10MB
            continue
        try:
            content = f.read_text(errors="replace")
        except Exception:
            continue
        for pattern, desc, risk in CODE_PATTERNS:
            for m in re.finditer(pattern, content):
                line_num = content[:m.start()].count("\n") + 1
                line_text = content.split("\n")[line_num - 1] if line_num <= content.count("\n") + 1 else ""
                if "pq-audit: noqa" in line_text:
                    continue
                findings.append({
                    "layer": "CODE",
                    "file": str(f),
                    "line": line_num,
                    "description": desc,
                    "risk": risk,
                    "match": m.group(0)[:100],
                })
    return findings


# ─── Layer 3: SYSTEM (TLS / SSH / PGP / certs) ─────────────────────────────────

def audit_tls(host, port=443):
    """Layer 3a: TLS/SSL configuration of a host."""
    findings = []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert(binary_form=True)
                cipher = ssock.cipher()
                version = ssock.version()

                # Version
                if version in ("TLSv1", "TLSv1.1", "SSLv3"):  # pq-audit: noqa — detection string, not usage
                    findings.append({
                        "layer": "SYSTEM", "sub": "TLS",
                        "host": f"{host}:{port}",
                        "description": f"TLS version obsoleta: {version}",
                        "risk": "BROKEN_NOW",
                    })
                elif version == "TLSv1.2":
                    findings.append({
                        "layer": "SYSTEM", "sub": "TLS",
                        "host": f"{host}:{port}",
                        "description": "TLS 1.2 aceptable pero 1.3 preferido",
                        "risk": "TRANSITION_REQUIRED",
                    })

                # Cipher
                if cipher:
                    cipher_name = cipher[0]
                    if any(weak in cipher_name.upper() for weak in ["RC4", "DES", "3DES", "MD5", "EXPORT", "NULL"]):
                        findings.append({
                            "layer": "SYSTEM", "sub": "TLS",
                            "host": f"{host}:{port}",
                            "description": f"Weak cipher: {cipher_name}",
                            "risk": "BROKEN_NOW",
                        })
                    # PQ hybrid?
                    if not any(pq in cipher_name.lower() for pq in ["kyber", "ml_kem", "mlkem"]):
                        findings.append({
                            "layer": "SYSTEM", "sub": "TLS",
                            "host": f"{host}:{port}",
                            "description": "TLS sin hybrid PQ (ML-KEM/Kyber)",
                            "risk": "SNDL_VULNERABLE",
                            "note": "Considerar TLS 1.3 + X25519Kyber768Draft00",
                        })
    except Exception as e:
        findings.append({
            "layer": "SYSTEM", "sub": "TLS",
            "host": f"{host}:{port}",
            "error": str(e),
        })
    return findings


def audit_ssh_config(host, port=22):
    """Layer 3b: SSH configuration (kex algorithms, host keys, ciphers)."""
    findings = []
    try:
        r = subprocess.run(
            ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
             "-o", "StrictHostKeyChecking=no",
             "-Q", "kex"],
            capture_output=True, text=True, timeout=15,
        )
        # Currently only tests if local ssh supports PQ. Ideally remote scan with ssh-audit.
        findings.append({
            "layer": "SYSTEM", "sub": "SSH",
            "host": f"{host}:{port}",
            "note": "Usar ssh-audit para analisis completo",
            "description": "SSH audit requires ssh-audit tool",
            "risk": "TRANSITION_REQUIRED",
        })
    except Exception as e:
        findings.append({"error": str(e)})
    return findings


def audit_x509_cert(cert_path):
    """Layer 3c: analyze x509 certificate."""
    findings = []
    try:
        # Usamos openssl para inspeccionar
        r = subprocess.run(
            ["openssl", "x509", "-in", cert_path, "-noout", "-text"],
            capture_output=True, text=True, timeout=15,
        )
        if r.returncode != 0:
            return [{"error": f"openssl failed: {r.stderr[:200]}"}]

        out = r.stdout
        # Algoritmo firma
        if "Signature Algorithm: md5" in out.lower():
            findings.append({
                "layer": "SYSTEM", "sub": "X509",
                "file": cert_path,
                "description": "Cert firmado con MD5",
                "risk": "BROKEN_NOW",
            })
        if "signature algorithm: sha1" in out.lower():
            findings.append({
                "layer": "SYSTEM", "sub": "X509",
                "file": cert_path,
                "description": "Cert firmado con SHA-1",
                "risk": "BROKEN_NOW",
            })
        # Key size RSA
        m = re.search(r"RSA Public-Key: \((\d+) bit", out)
        if m:
            bits = int(m.group(1))
            if bits < 2048:
                findings.append({
                    "layer": "SYSTEM", "sub": "X509",
                    "file": cert_path,
                    "description": f"RSA key {bits}-bit (broken)",
                    "risk": "BROKEN_NOW",
                })
            elif bits < 3072:
                findings.append({
                    "layer": "SYSTEM", "sub": "X509",
                    "file": cert_path,
                    "description": f"RSA key {bits}-bit (SNDL vulnerable)",
                    "risk": "SNDL_VULNERABLE",
                })
        # ECDSA curves
        if "secp192" in out.lower() or "secp224" in out.lower():
            findings.append({
                "layer": "SYSTEM", "sub": "X509",
                "file": cert_path,
                "description": "ECDSA con curva deprecada",
                "risk": "BROKEN_NOW",
            })

    except Exception as e:
        findings.append({"error": str(e)})
    return findings


# ─── Layer 4: DEPS ──────────────────────────────────────────────────────────────

WEAK_DEPS = {
    # Python
    "pycrypto": {"risk": "BROKEN_NOW", "note": "Abandonada 2014. Usar pycryptodome."},
    "rsa": {"risk": "TRANSITION_REQUIRED", "note": "Check version >= 4.0 y usar keys >= 3072"},
    "m2crypto": {"risk": "TRANSITION_REQUIRED", "note": "Mantenimiento limitado"},
    # Node
    "crypto-js": {"risk": "TRANSITION_REQUIRED", "note": "Usar Node crypto nativo"},
    "bcrypt@0": {"risk": "BROKEN_NOW", "note": "Old vulnerable version"},
    "md5": {"risk": "BROKEN_NOW"},
    "sha1": {"risk": "BROKEN_NOW"},
}


def audit_deps(requirements_path):
    """Layer 4: dependencies with vulnerable cryptography."""
    findings = []
    p = Path(requirements_path)
    if not p.exists():
        return [{"error": f"Path not found: {requirements_path}"}]

    content = p.read_text(errors="replace")
    for dep, meta in WEAK_DEPS.items():
        if re.search(rf"\b{re.escape(dep)}\b", content, re.IGNORECASE):
            findings.append({
                "layer": "DEPS",
                "file": str(p),
                "dependency": dep,
                "risk": meta["risk"],
                "note": meta.get("note", ""),
                "description": RISK_PQ[meta["risk"]],
            })
    return findings


# ─── Layer 5: NETWORK ───────────────────────────────────────────────────────────

NETWORK_WEAK_PROTOCOLS = {
    # Protocolos clasicamente rotos
    21: ("FTP", "BROKEN_NOW", "Plaintext credentials. Usar SFTP/FTPS."),
    23: ("Telnet", "BROKEN_NOW", "Plaintext everything. Usar SSH."),
    25: ("SMTP plain", "TRANSITION_REQUIRED", "Usar SMTP+STARTTLS (587) o SMTPS (465)."),
    53: ("DNS", "TRANSITION_REQUIRED", "Sin DNSSEC + sin DoT/DoH = spoofable. Considerar DoH/DoT."),
    69: ("TFTP", "BROKEN_NOW", "No encryption. Descartar."),
    79: ("Finger", "BROKEN_NOW", "User enumeration vector."),
    80: ("HTTP", "TRANSITION_REQUIRED", "Sin TLS. Usar HTTPS."),
    109: ("POP2", "BROKEN_NOW", "Obsoleto."),
    110: ("POP3 plain", "BROKEN_NOW", "Usar POP3S (995) o IMAPS."),
    111: ("RPCbind", "TRANSITION_REQUIRED", "Vector de reconocimiento / DDoS reflection."),
    135: ("RPC DCE", "TRANSITION_REQUIRED", "Exposicion innecesaria."),
    137: ("NetBIOS-NS", "BROKEN_NOW", "Poisoning (Responder)."),
    139: ("SMB v1/NetBIOS", "BROKEN_NOW", "SMBv1 prohibido (WannaCry/EternalBlue)."),
    143: ("IMAP plain", "BROKEN_NOW", "Usar IMAPS (993)."),
    161: ("SNMP v1/v2c", "BROKEN_NOW", "Community strings plaintext."),
    389: ("LDAP plain", "BROKEN_NOW", "Usar LDAPS (636)."),
    445: ("SMB", "TRANSITION_REQUIRED", "Verificar SMBv3 + signing. No exponer publico."),
    513: ("rlogin", "BROKEN_NOW", "Deprecated for 30+ years."),
    514: ("rshell", "BROKEN_NOW", "Deprecado."),
    1433: ("MSSQL", "TRANSITION_REQUIRED", "No exponer publico. Solo via VPN + TLS."),
    3306: ("MySQL", "TRANSITION_REQUIRED", "No exponer publico."),
    3389: ("RDP", "TRANSITION_REQUIRED", "Solo via VPN + NLA + MFA. NL3 (NTLM) deprecado."),
    5432: ("PostgreSQL", "TRANSITION_REQUIRED", "No exponer publico. Usar TLS."),
    5900: ("VNC", "BROKEN_NOW", "Weak authentication. Use over VPN."),
    6379: ("Redis plain", "BROKEN_NOW", "Sin auth por default, sin TLS."),
    9200: ("Elasticsearch", "BROKEN_NOW", "Sin auth historicamente. Verificar security plugin."),
    11211: ("Memcached", "BROKEN_NOW", "Sin auth. UDP amplification DDoS."),
    27017: ("MongoDB", "BROKEN_NOW", "Historicamente sin auth."),
}


def audit_network(host, ports=None, timeout=2):
    """Layer 5: scan for weak/exposed protocols."""
    findings = []
    target_ports = ports if ports else list(NETWORK_WEAK_PROTOCOLS.keys())

    for port in target_ports:
        try:
            with socket.create_connection((host, port), timeout=timeout) as s:
                service, risk, note = NETWORK_WEAK_PROTOCOLS.get(port, ("Unknown", "TRANSITION_REQUIRED", ""))
                findings.append({
                    "layer": "NETWORK",
                    "host": host,
                    "port": port,
                    "service": service,
                    "risk": risk,
                    "description": f"{service} exposed on {host}:{port}",
                    "note": note,
                })
        except (socket.timeout, ConnectionRefusedError, OSError):
            pass  # puerto cerrado — OK
        except Exception as e:
            findings.append({"error": str(e), "host": host, "port": port})

    # IPv6 check
    try:
        addrs = socket.getaddrinfo(host, None, socket.AF_INET6)
        if addrs:
            findings.append({
                "layer": "NETWORK",
                "host": host,
                "description": "IPv6 reachable - verify same hardening as IPv4",
                "risk": "TRANSITION_REQUIRED",
            })
    except Exception:
        pass

    # IKE/IPsec (VPN) PQ considerations
    # (placeholder — requires ike-scan)
    findings.append({
        "layer": "NETWORK",
        "host": host,
        "description": "VPN IKE PQ readiness check pendiente (IKEv2 + hybrid PQ KE)",
        "risk": "SNDL_VULNERABLE",
        "note": "RFC 9370 (IKEv2 PQ hybrid KE) for VPN migration",
    })

    return findings


# ─── Layer 6: SOFTWARE (documents, executables, files) ─────────────────────────

SUSPICIOUS_FILE_EXTS = {
    # Ejecutables
    ".exe": "Windows executable — verify digital signature",
    ".dll": "Windows library — verify signature and version",
    ".msi": "Windows installer",
    ".scr": "Screen saver — vector comun malware",
    ".bat": "Batch script — inspeccionar antes de ejecutar",
    ".ps1": "PowerShell script — verify signing + ExecutionPolicy",
    ".vbs": "VBScript — a menudo malicioso",
    ".hta": "HTA — vector phishing",
    ".jar": "Java archive — verify signature",
    # Documentos con macros
    ".docm": "Word con macros — alto riesgo",
    ".xlsm": "Excel con macros — alto riesgo",
    ".pptm": "PowerPoint con macros",
    ".dotm": "Word template con macros",
    # Archivos contenedores
    ".zip": "Verificar contenido antes de abrir",
    ".rar": "RAR — verify",
    ".7z": "Compressed",
    ".iso": "Disk image — verify signature / hash",
    ".img": "Disk image",
    # PDFs — pueden contener JS
    ".pdf": "PDF — verify JS/forms/attachments",
}


def audit_software_file(path):
    """Layer 6: analyze individual file/software artifact."""
    findings = []
    p = Path(path)
    if not p.exists():
        return [{"error": f"Path not found: {path}"}]
    if not p.is_file():
        return [{"error": "Not a file"}]

    ext = p.suffix.lower()
    size = p.stat().st_size

    # Riesgo por extension
    if ext in SUSPICIOUS_FILE_EXTS:
        findings.append({
            "layer": "SOFTWARE",
            "file": str(p),
            "extension": ext,
            "size_bytes": size,
            "description": SUSPICIOUS_FILE_EXTS[ext],
            "risk": "TRANSITION_REQUIRED",
        })

    # Hash SHA-256 (+ indicar necesidad de PQ-hardened signing)
    import hashlib
    try:
        h = hashlib.sha256()
        with open(p, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        findings.append({
            "layer": "SOFTWARE",
            "file": str(p),
            "sha256": h.hexdigest(),
            "note": "Verificar firma digital contra este hash (cosign / sigstore / authenticode)",
            "risk": "TRANSITION_REQUIRED" if ext in {".exe", ".dll", ".msi"} else "PQ_SAFE",
        })
    except Exception as e:
        findings.append({"error": f"hash failed: {e}"})

    # Verificar firmas (exe/dll Windows, jar, rpm, deb)
    if ext in {".exe", ".dll", ".msi"}:
        findings.append({
            "layer": "SOFTWARE",
            "file": str(p),
            "description": "Authenticode signature check — usar sigcheck / osslsigncode",
            "risk": "TRANSITION_REQUIRED",
            "note": "Migrate to PQ-hardened code signing (sigstore + ML-DSA on roadmap)",
        })

    if ext in {".pdf"}:
        findings.append({
            "layer": "SOFTWARE",
            "file": str(p),
            "description": "PDF — inspeccionar con peepdf/pdfid para JS/forms/attachments",
            "risk": "TRANSITION_REQUIRED",
        })

    if ext in {".docm", ".xlsm", ".pptm", ".dotm"}:
        findings.append({
            "layer": "SOFTWARE",
            "file": str(p),
            "description": "Office con macros — alto riesgo. Inspeccionar con oletools",
            "risk": "BROKEN_NOW",
        })

    # Usar file magic para detectar discrepancias
    try:
        r = subprocess.run(["file", "-b", str(p)], capture_output=True, text=True, timeout=10)
        magic = r.stdout.strip()
        findings.append({
            "layer": "SOFTWARE",
            "file": str(p),
            "file_magic": magic[:200],
        })
        # Mismatch extension vs content
        if ext in {".jpg", ".png", ".gif"} and "image" not in magic.lower():
            findings.append({
                "layer": "SOFTWARE",
                "file": str(p),
                "description": f"Extension {ext} pero contenido NO es imagen. Posible masquerade.",
                "risk": "BROKEN_NOW",
            })
    except Exception:
        pass

    return findings


# ─── Layer 7: CLOUD posture ─────────────────────────────────────────────────────

def audit_cloud_posture(config_path):
    """Layer 7: review cloud IaC configs (terraform, cloudformation, yaml) with PQ focus."""
    findings = []
    p = Path(config_path)
    if not p.exists():
        return [{"error": f"Path not found: {config_path}"}]

    cloud_patterns = [
        # TLS policies
        (r'(?i)ssl_policy.*ELBSecurityPolicy-201[0-6]', "AWS ELB TLS policy obsoleta", "BROKEN_NOW"),
        (r'(?i)(min.?tls.?version|tls_policy|ssl_policy)\s*[=:]\s*["\']?.*1\.[01]["\']?', "Min TLS 1.0/1.1 configured", "BROKEN_NOW"),
        # KMS key specs
        (r'customer_master_key_spec.*RSA_2048', "KMS RSA 2048 (SNDL)", "SNDL_VULNERABLE"),
        (r'customer_master_key_spec.*ECC_SECG_P256K1', "KMS ECC no-FIPS", "TRANSITION_REQUIRED"),
        # IAM legacy
        (r'(?i)signaturealgorithm.*sha1', "Firma SHA-1 en config", "BROKEN_NOW"),
        # S3 / Storage unencrypted
        (r'"SSEAlgorithm"\s*:\s*"?"?(?!AES256|aws:kms)', "Storage sin SSE", "BROKEN_NOW"),
        # Secrets hardcoded
        (r'(aws_access_key_id|aws_secret|password|api_key)\s*=\s*["\'][A-Za-z0-9+/=]{16,}["\']',
         "Credencial hardcoded en IaC", "BROKEN_NOW"),
        # Public S3
        (r'acl\s*=\s*["\']public-read', "S3 ACL public-read", "BROKEN_NOW"),
        # Unrestricted SG
        (r'cidr_blocks\s*=\s*\[["\']0\.0\.0\.0/0["\']\]', "SG con 0.0.0.0/0", "SNDL_VULNERABLE"),
        # Weak password policy
        (r'require_symbols\s*=\s*false', "IAM password policy sin simbolos", "TRANSITION_REQUIRED"),
    ]

    NON_IAC = {"package-lock.json", "package.json", "yarn.lock", "composer.lock", "Pipfile.lock", "poetry.lock", "Gemfile.lock", "cargo.lock"}
    NON_IAC_DIRS = {".terraform", "node_modules", ".git", "vendor", "__pycache__"}
    if p.is_file():
        files = [p]
    else:
        files = [
            f for f in p.rglob("*")
            if f.is_file()
            and f.suffix.lower() in {".tf", ".yaml", ".yml", ".json", ".hcl"}
            and f.name not in NON_IAC
            and not any(part in NON_IAC_DIRS for part in f.parts)
        ]
    for f in files[:500]:
        try:
            content = f.read_text(errors="replace")
        except Exception:
            continue
        for pattern, desc, risk in cloud_patterns:
            for m in re.finditer(pattern, content):
                line = content[:m.start()].count("\n") + 1
                findings.append({
                    "layer": "CLOUD",
                    "file": str(f),
                    "line": line,
                    "description": desc,
                    "risk": risk,
                    "match": m.group(0)[:100],
                })

    findings.append({
        "layer": "CLOUD",
        "note": "Complementar con cloud_analysis_dispatcher.py para audit completo (Prowler/Scout Suite)",
        "note": "Pair with cloud provider CLI (aws/az/gcloud) for complete audit",
    })
    return findings


# ─── Layer 8: LINKS / EMAILS (phishing + weak crypto) ──────────────────────────

SUSPICIOUS_URL_PATTERNS = [
    (r"http://[^/]+/(?:login|admin|signin|auth)", "Login sin HTTPS", "BROKEN_NOW"),
    (r"https?://[a-f0-9]{8,}\.[a-z]{2,6}/", "Dominio hash-like (potencial phishing)", "TRANSITION_REQUIRED"),
    (r"https?://[^/]+\.(?:tk|ml|ga|cf|gq)/", "TLD frequent phishing", "TRANSITION_REQUIRED"),
    (r"https?://[^/]+@[^/]+", "URL con @ (user redirect trick)", "BROKEN_NOW"),
    (r"data:text/html;base64,", "data URI HTML encoded", "BROKEN_NOW"),
    (r"javascript:", "javascript: URL scheme", "BROKEN_NOW"),
    (r"\.onion/", "Tor hidden service", "TRANSITION_REQUIRED"),
    # Homograph / typosquatting
    (r"https?://[^/]*[а-я][^/]*/", "Cirilico en URL (IDN homograph)", "BROKEN_NOW"),
]

EMAIL_HEADER_CHECKS = [
    # SPF / DKIM / DMARC missing
    # Replies suspicious
    # Reply-To mismatch From
]


def audit_link_or_email(target):
    """Layer 8: analyze URL, raw email, or file with links."""
    findings = []
    text = ""

    # Can be a direct URL, email file (.eml) or file with links
    if os.path.isfile(target):
        try:
            text = Path(target).read_text(errors="replace")
        except Exception as e:
            return [{"error": str(e)}]
    else:
        text = target  # URL directo

    # Scan URLs patterns
    for pattern, desc, risk in SUSPICIOUS_URL_PATTERNS:
        for m in re.finditer(pattern, text, re.IGNORECASE):
            findings.append({
                "layer": "LINK",
                "description": desc,
                "match": m.group(0)[:200],
                "risk": risk,
            })

    # Email headers (si parece .eml)
    if "From:" in text and "Subject:" in text:
        # SPF/DKIM/DMARC
        if "spf=fail" in text.lower() or "spf=softfail" in text.lower():
            findings.append({
                "layer": "LINK", "sub": "EMAIL",
                "description": "SPF fail / softfail",
                "risk": "BROKEN_NOW",
            })
        if "dkim=fail" in text.lower() or "dkim=none" in text.lower():
            findings.append({
                "layer": "LINK", "sub": "EMAIL",
                "description": "DKIM fail / none",
                "risk": "BROKEN_NOW",
            })
        if "dmarc=fail" in text.lower() or "dmarc=none" in text.lower():
            findings.append({
                "layer": "LINK", "sub": "EMAIL",
                "description": "DMARC fail / none",
                "risk": "BROKEN_NOW",
            })

        # Reply-To mismatch
        m_from = re.search(r"^From:\s*.*<([^>]+)>", text, re.MULTILINE)
        m_reply = re.search(r"^Reply-To:\s*.*<([^>]+)>", text, re.MULTILINE)
        if m_from and m_reply:
            from_domain = m_from.group(1).split("@")[-1].lower()
            reply_domain = m_reply.group(1).split("@")[-1].lower()
            if from_domain != reply_domain:
                findings.append({
                    "layer": "LINK", "sub": "EMAIL",
                    "description": f"From/Reply-To domain mismatch: {from_domain} vs {reply_domain}",
                    "risk": "BROKEN_NOW",
                })

        # SHA-1 / MD5 en DKIM
        if re.search(r"DKIM-Signature:.*a=rsa-sha1", text, re.IGNORECASE):
            findings.append({
                "layer": "LINK", "sub": "EMAIL",
                "description": "DKIM con RSA-SHA1 (deprecado)",
                "risk": "BROKEN_NOW",
            })

    return findings


# ─── Layer 10: WEB3 / DeFi ──────────────────────────────────────────────────────
# Immunefi-ready: audits off-chain endpoints of DeFi protocols.
# Scope: TLS/crypto in APIs, JWT algorithms, RPC endpoints, ECDSA in smart contracts.
# NOTE: Only run against targets IN SCOPE of the bug bounty program.
#       Do not run against mainnet contracts without explicit authorization.
#       Immunefi accepts research with PoC; does NOT accept scanner dumps.

WEB3_QUANTUM_PATTERNS = {
    # ECDSA/secp256k1 is quantum-vulnerable (Shor's algorithm breaks it)
    "secp256k1": ("SNDL_VULNERABLE", "secp256k1 — ECDSA curve used in all Ethereum/Bitcoin. Quantum-vulnerable (CNSA 2.0: migrate by 2030)"),
    "ecdsa_k1": ("SNDL_VULNERABLE", "ECDSA k1 — same as secp256k1"),
    "secp256r1": ("SNDL_VULNERABLE", "secp256r1 (P-256) — NIST curve, quantum-vulnerable per CNSA 2.0"),
    "keccak256": ("TRANSITION_REQUIRED", "Keccak-256 — used as hash in Ethereum. Quantum-resistant for collision, but vulnerable to Grover (preimage, 2^128 classical → 2^64 quantum)"),
    "sha256_hmac": ("TRANSITION_REQUIRED", "HMAC-SHA256 — weakened by Grover's algorithm (128-bit → 64-bit quantum security)"),
    "jwt_es256": ("SNDL_VULNERABLE", "JWT alg:ES256 (ECDSA P-256) — quantum-vulnerable signature algorithm in API auth"),
    "jwt_es256k": ("SNDL_VULNERABLE", "JWT alg:ES256K (ECDSA secp256k1) — quantum-vulnerable, common in Web3 auth"),
    "eth_sign": ("SNDL_VULNERABLE", "eth_sign / personal_sign — ECDSA signature scheme in Ethereum wallets"),
    "ec_recover": ("SNDL_VULNERABLE", "ecrecover() — ECDSA recovery in smart contracts, quantum-vulnerable"),
}


def audit_web3_endpoint(host: str, port: int = 443, rpc_path: str = "/") -> list:
    """
    WEB3 Layer: Audita endpoints off-chain de protocolos DeFi para vulnerabilidades
    cryptographic quantum vulnerabilities.

    Checks:
    1. TLS crypto (secp256r1 vs ML-KEM readiness)
    2. JWT algorithm in API responses (ES256/ES256K = ECDSA = quantum-vulnerable)
    3. JSON-RPC endpoint crypto exposure
    4. API headers for crypto algorithm hints
    5. CBOM generation (Cryptographic Bill of Materials)

    Immunefi scope: off-chain APIs, bridges, web UIs, oracle endpoints.
    NOT: direct on-chain calls or EVM bytecode (out of scope for this layer).
    """
    import urllib.request, urllib.error, ssl, socket, json as json_mod, datetime

    findings = []
    scheme = "https" if port in (443, 8443) else "http"
    base_url = f"{scheme}://{host}:{port}{rpc_path}"

    # 1. TLS crypto check (reuse audit_tls)
    if scheme == "https":
        tls_findings = audit_tls(host, port)
        for f in tls_findings:
            f["layer"] = "WEB3"
            f["sub"] = "TLS"
            f["immunefi_context"] = "Off-chain API TLS weakness — SNDL risk for long-lived data"
        findings.extend(tls_findings)

    # 2. Probe JSON-RPC (standard Ethereum RPC)
    rpc_payloads = [
        {"jsonrpc": "2.0", "method": "web3_clientVersion", "params": [], "id": 1},
        {"jsonrpc": "2.0", "method": "eth_chainId", "params": [], "id": 2},
        {"jsonrpc": "2.0", "method": "net_version", "params": [], "id": 3},
    ]
    for payload in rpc_payloads:
        try:
            data = json_mod.dumps(payload).encode()
            req = urllib.request.Request(
                base_url, data=data,
                headers={"Content-Type": "application/json", "User-Agent": "pq-audit/1.0"},
                method="POST"
            )
            ctx = ssl.create_default_context() if scheme == "https" else None
            with urllib.request.urlopen(req, timeout=10, context=ctx) as r:
                resp = json_mod.loads(r.read().decode("utf-8", errors="replace"))
                # Check for Ethereum RPC exposure
                if "result" in resp or "jsonrpc" in resp:
                    findings.append({
                        "layer": "WEB3", "sub": "JSON-RPC",
                        "host": host, "endpoint": base_url,
                        "method": payload["method"],
                        "risk": "SNDL_VULNERABLE",
                        "description": f"Ethereum JSON-RPC exposed: {payload['method']} → uses ECDSA secp256k1 (quantum-vulnerable)",
                        "response_preview": str(resp.get("result", "?"))[:100],
                        "immunefi_relevance": "Confirms blockchain node reachable. ECDSA signatures quantum-vulnerable per CNSA 2.0.",
                        "remediation": "Plan migration to NIST PQC signature (ML-DSA/SLH-DSA) when EIPs support it. Monitor EIP-7000s.",
                    })
                    break
        except Exception:
            pass

    # 3. Check API response headers for JWT algorithm hints
    try:
        req = urllib.request.Request(
            base_url, headers={"User-Agent": "pq-audit/1.0"}
        )
        ctx = ssl.create_default_context() if scheme == "https" else None
        with urllib.request.urlopen(req, timeout=10, context=ctx) as r:
            headers = dict(r.headers)
            body = r.read(4096).decode("utf-8", errors="replace")

            # Check for ECDSA/secp256 mentions in response
            for pattern, (risk, desc) in WEB3_QUANTUM_PATTERNS.items():
                if pattern.lower() in body.lower() or pattern.lower() in str(headers).lower():
                    findings.append({
                        "layer": "WEB3", "sub": "API_RESPONSE",
                        "host": host, "pattern": pattern,
                        "risk": risk, "description": desc,
                        "immunefi_relevance": "Detected in off-chain API response/headers",
                    })

            # Check for JWT in Authorization header or response
            if "eyJ" in body:
                # Decode JWT header to check algorithm
                import base64
                jwt_parts = [p for p in body.split() if p.startswith("eyJ")]
                for jwt in jwt_parts[:3]:
                    try:
                        parts = jwt.split(".")
                        if len(parts) >= 2:
                            hdr = json_mod.loads(base64.urlsafe_b64decode(parts[0] + "=="))
                            alg = hdr.get("alg", "?")
                            if alg in ("ES256", "ES256K", "ES384", "ES512"):
                                findings.append({
                                    "layer": "WEB3", "sub": "JWT_ALGORITHM",
                                    "host": host, "algorithm": alg,
                                    "risk": "SNDL_VULNERABLE",
                                    "description": f"JWT with ECDSA algorithm {alg} — quantum-vulnerable",
                                    "immunefi_relevance": "API authentication uses quantum-vulnerable ECDSA JWT",
                                    "poc_note": f"JWT header: {str(hdr)[:100]}",
                                    "remediation": "Migrate to EdDSA (Ed25519) as interim; plan ML-DSA for PQC.",
                                })
                    except Exception:
                        pass
    except Exception:
        pass

    # 4. Generate CBOM (Cryptographic Bill of Materials) for this endpoint
    cbom = {
        "target": base_url,
        "timestamp": datetime.datetime.now().isoformat(),
        "crypto_inventory": [],
        "quantum_readiness": "VULNERABLE" if findings else "UNKNOWN",
    }
    for f in findings:
        cbom["crypto_inventory"].append({
            "algorithm": f.get("pattern", f.get("sub", "?")),
            "risk_level": f.get("risk", "?"),
            "location": f"{host}:{port}",
        })
    findings.append({"layer": "WEB3", "sub": "CBOM", "cbom": cbom})

    return findings


def audit_web3_source(path: str) -> list:
    """
    WEB3 Layer (source): Detects quantum-vulnerable crypto in smart contract source code
    y off-chain code (Solidity, JavaScript, TypeScript, Python).

    Immunefi-relevant: off-chain code for bridges, oracles, APIs.
    """
    import re, json as json_mod

    findings = []
    target = Path(path)
    if not target.exists():
        return [{"error": f"Path not found: {path}"}]

    # Solidity / JavaScript / TypeScript patterns
    WEB3_CODE_PATTERNS = [
        (r"secp256k1|SECP256K1", "SNDL_VULNERABLE", "secp256k1 usage — ECDSA, quantum-vulnerable (Shor's algorithm)"),
        (r"ethers\.utils\.verifyMessage|ethers\.utils\.recoverAddress", "SNDL_VULNERABLE", "ECDSA signature verification — quantum-vulnerable"),
        (r"ecrecover\s*\(", "SNDL_VULNERABLE", "Solidity ecrecover() — ECDSA recovery, quantum-vulnerable"),
        (r"keccak256\s*\(", "TRANSITION_REQUIRED", "keccak256 — weakened by Grover's algorithm (128-bit → 64 quantum-bit)"),
        (r"web3\.eth\.accounts\.sign|signMessage\s*\(", "SNDL_VULNERABLE", "Ethereum account signing — ECDSA secp256k1"),
        (r"ecdsa\s*\.|ECDSA\s*\.", "SNDL_VULNERABLE", "ECDSA library usage — quantum-vulnerable"),
        (r"\"alg\"\s*:\s*\"ES256\"", "SNDL_VULNERABLE", "JWT ES256 hardcoded — ECDSA P-256 algorithm"),
        (r"require\s*\(\s*['\"]elliptic['\"]", "SNDL_VULNERABLE", "elliptic npm package — secp256k1 usage"),
        (r"from\s+['\"]@noble/secp256k1['\"]", "SNDL_VULNERABLE", "@noble/secp256k1 — ECDSA library"),
        (r"import\s+.*secp256k1", "SNDL_VULNERABLE", "secp256k1 import detected"),
        # Positive: PQC usage (informational)
        (r"ml-kem|mlkem|kyber|dilithium|falcon|sphincs|ml_kem|ML-KEM", "PQ_HYBRID_PRESENT", "PQC algorithm detected — good"),
    ]

    ext_include = {".sol", ".js", ".ts", ".py", ".go", ".rs", ".java"}
    files_scanned = 0

    for f in (target.rglob("*") if target.is_dir() else [target]):
        if f.suffix.lower() not in ext_include or not f.is_file():
            continue
        files_scanned += 1
        try:
            content = f.read_text(errors="replace")
            for pattern, risk, desc in WEB3_CODE_PATTERNS:
                for match in re.finditer(pattern, content, re.IGNORECASE):
                    line = content[:match.start()].count("\n") + 1
                    if risk == "PQ_HYBRID_PRESENT":
                        continue  # Skip positive findings in output (just track)
                    findings.append({
                        "layer": "WEB3", "sub": "SOURCE_CODE",
                        "file": str(f.relative_to(target) if target.is_dir() else f),
                        "line": line,
                        "pattern": match.group(0)[:50],
                        "risk": risk,
                        "description": desc,
                        "immunefi_relevance": "Off-chain code with quantum-vulnerable crypto",
                    })
        except Exception:
            pass

    return findings


# ─── Layer 9: DOCKER ────────────────────────────────────────────────────────────

def audit_docker_image(image):
    """Layer 9: scan Docker image — weak crypto labels + Docker Scout CVEs (if available)."""
    findings = []
    # Labels check
    try:
        r = subprocess.run(["docker", "inspect", image], capture_output=True, text=True, timeout=30)
        if r.returncode == 0:
            data = json.loads(r.stdout)
            labels = data[0].get("Config", {}).get("Labels", {}) or {}
            for k, v in labels.items():
                if any(weak in str(v).lower() for weak in ["md5", "sha1", "rc4", "des"]):
                    findings.append({
                        "layer": "DOCKER", "image": image,
                        "field": f"label.{k}", "value": str(v)[:100],
                        "risk": "BROKEN_NOW",
                        "description": "Label referencing weak crypto algorithm",
                    })
    except Exception as e:
        findings.append({"layer": "DOCKER", "error": str(e)})

    # Docker Scout CVE scan (optional — requires docker scout plugin)
    try:
        scout = subprocess.run(
            ["docker", "scout", "cves", "--format", "sarif", image],
            capture_output=True, text=True, timeout=120,
        )
        if scout.returncode == 0 and scout.stdout.strip():
            try:
                sarif = json.loads(scout.stdout)
                for run in sarif.get("runs", []):
                    for result in run.get("results", []):
                        rule_id = result.get("ruleId", "")
                        msg = result.get("message", {}).get("text", "")
                        # Only report crypto-related CVEs
                        if any(kw in msg.lower() for kw in ["crypto", "ssl", "tls", "cipher",
                                                              "rsa", "sha", "md5", "openssl"]):
                            findings.append({
                                "layer": "DOCKER", "image": image,
                                "cve": rule_id, "description": msg[:200],
                                "risk": "SNDL_VULNERABLE",
                                "source": "docker-scout",
                            })
            except json.JSONDecodeError:
                pass
    except FileNotFoundError:
        pass  # docker scout no disponible — no es error
    except Exception:
        pass

    return findings


# ─── Plan de remediacion ───────────────────────────────────────────────────────

def build_remediation_plan(findings):
    """Generate prioritized migration plan."""
    by_risk = {"BROKEN_NOW": [], "SNDL_VULNERABLE": [], "TRANSITION_REQUIRED": [], "PQ_HYBRID_MISSING": []}
    for f in findings:
        risk = f.get("risk", "")
        if risk in by_risk:
            by_risk[risk].append(f)

    plan = {
        "immediate_actions_broken": {
            "deadline": "30 dias",
            "rationale": "Ya roto clasicamente. Riesgo operativo actual.",
            "count": len(by_risk["BROKEN_NOW"]),
            "items": by_risk["BROKEN_NOW"][:10],
        },
        "short_term_sndl": {
            "deadline": "6-12 meses",
            "rationale": "Store-Now-Decrypt-Later. Data long-lived en riesgo con CRQC ~2030s.",
            "count": len(by_risk["SNDL_VULNERABLE"]),
            "items": by_risk["SNDL_VULNERABLE"][:10],
        },
        "medium_term_transition": {
            "deadline": "12-24 meses",
            "rationale": "Migrate to PQ hybrid or stronger primitives before 2030.",
            "count": len(by_risk["TRANSITION_REQUIRED"]),
        },
        "long_term_hybrid": {
            "deadline": "24-36 meses",
            "rationale": "Adoptar hybrid PQC (NIST FIPS 203/204/205).",
            "count": len(by_risk["PQ_HYBRID_MISSING"]),
        },
    }
    return plan


# ─── Main ──────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description="pq-audit — Post-Quantum Holistic Security Audit")
    ap.add_argument("--layer", choices=["all", "crypto", "code", "system", "tls", "ssh", "cert",
                                         "deps", "docker", "network", "software", "cloud", "link",
                                         "web3"],  # NEW: DeFi/Immunefi layer
                    default="all")
    ap.add_argument("--target", default=None, help="Path / host / image segun layer")
    ap.add_argument("--host", default=None, help="Host para TLS/SSH audit")
    ap.add_argument("--port", type=int, default=443)
    ap.add_argument("--requirements", default=None, help="requirements.txt o package.json")
    ap.add_argument("--file", default=None, help="Archivo cert o codigo")
    ap.add_argument("--image", default=None, help="Imagen Docker")
    ap.add_argument("--output", default=None, help="JSON salida")
    args = ap.parse_args()

    all_findings = []

    if args.layer in ("all", "crypto") and args.target:
        all_findings.extend(audit_crypto_primitives(args.target))
    if args.layer in ("all", "code") and args.target:
        all_findings.extend(audit_code(args.target))
    if args.layer in ("all", "system", "tls") and args.host:
        all_findings.extend(audit_tls(args.host, args.port))
    if args.layer in ("all", "ssh") and args.host:
        all_findings.extend(audit_ssh_config(args.host, args.port))
    if args.layer in ("all", "cert", "system") and args.file:
        all_findings.extend(audit_x509_cert(args.file))
    if args.layer in ("all", "deps") and args.requirements:
        all_findings.extend(audit_deps(args.requirements))
    if args.layer in ("all", "docker") and args.image:
        all_findings.extend(audit_docker_image(args.image))
    if args.layer in ("all", "network") and args.host:
        all_findings.extend(audit_network(args.host))
    if args.layer in ("all", "software") and args.file:
        all_findings.extend(audit_software_file(args.file))
    if args.layer in ("all", "cloud") and args.target:
        all_findings.extend(audit_cloud_posture(args.target))
    if args.layer in ("all", "link") and args.target:
        all_findings.extend(audit_link_or_email(args.target))
    # WEB3 layer — DeFi/Immunefi: off-chain endpoints + source code
    if args.layer == "web3":
        if args.host:
            all_findings.extend(audit_web3_endpoint(args.host, args.port, args.target or "/"))
        if args.target and Path(args.target).exists():
            all_findings.extend(audit_web3_source(args.target))
        if not args.host and not args.target:
            print("[!] web3 layer requires --host <api-endpoint> or --target <source-dir>")

    if not all_findings:
        print("[!] No findings. Check args (--target / --host / --requirements / --file / --image)")
        sys.exit(0)

    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "scope": args.layer,
        "summary": {
            "total_findings": len(all_findings),
            "by_risk": {r: sum(1 for f in all_findings if f.get("risk") == r) for r in RISK_PQ.keys()},
        },
        "remediation_plan": build_remediation_plan(all_findings),
        "findings": all_findings,
    }

    output = json.dumps(report, indent=2, default=str)
    if args.output:
        Path(args.output).write_text(output)
        print(f"[OK] {args.output}")
    else:
        print(output)

    # Exit code refleja severidad maxima
    if report["summary"]["by_risk"].get("BROKEN_NOW", 0) > 0:
        sys.exit(3)
    elif report["summary"]["by_risk"].get("SNDL_VULNERABLE", 0) > 0:
        sys.exit(2)
    elif report["summary"]["by_risk"].get("TRANSITION_REQUIRED", 0) > 0:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
