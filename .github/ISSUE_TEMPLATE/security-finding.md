---
name: Security Finding
about: Report a new cryptographic or IaC vulnerability pattern pq-audit should detect
title: "[FINDING]"
labels: enhancement, security
assignees: ''

---

```markdown
---
name: Security Finding
about: Report a new cryptographic or IaC vulnerability pattern pq-audit should detect
title: '[FINDING] '
labels: security, enhancement
assignees: ''
---

## Vulnerability Pattern
<!-- Describe the cryptographic or IaC misconfiguration -->

## Risk Classification
- [ ] BROKEN_NOW — broken by current standards today
- [ ] SNDL_VULNERABLE — harvest-now-decrypt-later exposure
- [ ] PQC_READY gap — missing migration path to NIST FIPS 203/204/205
- [ ] Other misconfiguration

## Where It Appears
<!-- Terraform resource, config file, code pattern, etc. -->

## Example (sanitized)
```
# Example of the vulnerable pattern
```

## Detection Suggestion
<!-- How should pq-audit detect this? Key/value pattern, regex, etc. -->

## References
<!-- NIST SP 800-xxx, CWE-xxx, CVE-xxx, etc. -->
```
