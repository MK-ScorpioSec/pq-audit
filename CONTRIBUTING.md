# Contributing to pq-audit

## How to Contribute

**Bug reports:** Open an issue using the Bug Report template.  
**New detection patterns:** Open an issue using the Security Finding template — describe the vulnerability pattern and how pq-audit should detect it.  
**Code contributions:** Fork → branch → PR against `main`. PRs must be signed (DCO sign-off required on web commits).

## Development Setup

```bash
git clone https://github.com/mk-scorpiosec/pq-audit.git
cd pq-audit
python3 pq_audit.py --help
```

No external dependencies — stdlib only.

## Code Style

- Python 3.10+
- No third-party libraries (keep stdlib-only)
- Functions documented with one-line docstrings where non-obvious
- New detection patterns follow the existing layer structure

## Commit Signing

All commits to `main` must be GPG signed. Configure:
```bash
git config --global user.signingkey YOUR_KEY_ID
git config --global commit.gpgsign true
```

## License

By contributing, you agree your contributions are licensed under Apache 2.0 and you certify the [Developer Certificate of Origin](https://developercertificate.org/).
