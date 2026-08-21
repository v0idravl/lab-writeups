# Lab Writeups Maintenance

This repo is published as a public-safe portfolio artifact. Private lab notes can contain exact proof values, target IPs, hashes, and credentials, but the public writeups should preserve methodology while redacting details that are not necessary for learning value.

## Public-safe standard

Public writeups should include:

- Summary
- Enumeration / reconnaissance
- Initial access
- Privilege escalation or lateral movement, when applicable
- Root cause
- Impact
- Remediation
- Detection opportunities
- Lessons learned

Public writeups should redact:

- lab target IPs
- flags and proof-only values
- exact NT hashes / captured hashes
- reusable plaintext passwords
- temporary accounts or credentials created during exploitation

## Local verification

```bash
python3 scripts/normalize_public_writeups.py
python3 scripts/quality_check.py
```

If Ruby dependencies are available, validate the generated site too:

```bash
bundle install
bundle exec jekyll build
```
