# Lab Writeups

This repository is my landing page for individual lab, HTB, PG, and OSCP-style machine writeups.

It is built around a per-machine workflow:

1. Take structured notes during testing.
2. Convert those notes into a clean technical writeup.
3. Keep the final report readable, reproducible, and evidence-driven.

## Purpose

This repo is focused on single-target technical writeups, not full multi-host client reports. The goal is to document attack paths clearly enough to:

- preserve methodology and proof
- support OSCP-style reporting expectations
- stay readable on GitHub
- avoid bloated, boilerplate-heavy report sections

## Core Files

- [writeup-template.md](./writeup-template.md): Primary per-machine template for recon, exploitation, privilege escalation, proof, screenshots, and report-ready narrative.
- [oscp-findings-reference.md](./oscp-findings-reference.md): Supporting reference material for shaping findings and remediation language.

## Writeup Standard

Writeups in this repo are intended to:

- show the attack path from enumeration to objective completion
- include enough detail to reproduce the compromise
- capture proof such as `local.txt`, `proof.txt`, `whoami`, `id`, `hostname`, or equivalent evidence when applicable
- reference screenshots at major milestones
- include modified exploit code, payloads, or snippets only when they materially matter
- keep findings concise and grounded in actual proof

## Writeup Index

### Linux

| Platform | Machine | Key Technique | Writeup |
|---|---|---|---|
| HTB | Example | Redis file write, SSH key injection, Webmin RCE | `<add link>` |

### Windows

| Platform | Machine | Key Technique | Writeup |
|---|---|---|---|
| - | - | - | - |

### Active Directory

| Platform | Machine / Set | Key Technique | Writeup |
|---|---|---|---|
| - | - | - | - |


## Notes

- This repo is optimized for per-machine reporting, especially OSCP-style technical documentation.
- It also borrows useful structure from professional penetration test reporting, but it does not aim to be a full client deliverable by itself.