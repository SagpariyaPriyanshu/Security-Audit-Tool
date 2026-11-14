# HardenScan: System Security Audit Tool (Project 2)

Cross-platform (Windows + Linux) Python tool that audits a host against CIS Benchmarks and the
ACSC Essential Eight, scores it out of 100 and writes an HTML report with a fix per failed check.
Cyber security resume project, paired with Project 1 (LogSentry mini SIEM). Full plan, module
reference with code walkthroughs, and roadmap: `docs/DEVELOPMENT_GUIDE.md`. Read it before
starting any phase.

## How we work: learning mode

The owner (Priyansuh) is learning while building. Optimise for understanding, not speed.

- Build ONE function or small step at a time. Never write a whole module in one go.
- Before writing code: explain in plain words what the function does, its inputs and
  outputs, and any new concept it uses (enum, dataclass, decorator, subprocess, thread pool, etc.).
- After writing code: walk through it line by line for anything non-obvious, then show
  how to run or test it.
- Prefer clear, readable code over clever code. Comment the "why", not the "what".
- Ask before adding a dependency, changing the folder structure, or skipping ahead a phase.
- End each step by suggesting a Git commit message.
- When a phase milestone is reached, tick its boxes in `docs/DEVELOPMENT_GUIDE.md`
  and update "Current status" below.

## Tech stack

Python 3.11+, `subprocess`, `dataclasses`, `enum`, `concurrent.futures`, psutil, PyYAML,
Jinja2, pytest. On Windows, checks call PowerShell via `platform.powershell()` (JSON output).

## Structure

```
main.py                         CLI: scan / fix
controls.yaml                   check id -> CIS / Essential Eight references
hardenscan/models.py            Status, Severity, CheckResult
hardenscan/platform.py          current_os, is_admin, run(), powershell()
hardenscan/registry.py          @register + discover()
hardenscan/checks/base.py       Check base class: subclasses implement evaluate()
hardenscan/checks/windows/      firewall, defender, updates, password_policy, accounts,
                                bitlocker, legacy_services
hardenscan/checks/linux/        firewall, antivirus, updates, password_policy, accounts,
                                luks, legacy_services
hardenscan/checks/common/       open_ports (psutil)
hardenscan/runner.py            thread pool + timeouts
hardenscan/scoring.py           weighted score, grade, coverage, critical cap
hardenscan/report/              html.py (Jinja2, autoescape), json_out.py, templates/
hardenscan/fixer.py             auto-fix (bonus)
tests/                          pytest; fixtures/ holds saved real command output
```

## Rules

- The scanner is read-only. Only `fixer.py` changes the host, only with `--apply`, and asks per change.
- Commands are always lists passed to `platform.run()`; never `shell=True`.
- A check that cannot read its data returns ERROR, never FAIL. ERROR/SKIP are excluded from the score.
- Windows-only imports (e.g. `ctypes.windll`, `winreg`) go inside functions, never at module top,
  because the registry imports every check on every OS.
- Jinja2 autoescape stays on; `yaml.safe_load` only.
- Every check gets a PASS test and a FAIL test using fixtures + `monkeypatch`.
- Destructive lab testing and auto-fix only on VMs the owner controls, with a snapshot first.

## Commands

- Scan: `python main.py scan --out reports/` (run as admin / with sudo)
- Fix (dry run): `python main.py fix`  |  apply: `python main.py fix --apply`
- Tests: `pytest -q`

## Current status

Skeleton created (stub files only). Phase 0 (setup) not started: GitHub repo, VMs and
snapshots still to do. Owner's dev OS: not yet confirmed (ask on first session).
