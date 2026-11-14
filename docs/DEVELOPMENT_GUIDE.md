# Project 2: System Security Audit Tool Development Guide

2026-10-12 · Priyansuh

## What we're building

**HardenScan** is a Python command-line tool that audits a Windows or Linux machine against security best practice, gives it a score out of 100, and writes an HTML report with a fix for every failed check. It is Project 2 from the Cyber Security Resume Projects ideas doc: the "harden systems" half of your portfolio, paired with the Project 1 mini SIEM that detects threats.

**What it checks** (from the ideas doc)

| Check | Windows source | Linux source | Maps to |
|---|---|---|---|
| Firewall on | `Get-NetFirewallProfile` | `ufw status` / `firewalld` | CIS host firewall controls |
| Antivirus / Defender running | `Get-MpComputerStatus` | ClamAV service status | Essential Eight: application control (related) |
| Pending OS updates | Windows Update COM API | `apt list --upgradable` | Essential Eight: patch operating systems |
| Password policy (length, lockout) | `net accounts` | `/etc/login.defs`, `pwquality.conf`, `faillock.conf` | CIS password and lockout controls |
| Open ports and listening services | `Get-NetTCPConnection` | `ss -tulnp` | CIS network services |
| Admin, guest and disabled accounts | `Get-LocalUser`, `Get-LocalGroupMember` | `/etc/passwd`, `sudo`/`wheel` group | Essential Eight: restrict admin privileges |
| Disk encryption | `Get-BitLockerVolume` | `lsblk` looking for LUKS (`crypto_LUKS`) | CIS encryption controls |
| Risky services (Telnet, SMBv1, RDP) | `Get-SmbServerConfiguration`, RDP registry key | `telnet`, `rsh`, Samba services | CIS legacy services |

The Windows and Linux command names are the usual built-in sources; confirm each against your OS version as you build it. Control IDs vary between CIS benchmark versions, so the tool stores them in a config file rather than in code.

**Design decisions**

- **Python, not pure PowerShell.** One codebase covers both operating systems, and it matches Project 1. On Windows the Python checks call PowerShell under the hood, so you still learn the PowerShell you would use in an IT support job.
- **Read-only by default.** The scanner only reads settings. The optional auto-fix mode changes nothing unless you pass `--fix` and confirm each change.
- **Checks are plugins.** Each check is a small class that registers itself. Adding a check never means editing the scanner, the scorer or the report.
- **Results are data first.** Every check returns the same `CheckResult` shape, saved as JSON. The HTML report, the score and any future dashboard all read that one file.

## Architecture

A scan moves through three layers: gather facts from the host, judge them, then present them. Each layer only talks to the one next to it.

_(Architecture diagram: see the online guide.)_

Read it from the top left. `main.py` asks the registry for the checks that fit this OS, and the runner runs them. Each check asks `platform.py` to run a command on the host, then turns the output into a status plus evidence. The scorer and the report only ever see that list of results, never the host. The fixer is the one part allowed to change the host, and only when you run `fix --apply`.

## Folder structure and setup

The code has three jobs: `checks/` gathers facts, `runner.py` and `scoring.py` judge and score them, and `report/` presents them. If you are unsure where code belongs, ask which of those jobs it does.

```
hardenscan/
├── README.md                    # what it does, screenshots, how to run
├── requirements.txt             # jinja2, pyyaml, psutil, pytest
├── controls.yaml                # check id -> CIS / Essential Eight mapping, weights
├── main.py                      # command-line entry point
├── hardenscan/
│   ├── __init__.py
│   ├── models.py                # Status, Severity, CheckResult
│   ├── platform.py              # detect OS, admin rights, run commands safely
│   ├── registry.py              # @register decorator + check discovery
│   ├── runner.py                # runs every check with timeouts
│   ├── scoring.py               # weighted score out of 100
│   ├── fixer.py                 # optional auto-fix mode (bonus)
│   ├── checks/
│   │   ├── base.py              # Check base class
│   │   ├── windows/
│   │   │   ├── firewall.py
│   │   │   ├── defender.py
│   │   │   ├── updates.py
│   │   │   ├── password_policy.py
│   │   │   ├── accounts.py
│   │   │   ├── bitlocker.py
│   │   │   └── legacy_services.py   # SMBv1, Telnet, RDP
│   │   ├── linux/
│   │   │   ├── firewall.py
│   │   │   ├── antivirus.py
│   │   │   ├── updates.py
│   │   │   ├── password_policy.py
│   │   │   ├── accounts.py
│   │   │   ├── luks.py
│   │   │   └── legacy_services.py
│   │   └── common/
│   │       └── open_ports.py    # uses psutil on both OSes
│   └── report/
│       ├── html.py              # renders the Jinja2 template
│       ├── json_out.py          # machine-readable results
│       └── templates/
│           └── report.html.j2
├── tests/
│   ├── fixtures/                # saved command output from real VMs
│   └── test_*.py
└── reports/                     # generated reports (git-ignored)
```

**Setup**

1. Install Python 3.11 or newer on both your Windows and Ubuntu VMs.
2. Create a virtual environment: `python -m venv .venv`, then activate it (`.venv\Scripts\activate` on Windows, `source .venv/bin/activate` on Linux).
3. Install packages: `pip install jinja2 pyyaml psutil pytest`.
4. Run as administrator (Windows) or with `sudo` (Linux). Several checks, such as BitLocker and `faillock`, need elevated rights to read their settings. Without them the check returns **Error**, not **Fail**, so the score is never wrong because of permissions.
5. First run: `python main.py scan --out reports/`.

## Module guide: every file and the complex functions

Files are listed in the order you build them. Simple files get a sentence; the functions that are easy to get wrong get the full code and a plain-English walkthrough.

### models.py: the shared data shapes

Every check, whatever it inspects, returns one `CheckResult`. The scorer, the report and the fixer only ever see this shape, which is what lets you add checks without touching them.

```python
from dataclasses import dataclass, field, asdict
from enum import Enum

class Status(str, Enum):
    PASS = 'pass'
    WARN = 'warn'     # not ideal, but not a clear failure
    FAIL = 'fail'
    ERROR = 'error'   # the check could not run (no permission, tool missing)
    SKIP = 'skip'     # the check does not apply to this machine

class Severity(str, Enum):
    LOW = 'low'
    MEDIUM = 'medium'
    HIGH = 'high'
    CRITICAL = 'critical'

@dataclass
class CheckResult:
    check_id: str              # e.g. 'win.firewall'
    title: str
    status: Status
    severity: Severity
    evidence: str              # what we actually saw: 'Public profile: off'
    fix: str = ''              # shown in the report for FAIL and WARN
    controls: list[str] = field(default_factory=list)
    duration_ms: int = 0

    def to_dict(self):
        d = asdict(self)
        d['status'] = self.status.value
        d['severity'] = self.severity.value
        return d
```

**Why it is built this way**

- `Status(str, Enum)` makes each status both an enum and a string. You get typo protection in code (`Status.FAIL`, not `'fial'`) and it still writes to JSON as plain text.
- **ERROR is separate from FAIL.** If the tool cannot read the BitLocker status because you forgot to run as admin, that is not proof the disk is unencrypted. Mixing the two would make the score lie. Errors are reported, but left out of the score.
- `evidence` holds the raw fact behind the verdict. An auditor's first question is always "how do you know?", and the report should answer it.

### platform.py: running system commands safely

Almost every check works by running a system command and reading its output. This file is the one place that does that, so the safety rules live in one spot.

```python
import ctypes, json, os, platform, shutil, subprocess

class CommandError(Exception):
    pass

def current_os() -> str:
    return {'Windows': 'windows', 'Linux': 'linux'}.get(platform.system(), 'unsupported')

def is_admin() -> bool:
    if current_os() == 'windows':
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    return os.geteuid() == 0

def run(cmd: list[str], timeout: int = 30, ok_codes=(0,)) -> str:
    if shutil.which(cmd[0]) is None:
        raise CommandError(f'{cmd[0]} is not installed')
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise CommandError(f'{cmd[0]} gave no answer within {timeout}s')
    if proc.returncode not in ok_codes:
        raise CommandError(proc.stderr.strip() or f'exit code {proc.returncode}')
    return proc.stdout

def powershell(script: str, timeout: int = 30) -> list[dict]:
    out = run(['powershell', '-NoProfile', '-NonInteractive', '-Command',
               f'{script} | ConvertTo-Json -Depth 4 -Compress'], timeout)
    if not out.strip():
        return []
    data = json.loads(out)
    return data if isinstance(data, list) else [data]
```

**`run()` line by line**

1. `shutil.which` checks the program exists first, so a missing tool gives a clear message ("ufw is not installed") instead of a Python traceback.
2. The command is a **list**, never a single string with `shell=True`. With a list, each item is passed to the program as-is, so nothing in it can be read as an extra shell command. This prevents command injection, the same class of bug you would look for in someone else's code.
3. `timeout` stops a hung command (Windows Update queries are known to stall) from freezing the whole scan.
4. `ok_codes` exists because some tools use exit codes as answers. For example, `systemctl is-active telnet` exits with 3 when the service is not running. That is a valid answer, not an error, so that check passes `ok_codes=(0, 3)`.

**`powershell()` line by line**

1. `-NoProfile` skips the user's PowerShell profile, so their custom settings cannot change the output. `-NonInteractive` makes PowerShell fail rather than wait for input nobody will type.
2. Piping into `ConvertTo-Json` is the key trick. PowerShell's normal table output is made for humans and changes with window width. JSON is stable and Python reads it with one call.
3. The last line fixes a PowerShell quirk: one result comes back as a single object `{...}`, several come back as a list `[...]`. Always returning a list means every check can loop over the result without checking which case it got.
4. `is_admin()` uses `ctypes.windll` only inside the Windows branch. Importing it at the top of a Linux check would crash, which matters for the registry below.

### checks/base.py: the Check base class

Every check is a small class that inherits from `Check` and fills in one method, `evaluate()`. The base class does everything around it: timing, admin checks, and turning exceptions into ERROR results. This pattern is called a **template method**: the parent class owns the steps and the child class fills in the one step that differs.

```python
import time
from abc import ABC, abstractmethod
from hardenscan.models import CheckResult, Status, Severity
from hardenscan.platform import CommandError

class Check(ABC):
    id: str
    title: str
    severity: Severity
    platforms: tuple[str, ...]
    needs_admin: bool = False
    fix: str = ''

    @abstractmethod
    def evaluate(self) -> tuple[Status, str]:
        ...   # return (status, evidence); raise CommandError if it cannot run

    def run(self, admin: bool) -> CheckResult:
        start = time.perf_counter()
        if self.needs_admin and not admin:
            status, evidence = Status.ERROR, 'needs administrator rights'
        else:
            try:
                status, evidence = self.evaluate()
            except CommandError as e:
                status, evidence = Status.ERROR, str(e)
            except Exception as e:   # a bug in one check must not end the scan
                status, evidence = Status.ERROR, f'unexpected {type(e).__name__}: {e}'
        return CheckResult(
            check_id=self.id, title=self.title, status=status,
            severity=self.severity, evidence=evidence,
            fix=self.fix if status in (Status.FAIL, Status.WARN) else '',
            duration_ms=int((time.perf_counter() - start) * 1000))
```

**What to notice**

- `@abstractmethod` means Python refuses to create a check that forgot to write `evaluate()`. You find the mistake at startup, not halfway through a scan.
- The broad `except Exception` is normally a bad habit. Here it is deliberate: one buggy check should become one ERROR line in the report, not crash a 30-check audit. The error text is kept so you can fix the bug.
- The fix text is only attached to FAIL and WARN results, so the report never tells someone to fix something that already passes.

### registry.py: finding checks automatically

The registry means you never keep a hand-written list of checks. Drop a new file into `checks/linux/`, add `@register` above the class, and the next scan runs it.

```python
import importlib, pkgutil
from hardenscan import checks as checks_pkg

_REGISTRY: dict[str, type] = {}

def register(cls):
    if cls.id in _REGISTRY:
        raise ValueError(f'two checks share the id {cls.id}')
    _REGISTRY[cls.id] = cls
    return cls

def discover(os_name: str) -> list:
    prefix = checks_pkg.__name__ + '.'
    for mod in pkgutil.walk_packages(checks_pkg.__path__, prefix):
        importlib.import_module(mod.name)
    return [cls() for cid, cls in sorted(_REGISTRY.items())
            if os_name in cls.platforms]
```

**How it works, step by step**

1. `register` is a **decorator**: a function that receives the class right after Python defines it. It stores the class in a dictionary keyed by id and hands it back unchanged.
2. A decorator only runs when its file is imported. `discover()` therefore walks every file under `checks/` with `pkgutil.walk_packages` and imports each one, which fires every `@register`.
3. It then keeps only the checks whose `platforms` include the current OS and creates one object of each. Sorting by id keeps report order the same between runs, which makes two reports easy to compare.
4. Because Windows check files are imported on Linux too, they must not import Windows-only modules at the top of the file. Put such imports inside `evaluate()`, or use the helpers in `platform.py`.

### checks/: four worked examples

The other checks follow the same pattern as these four. Each one shows a different difficulty you will meet.

**1. Windows firewall: reading PowerShell output**

```python
from hardenscan.checks.base import Check
from hardenscan.models import Status, Severity
from hardenscan.platform import powershell
from hardenscan.registry import register

@register
class WindowsFirewall(Check):
    id = 'win.firewall'
    title = 'Windows Firewall is on for every profile'
    severity = Severity.HIGH
    platforms = ('windows',)
    fix = 'Run as admin: Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True'

    def evaluate(self):
        profiles = powershell('Get-NetFirewallProfile | Select-Object Name, Enabled')
        off = [p['Name'] for p in profiles if not p['Enabled']]
        if off:
            return Status.FAIL, 'Firewall off for: ' + ', '.join(off)
        return Status.PASS, 'On for: ' + ', '.join(p['Name'] for p in profiles)
```

Windows has three firewall profiles: Domain (work network), Private (home) and Public (cafe wifi). A machine can have one switched off without anyone noticing, so the check looks at each. Depending on the PowerShell version, `Enabled` arrives as `True`/`False` or as `1`/`0`; testing `not p['Enabled']` handles both.

**2. Linux password policy: parsing config files**

```python
def read_settings(path: str) -> dict[str, str]:
    values = {}
    try:
        with open(path) as f:
            for line in f:
                line = line.split('#', 1)[0].strip()   # drop comments
                if not line:
                    continue
                key, sep, val = line.partition('=')
                if not sep:                            # 'KEY value' style
                    key, _, val = line.partition(' ')
                values[key.strip()] = val.strip()
    except FileNotFoundError:
        pass
    return values

@register
class LinuxPasswordPolicy(Check):
    id = 'linux.password_policy'
    title = 'Password length and lockout are enforced'
    severity = Severity.MEDIUM
    platforms = ('linux',)
    fix = ('Set minlen = 14 in /etc/security/pwquality.conf and deny = 5 in '
           '/etc/security/faillock.conf, then enable pam_faillock in PAM.')

    def evaluate(self):
        quality = read_settings('/etc/security/pwquality.conf')
        lockout = read_settings('/etc/security/faillock.conf')
        minlen = int(quality.get('minlen', 8))     # pwquality default
        deny = int(lockout.get('deny', 3))
        pam = open('/etc/pam.d/common-auth').read()
        problems = []
        if minlen < 14:
            problems.append(f'minimum length is {minlen}, should be 14+')
        if 'pam_faillock' not in pam:
            problems.append('account lockout is not enabled in PAM')
        elif not 1 <= deny <= 5:
            problems.append(f'lockout after {deny} failures, should be 1-5')
        if problems:
            return Status.FAIL, '; '.join(problems)
        return Status.PASS, f'minlen {minlen}, lockout after {deny} failures'
```

The hard part is not the parsing but the **"configured but not enforced" trap**. `faillock.conf` can say `deny = 5`, but if the `pam_faillock` module is not switched on in PAM (Linux's login pipeline), that setting does nothing. So the check reads both. Real auditors are caught by this too, so it is worth mentioning in interviews.

`read_settings` copes with both styles Linux config files use (`minlen = 14` and `PASS_MAX_DAYS 90`) and with a missing file, in which case the program's built-in default applies. The path `/etc/pam.d/common-auth` is the Ubuntu/Debian one; Red Hat family systems use `/etc/pam.d/system-auth`.

**3. Open ports: one check for both OSes**

```python
import psutil

RISKY = {21: 'FTP', 23: 'Telnet', 3389: 'RDP', 5900: 'VNC', 3306: 'MySQL', 1433: 'MS SQL'}
REVIEW = {445: 'SMB', 139: 'NetBIOS', 22: 'SSH'}

@register
class OpenPorts(Check):
    id = 'common.open_ports'
    title = 'No risky services listen on the network'
    severity = Severity.HIGH
    platforms = ('windows', 'linux')
    needs_admin = True     # needed to see other users' processes
    fix = 'Stop and disable the service, or block the port in the firewall.'

    def evaluate(self):
        exposed = set()
        for conn in psutil.net_connections(kind='tcp'):
            if conn.status != psutil.CONN_LISTEN:
                continue
            ip = conn.laddr.ip
            if ip.startswith('127.') or ip == '::1':
                continue   # loopback: only this machine can reach it
            exposed.add(conn.laddr.port)
        risky = sorted(p for p in exposed if p in RISKY)
        review = sorted(p for p in exposed if p in REVIEW)
        if risky:
            return Status.FAIL, 'Exposed: ' + ', '.join(f'{p} ({RISKY[p]})' for p in risky)
        if review:
            return Status.WARN, 'Check these are needed: ' + ', '.join(f'{p} ({REVIEW[p]})' for p in review)
        return Status.PASS, f'{len(exposed)} listening ports, none on the risky list'
```

Two ideas make this check accurate. First, a service listening on `127.0.0.1` (loopback) cannot be reached from another computer, so it is ignored. Only ports bound to a real network address are "exposed". Second, ports are split into **FAIL** (almost never needed on a workstation) and **WARN** (often needed, worth a look). SMB on port 445 is open on most Windows machines by default; failing every Windows PC for it would bury the real problems. Deciding where that line sits is false-positive tuning, the same skill as in Project 1.

**4. Linux updates: commands that need context**

```python
import os, time
from hardenscan.platform import run

@register
class LinuxUpdates(Check):
    id = 'linux.updates'
    title = 'Operating system updates are installed'
    severity = Severity.CRITICAL
    platforms = ('linux',)
    fix = 'Run: sudo apt update && sudo apt upgrade'

    def evaluate(self):
        out = run(['apt-get', '-s', 'upgrade'], timeout=120)
        pending = [l for l in out.splitlines() if l.startswith('Inst ')]
        security = [l for l in pending if '-security' in l]
        age_days = (time.time() - os.path.getmtime('/var/lib/apt/lists')) / 86400
        note = f' (package list is {age_days:.0f} days old)' if age_days > 7 else ''
        if security:
            return Status.FAIL, f'{len(security)} security updates pending{note}'
        if pending or note:
            return Status.WARN, f'{len(pending)} other updates pending{note}'
        return Status.PASS, 'No pending updates'
```

`apt-get -s upgrade` is a **simulation**: it prints what it would install (lines starting `Inst`) without changing anything, which keeps the scanner read-only. Lines from the `-security` repository are counted separately because they carry the urgent fixes. The catch is that apt only knows about updates it has downloaded the list for. If `apt update` has not run in weeks, the machine looks fully patched when it is not. Checking the age of `/var/lib/apt/lists` catches that. Windows has the same problem, and its version of this check should read the date of the last successful update search.

### controls.yaml: mapping checks to standards

This file links each check to the standards it supports. Keeping it out of the code means you can update control references when a benchmark is revised without touching Python.

```yaml
win.firewall:
  controls:
    - 'CIS Microsoft Windows 11 Benchmark: Windows Defender Firewall'
    - 'ACSC ISM: host-based firewalls'
linux.updates:
  controls:
    - 'Essential Eight: Patch operating systems'
    - 'CIS Ubuntu Linux Benchmark: ensure updates are installed'
win.local_admins:
  controls:
    - 'Essential Eight: Restrict administrative privileges'
```

Replace the descriptive names with exact recommendation numbers from the benchmark PDFs you download from the CIS website (free with registration) and from the ACSC's Essential Eight Maturity Model. Quoting real control numbers is what makes the report look professional.

### runner.py: running every check

```python
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
import yaml
from hardenscan.models import CheckResult, Status

def run_all(checks, admin, controls_path='controls.yaml', workers=4, timeout=180):
    with open(controls_path) as f:
        controls = yaml.safe_load(f) or {}
    results = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(c.run, admin): c for c in checks}
        for future, check in futures.items():
            try:
                result = future.result(timeout=timeout)
            except FutureTimeout:
                result = CheckResult(check.id, check.title, Status.ERROR,
                                     check.severity, f'no result after {timeout}s')
            result.controls = controls.get(check.id, {}).get('controls', [])
            results.append(result)
    return sorted(results, key=lambda r: r.check_id)
```

**Why threads?** Most checks spend their time waiting for a command such as `apt-get` or PowerShell to answer, not using the CPU. A thread pool lets four checks wait at once, so a 30-check scan takes seconds instead of a minute or more. `pool.submit` starts a check and returns a **future**, a placeholder for a result that is not ready yet; `future.result()` waits for it.

**Why two timeouts?** Python cannot force-stop a thread. The real protection is the per-command timeout in `platform.run()`, which kills the stuck program. The `future.result(timeout=...)` here is a backstop so a check with a bug cannot leave the report waiting forever.

`yaml.safe_load` (not `yaml.load`) matters for a security tool: plain `load` can be tricked into creating arbitrary Python objects from a crafted file.

### scoring.py: the security score

The score is a weighted percentage: important checks count for more, and a half-fixed setting earns half credit.

```latex
\text{score} = 100 \times \frac{\sum_i w_i \, c_i}{\sum_i w_i}
```

Here w is the weight from the check's severity (low 1, medium 2, high 3, critical 5) and c is the credit from its status (pass 1, warn 0.5, fail 0). Checks with status ERROR or SKIP are left out of both sums.

```python
from hardenscan.models import Status, Severity

WEIGHTS = {Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3, Severity.CRITICAL: 5}
CREDIT = {Status.PASS: 1.0, Status.WARN: 0.5, Status.FAIL: 0.0}

def grade(value):
    for floor, letter in ((90, 'A'), (75, 'B'), (60, 'C'), (40, 'D')):
        if value >= floor:
            return letter
    return 'F'

def score(results):
    scored = [r for r in results if r.status in CREDIT]
    if not scored:
        return {'score': None, 'grade': 'N/A', 'coverage': 0.0}
    total = sum(WEIGHTS[r.severity] for r in scored)
    earned = sum(WEIGHTS[r.severity] * CREDIT[r.status] for r in scored)
    value = round(100 * earned / total)
    if any(r.status is Status.FAIL and r.severity is Severity.CRITICAL for r in scored):
        value = min(value, 59)          # a critical failure caps the score
    return {'score': value, 'grade': grade(value),
            'coverage': round(len(scored) / len(results), 2)}
```

**Worked example** with eight checks:

| Check | Severity (weight) | Status (credit) | Points earned |
|---|---|---|---|
| Firewall | high (3) | pass (1) | 3 |
| Defender | high (3) | pass (1) | 3 |
| OS updates | critical (5) | warn (0.5) | 2.5 |
| Password policy | medium (2) | fail (0) | 0 |
| Open ports | high (3) | pass (1) | 3 |
| Admin accounts | high (3) | pass (1) | 3 |
| Disk encryption | high (3) | fail (0) | 0 |
| Legacy services | medium (2) | pass (1) | 2 |
| **Total** | **24** |  | **16.5** |

16.5 out of 24 gives a score of 69/100, grade C.

**Three design choices to explain in an interview**

- **Coverage is reported beside the score.** If half the checks errored, a score of 95 means little. Showing "coverage 50%" next to it keeps the number honest.
- **The critical cap.** Without it, a machine with no security updates for a year could still score 90 by passing many small checks. Capping at 59 when any critical check fails means the score can never look fine while the most important thing is broken.
- **Weights are a judgement call.** Say so openly. Explaining why you weighted updates above password length shows you understand risk, which matters more than the exact numbers.

### report/html.py: the HTML report

```python
import datetime, platform
from pathlib import Path
from jinja2 import Environment, FileSystemLoader
from hardenscan.models import Status, Severity

TEMPLATES = Path(__file__).parent / 'templates'
STATUS_ORDER = {Status.FAIL: 0, Status.WARN: 1, Status.ERROR: 2, Status.PASS: 3, Status.SKIP: 4}
SEVERITY_ORDER = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3}

def render(results, summary, out_dir):
    env = Environment(loader=FileSystemLoader(TEMPLATES), autoescape=True)
    ordered = sorted(results, key=lambda r: (STATUS_ORDER[r.status], SEVERITY_ORDER[r.severity]))
    html = env.get_template('report.html.j2').render(
        host=platform.node(), os=platform.platform(),
        scanned=datetime.datetime.now().strftime('%Y-%m-%d %H:%M'),
        summary=summary, results=ordered)
    stamp = datetime.datetime.now().strftime('%Y%m%d-%H%M')
    path = Path(out_dir) / f'hardenscan-{platform.node()}-{stamp}.html'
    path.write_text(html, encoding='utf-8')
    return path
```

A trimmed version of the template, to show how the data reaches the page:

```html
<h1>{{ host }}: {{ summary.score }}/100 (grade {{ summary.grade }})</h1>
<p>{{ os }} · scanned {{ scanned }} · coverage {{ (summary.coverage * 100) | round | int }}%</p>
{% for r in results %}
<section class='check {{ r.status.value }}'>
  <h2>{{ r.title }} <span class='badge'>{{ r.status.value | upper }}</span></h2>
  <p><strong>Found:</strong> {{ r.evidence }}</p>
  {% if r.fix %}<p><strong>Fix:</strong> {{ r.fix }}</p>{% endif %}
  {% if r.controls %}<p class='controls'>{{ r.controls | join(' · ') }}</p>{% endif %}
</section>
{% endfor %}
```

**Two details that matter**

- **Sorting puts problems first.** Failures come before warnings, and within each, critical before low. The reader sees what to fix first without scrolling past 20 green rows.
- **`autoescape=True` prevents a security hole in your security tool.** The report prints text taken from the machine, such as usernames and service names. Anyone who can create a local account could name it `<script>...</script>`. Without escaping, that script would run in the browser of whoever opens the report: a stored cross-site scripting (XSS) bug. Autoescaping turns `<` into `&lt;` so it shows as text. This is an excellent interview story.

**PDF output (optional):** open the HTML in a browser and print to PDF, or install WeasyPrint and call `HTML(filename=path).write_pdf(...)`. Add a print stylesheet so badges and colours survive printing.

### fixer.py: auto-fix mode (bonus)

Auto-fix is where a hardening tool can do real damage, so this module is built around caution: an allowlist of fixes, a dry run by default, a confirmation for each change, and a re-check afterwards.

```python
from hardenscan.models import Status
from hardenscan.platform import run

# Only settings that are safe to change on a typical workstation.
FIXES = {
    'win.firewall': [
        ['powershell', '-NoProfile', '-Command',
         'Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True']],
    'win.smbv1': [
        ['powershell', '-NoProfile', '-Command',
         'Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force']],
    'linux.firewall': [
        ['ufw', 'allow', 'OpenSSH'],       # first, so enabling cannot lock you out
        ['ufw', '--force', 'enable']],
}

def apply_fixes(results, checks_by_id, admin, dry_run=True, ask=input, log=print):
    outcomes = []
    for r in results:
        if r.status is not Status.FAIL or r.check_id not in FIXES:
            continue
        steps = FIXES[r.check_id]
        log(f'[{r.check_id}] {r.title}: {r.evidence}')
        for cmd in steps:
            log('    will run: ' + ' '.join(cmd))
        if dry_run or ask('    Apply this fix? [y/N] ').strip().lower() != 'y':
            continue
        for cmd in steps:
            run(cmd, timeout=120)
        after = checks_by_id[r.check_id].run(admin)    # prove it worked
        log(f'    now: {after.status.value} ({after.evidence})')
        outcomes.append((r, after))
    return outcomes
```

**How it stays safe**

1. **Allowlist, not "fix everything".** Only checks listed in `FIXES` can be changed. Password policy, accounts and disk encryption are left out on purpose: getting them wrong can lock people out or make data unreadable. The report still explains how to fix them by hand.
2. **Order of steps.** Enabling `ufw` on a Linux server you reach over SSH blocks your own connection unless SSH is allowed first. The fix list puts `allow OpenSSH` before `enable`. Thinking through side effects like this is the skill the bonus exists to show.
3. **Dry run by default.** `python main.py fix` only prints what it would do. Changes happen only with `--apply`, and even then each one asks for `y`.
4. **Verify, don't assume.** After a fix runs, the same check runs again and reports the new status. A fix that "succeeded" but changed nothing shows up immediately.
5. `ask` and `log` are parameters rather than hard-coded `input` and `print`, so tests can pass in fake versions and check the fixer without a keyboard.

### main.py: the command line

```python
import argparse, json, sys
from pathlib import Path
from hardenscan import platform as plat, registry, runner, scoring, fixer
from hardenscan.report import html

def main():
    parser = argparse.ArgumentParser(prog='hardenscan')
    sub = parser.add_subparsers(dest='command', required=True)
    scan = sub.add_parser('scan', help='audit this machine')
    scan.add_argument('--out', default='reports')
    scan.add_argument('--min-score', type=int, default=0)
    fix = sub.add_parser('fix', help='fix failed checks from the allowlist')
    fix.add_argument('--apply', action='store_true')
    args = parser.parse_args()

    os_name = plat.current_os()
    if os_name == 'unsupported':
        sys.exit('Only Windows and Linux are supported.')
    admin = plat.is_admin()
    if not admin:
        print('Warning: not running as admin; some checks will show ERROR.')

    checks = registry.discover(os_name)
    results = runner.run_all(checks, admin)
    summary = scoring.score(results)

    if args.command == 'fix':
        by_id = {c.id: c for c in checks}
        fixer.apply_fixes(results, by_id, admin, dry_run=not args.apply)
        return 0

    Path(args.out).mkdir(exist_ok=True)
    report = html.render(results, summary, args.out)
    (Path(args.out) / 'latest.json').write_text(
        json.dumps({'summary': summary, 'results': [r.to_dict() for r in results]}, indent=2))
    print(f'Score {summary["score"]}/100 ({summary["grade"]}). Report: {report}')
    return 0 if (summary['score'] or 0) >= args.min_score else 1

if __name__ == '__main__':
    sys.exit(main())
```

The exit code is the useful detail. `--min-score 75` makes the program exit with 1 when the machine scores below 75. Scripts, scheduled tasks and CI pipelines read exit codes, so this one flag lets an IT team run HardenScan across many machines and flag only the ones that fall short. The JSON file is there for the same reason: other tools can read it, and two scans can be compared to show improvement.

## Development roadmap

Build in six phases. Each ends with something that runs, so you always have a working version to commit and show. Do Linux and Windows side by side, or finish one OS first if time is short.

### Phase 0: Setup

- [ ] Create the GitHub repo, `.gitignore` (add `reports/` and `.venv/`) and the folder tree above
- [ ] Build two VMs in VirtualBox: Ubuntu 24.04 and Windows 11 (Microsoft offers free evaluation images)
- [ ] Take a snapshot of each VM before changing anything, so you can roll back

**Done when:** `python main.py --help` prints the usage text on both VMs.

### Phase 1: Core and the first check

- [ ] Write `models.py`, `platform.py`, `checks/base.py` and `registry.py`
- [ ] Write one check per OS: the firewall check is the simplest
- [ ] Print results to the terminal as plain lines (no report yet)

**Done when:** turning the firewall off on a VM changes the output from PASS to FAIL.

### Phase 2: The full check set

- [ ] Add the remaining checks from the table in "What we're building", one file each
- [ ] Save the raw command output from each VM into `tests/fixtures/` as you go
- [ ] Write `runner.py` with the thread pool and timeouts

**Done when:** a full scan runs on both VMs and every check returns PASS, WARN, FAIL or a clear ERROR.

### Phase 3: Scoring and standards

- [ ] Write `scoring.py` and test it against the worked example
- [ ] Fill in `controls.yaml` with real CIS and Essential Eight references

**Done when:** the scan prints a score and coverage, and each result lists its controls.

### Phase 4: The report

- [ ] Build `report.html.j2`: summary at the top, problems first, colour badges
- [ ] Write `html.py` and `json_out.py`
- [ ] Test the XSS protection: create a local user named `<b>test</b>` and confirm the report shows the tags as text

**Done when:** the HTML report opens cleanly, reads well on a phone, and prints to PDF.

### Phase 5: Auto-fix and polish (bonus)

- [ ] Write `fixer.py` with the allowlist, dry run and re-check
- [ ] Restore a VM snapshot after each auto-fix test
- [ ] Add `--min-score`, a before-and-after comparison of two JSON files, and the README with screenshots

**Done when:** running `fix --apply` on a deliberately weakened VM raises its score, and a fresh scan proves it.

## Testing and home lab

Test at two levels: unit tests that run anywhere in seconds, and lab tests on real VMs that prove the checks match reality.

**Unit tests with saved output.** A check that calls PowerShell cannot run on your Linux laptop, and you should not have to break a real firewall to test the FAIL path. Instead, save real command output into `tests/fixtures/` and swap it in with pytest's `monkeypatch`:

```python
import json
from hardenscan.checks.windows import firewall
from hardenscan.models import Status

def test_public_profile_off_fails(monkeypatch):
    fake = [{'Name': 'Domain', 'Enabled': 1},
            {'Name': 'Private', 'Enabled': 1},
            {'Name': 'Public', 'Enabled': 0}]
    monkeypatch.setattr(firewall, 'powershell', lambda script: fake)
    status, evidence = firewall.WindowsFirewall().evaluate()
    assert status is Status.FAIL
    assert 'Public' in evidence
```

`monkeypatch.setattr` replaces the `powershell` function inside the firewall module for the length of one test, then puts it back. The check never knows the difference. Write one PASS test and one FAIL test per check, plus tests for `score()` using the worked example (the answer must be 69).

**Lab tests: weaken a VM on purpose.** Take a snapshot, then make each check fail deliberately and confirm the tool notices:

| Check | How to make it fail on purpose |
|---|---|
| Firewall | Windows: `Set-NetFirewallProfile -Profile Public -Enabled False`. Ubuntu: `sudo ufw disable` |
| Legacy services | Ubuntu: `sudo apt install telnetd`. Windows: enable the SMB 1.0 optional feature |
| Open ports | Run `python -m http.server 3306 --bind 0.0.0.0` to imitate an exposed database port |
| Accounts | Windows: `net user guest /active:yes` |
| Password policy | Ubuntu: set `minlen = 6` in `/etc/security/pwquality.conf` |
| Updates | Restore an older snapshot that has not been updated |

Scan, record the score, apply the fixes, scan again and restore the snapshot. Keep the before and after reports: they become your screenshots.

**Run as a normal user once too.** Every check that needs admin should show a clear ERROR, never a crash and never a false FAIL.

## Resume, GitHub and interviews

**README checklist**

- [ ] One-line summary and a screenshot of the HTML report at the top
- [ ] The check table with the standard each maps to
- [ ] Install and run steps for both OSes, including the admin requirement
- [ ] A before-and-after pair from your lab (for example, 41/100 to 88/100)
- [ ] A short "Design decisions" section: read-only by default, ERROR vs FAIL, the critical cap, autoescaping

**Resume bullets** (replace the numbers with your real results)

- *Built a cross-platform Python audit tool that checks Windows and Linux hosts against CIS Benchmarks and the ACSC Essential Eight, scores them out of 100 and produces HTML remediation reports.*
- *Hardened lab VMs from a score of 41 to 88 using the tool's findings and its optional, verified auto-fix mode.*
- *Designed a plugin architecture so new checks are added as a single file, with unit tests using recorded system output.*

**Questions to be ready for**

| Question | What a strong answer covers |
|---|---|
| Why did a check report ERROR instead of FAIL? | Missing evidence is not proof of a problem; mixing them makes the score lie |
| How did you pick the weights? | Risk-based judgement, updates above password length, the critical cap |
| What stops your report being an attack vector? | Jinja2 autoescaping and the malicious username example |
| Why not let auto-fix change everything? | Allowlist, SSH lockout example, dry run, re-check after fixing |
| How would you scan 200 machines? | Exit codes and JSON output, a scheduled task or Intune/Ansible to run it, collect the JSON centrally |
| How do this and your SIEM project connect? | One prevents (hardening), the other detects; a low score tells you which machines to watch most closely |

