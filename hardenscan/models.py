"""Status, Severity and CheckResult: the data shapes every check returns."""

from dataclasses import asdict, dataclass, field
from enum import Enum


class Status(str, Enum):
    """The verdict of one check."""

    PASS = 'pass'
    WARN = 'warn'     # not ideal, but not a clear failure
    FAIL = 'fail'
    ERROR = 'error'   # the check could not run (no permission, tool missing)
    SKIP = 'skip'     # the check does not apply to this machine


class Severity(str, Enum):
    """How much a failed check matters."""

    LOW = 'low'
    MEDIUM = 'medium'
    HIGH = 'high'
    CRITICAL = 'critical'


# Used to sort the report (most serious first). Scoring weights live in scoring.py.
SEVERITY_RANK = {
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


@dataclass
class CheckResult:
    """The outcome of running one check on this machine."""

    check_id: str              # e.g. 'win.firewall', 'linux.password_policy'
    title: str                 # human-readable, e.g. 'Firewall is on for all profiles'
    status: Status
    severity: Severity
    evidence: str              # what we actually saw, e.g. 'Public profile: off'
    fix: str = ''              # shown in the report for FAIL and WARN only
    controls: list[str] = field(default_factory=list)  # CIS / Essential Eight refs
    duration_ms: int = 0       # how long the check took

    def to_dict(self) -> dict:
        """Plain dictionary (no enum objects) ready for JSON."""
        d = asdict(self)
        d['status'] = self.status.value
        d['severity'] = self.severity.value
        return d