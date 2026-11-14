"""HardenScan command-line entry point.

Phase 0 version: only the command shape exists so `python main.py --help` works.
`scan` gets real logic in Phase 1, `fix` in Phase 5.
"""
import argparse
import sys


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='hardenscan',
        description='Audit this machine against security best practice.')
    sub = parser.add_subparsers(dest='command', required=True)

    scan = sub.add_parser('scan', help='run all checks and write a report (read-only)')
    scan.add_argument('--out', default='reports/', help='folder for the report files')
    scan.add_argument('--min-score', type=int, default=None,
                      help='exit with code 1 if the score is below this (Phase 5)')

    fix = sub.add_parser('fix', help='fix failed checks (dry run unless --apply)')
    fix.add_argument('--apply', action='store_true', help='actually make changes')
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    print(f'"{args.command}" is not built yet. See docs/DEVELOPMENT_GUIDE.md.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
