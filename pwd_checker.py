"""Password Strength Checker v2.0 entry point.

    python pwd_checker.py            grey terminal-style GUI
    python pwd_checker.py --cli      plain terminal mode
    python pwd_checker.py --offline  skip the Have I Been Pwned lookup (CLI)
"""

import argparse
import getpass
import os
import sys

import strength

RESET = "\033[0m"
ANSI = {
    "dim": "\033[90m",
    "head": "\033[1;37m",
    "title": "\033[30;47m",
    "good": "\033[92m",
    "warn": "\033[33m",
    "bad": "\033[91m",
}


def run_cli(offline):
    if os.name == "nt":
        os.system("")  # enables ANSI colour escapes in the Windows console

    print(strength.BANNER)
    try:
        password = getpass.getpass("Enter The Password (hidden): ")
    except (KeyboardInterrupt, EOFError):
        print()
        return 1
    if not password:
        print("No password entered.")
        return 1

    analysis = strength.analyze(password)
    breach = None
    if not offline:
        print("Checking Have I Been Pwned ...")
        breach = strength.check_breach(password)
    print()

    report = strength.build_report(analysis, breach, reveal=False, breach_hint="skipped (--offline)")
    for line in report:
        print("".join(f"{ANSI[style]}{text}{RESET}" if style else text for text, style in line))
    return 0


def main():
    parser = argparse.ArgumentParser(description="Check password strength.")
    parser.add_argument("--cli", action="store_true", help="run in the plain terminal instead of the GUI")
    parser.add_argument("--offline", action="store_true", help="skip the Have I Been Pwned lookup (CLI mode)")
    args = parser.parse_args()

    if args.cli or args.offline:
        return run_cli(args.offline)

    try:
        import gui
    except ImportError as e:  # Python built without tkinter
        print(f"GUI unavailable ({e}); falling back to terminal mode.\n")
        return run_cli(offline=False)
    try:
        gui.main()
    except gui.tk.TclError as e:  # e.g. no display available
        print(f"GUI unavailable ({e}); falling back to terminal mode.\n")
        return run_cli(offline=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
