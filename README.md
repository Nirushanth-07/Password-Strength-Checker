# Password-Strength-Checker
A security tool that evaluates password strength using **entropy analysis**, **pattern detection** (the approach used by tools like zxcvbn), and checks for historical compromises using the **Have I Been Pwned (HIBP) API**. It comes with a grey terminal-style GUI and a plain CLI mode.


## Features

* Grey terminal UI: a masked password prompt with live analysis as you type. Press Enter to add the breach lookup.

* Composition check: length against the NIST SP 800-63B guidance (8 minimum, 12+ recommended) and character classes (lowercase, uppercase, digits, symbols, unicode).

* Pool entropy: E = L × log<sub>2</sub>(R), the classic brute-force estimate.

* Shannon entropy: measures how varied the characters really are (`aaaaaaaa` has a large pool but almost no variety).

* Pattern detection: finds what crackers try first.
  * Common passwords (blocklist)
  * Dictionary words and names, including leetspeak (`P@ssw0rd`)
  * Sequences (`abc`, `987`)
  * Repeats (`aaaa`, `abcabc`)
  * Keyboard walks (`qwerty`, `1qaz`, `zxcvbn`)
  * Dates and years (`12/05/1998`, `2019`)

* Effective entropy: a pattern-aware estimate. It finds the cheapest way to build the password from patterns plus brute-forced characters, which is how a smart attacker would guess it.

* Crack time estimates for four attack scenarios, from a throttled online attack to an offline GPU attack on a fast hash.

* HIBP integration: uses k-anonymity (with response padding), so the full password or hash never leaves your machine.

* Actionable feedback: warnings and suggestions for improving the password.


## Usage

Requires Python 3.8+ and only the standard library (Tkinter for the GUI).

```bash
python pwd_checker.py             # grey terminal GUI
python pwd_checker.py --cli       # plain terminal mode
python pwd_checker.py --offline   # terminal mode without the HIBP lookup
```

GUI keys: **Enter** runs the breach check, **Ctrl+R** shows or hides the password and matched fragments, **Esc** clears, **Ctrl+Q** quits.


## How It Works

1. Strength tiers

Tiers are based on the effective (pattern-aware) entropy:

    less than 32 bits: Very Weak (Red)

    32 - 55 bits: Weak (Red)

    56 - 80 bits: Medium (Yellow)

    81 - 111 bits: Strong (Green)

    112 bits or more: Excellent (Green)

Hard caps: a password shorter than 8 characters is at most **Weak**. A common or breached password is always **Very Weak**.


2. Secure Breach Checking (K-Anonymity)

To protect user privacy, the tool:

* Hashes the password using SHA-1.

* Sends only the first 5 characters of the hash to the HIBP API.

* Receives a padded list of suffixes and compares them locally to confirm a breach.


## Project Layout

* `pwd_checker.py`: entry point and CLI mode
* `gui.py`: grey terminal-style Tkinter UI
* `strength.py`: analysis engine and report builder (no UI code)
* `wordlists.py`: embedded common-password and dictionary lists


## Security Considerations

* Local Processing: every check except the HIBP lookup runs on your machine.

* Privacy: This tool follows the K-Anonymity protocol; your plain-text password is never stored or transmitted to any third-party server.

* The embedded word lists are small. A password that passes them may still be in a large cracking dictionary, so treat the result as an estimate.


## Contributing

Contributions, issues, and feature requests are welcome! Feel free to check the issues page.




**Disclaimer:** This tool is for educational and security-awareness purposes. Always use a dedicated password manager for sensitive accounts.
