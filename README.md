# Password-Strength-Checker
A security tool designed to evaluate password strength using **Shannon Entropy** and check for historical compromises using the **Have I Been Pwned (HIBP) API**.


## Features

* Entropy Analysis: Calculates the mathematical randomness of a password based on character pool size (R) and length (L).

* HIBP Integration: Uses the K-Anonymity model to securely check if a password has appeared in known data breaches without ever sending the full password over the network.

* Visual Strength Tiers: Categorizes passwords from "Very Weak" to "Excellent" based on bit-count thresholds.


## How It Works
1. Entropy Calculation

The tool identifies the character pool (R) used (lowercase, uppercase, digits, and symbols) and applies the formula:
E=L×log<sub>2</sub>​(R)

Passwords are then split into the following tiers:

    less than 32 bits: Very Weak (Red)

    32 - 55 bits: Weak (Red)

    56 - 80 bits: Medium (Yellow)

    81 - 112 bits: Strong (Green)

    more than 112 bits: Excellent (Green)


2. Secure Breach Checking (K-Anonymity)

To protect user privacy, the tool:

* Hashes the password using SHA-1.

* Sends only the first 5 characters of the hash to the HIBP API.

* Receives a list of suffixes and compares them locally to confirm a breach.


## Tech Stack

* Language: Python

* Hashing: SHA-1

* API: Have I Been Pwned (Pwned Passwords)

* Environment: Linux / Terminal-based


## Security Considerations

* Local Processing: Entropy calculations are performed entirely on the client side.

* Privacy: This tool follows the K-Anonymity protocol; your plain-text password is never stored or transmitted to any third-party server.


## Contributing

Contributions, issues, and feature requests are welcome! Feel free to check the issues page.




**Disclaimer:** This tool is for educational and security-awareness purposes. Always use a dedicated password manager for sensitive accounts.