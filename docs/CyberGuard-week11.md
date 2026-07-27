# Week 11 – Final Presentation & Viva

## Project Title

**CyberGuard – Password Security Toolkit**

---

## Slide Outline & Presentation Flow

### Slide 1: Title & Student Info
* Project Title: CyberGuard – Password Security Toolkit.
* Presenter details, Course details, and Supervisor name.

### Slide 2: Problem Statement
* Common usage of weak passwords and credential recycling.
* Need for a privacy-focused local tool to test strengths without sending raw passwords over the internet.

### Slide 3: Objectives & Scope
* Offline breach checking, real-time strength calculation, password generation.

### Slide 4: System Architecture & Technologies
* Python, Flask, SQLite, Bootstrap 5, ReportLab (PDF Export).

### Slide 5: Demonstration & Screenshots
* User dashboard showing past safety scores.
* Offline password check page & generated secure combinations.

### Slide 6: Security Implementations
* Secure password hashing using PBKDF2/SHA-256 for user logins.
* Prepared statements using SQLAlchemy ORM to prevent SQL Injection.

### Slide 7: Evaluation & Future Scope
* Latency <5ms, offline analysis limits.
* Future support for HaveIBeenPwned API integration via k-Anonymity.

### Slide 8: Conclusion & Q&A
* Summary of findings and opening floor for supervisor questions.

---

## Viva Q&A Preparation Notes

* **Q: Why check password leaks offline?**
  * *A*: Uploading raw passwords to public online checkers is itself a security risk. Checking against a local, curated database of common breaches is safer for user privacy.
* **Q: How is the password strength score calculated?**
  * *A*: By checking criteria like minimum length, inclusion of lowercase/uppercase letters, numbers, special characters, and matching against common patterns.
