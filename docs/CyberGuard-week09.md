# Week 09 – Evaluation & Analysis

## Project Title

**CyberGuard – Password Security Toolkit**

---

## Evaluation Overview

This week, the CyberGuard application underwent a comprehensive security and performance evaluation to assess the accuracy of the password strength analyzer and the safety of the encryption/hashing configurations.

---

## Security Assessment & Analysis

### 1. Entropy & Analysis Accuracy
* Tested 50 common weak passwords (e.g., `123456`, `password`, `qwerty`). The offline breach detection checker successfully identified all of them as compromised.
* Checked complex password generation parameters. The generated passwords consistently achieve a "Strong" score and have high entropy (>60 bits).

### 2. SQLite Database Hashing
* Verified that user password records are hashed using `werkzeug.security` (PBKDF2 with SHA-256 fallback), preventing plain text exposure in the database.

---

## Performance Metrics

* **Password Evaluation Latency**: <5ms for local checks.
* **PDF Report Generation**: <1.2 seconds using ReportLab buffer processing.
* **Server Overhead**: Under Flask dev server, memory consumption remained stable at ~35MB under multiple local test sessions.

---

## Limitations & Improvements

* **Limitations**: The breach checker is offline-based with a preloaded list. It does not check real-time online breach databases like HaveIBeenPwned (to avoid external API delays and privacy leaks).
* **Future Work**: Implement an online API integration option using k-Anonymity (sending only the first 5 characters of SHA-1 hash) to safely query online breach repositories.
