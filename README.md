
# LogSentinel

LogSentinel is a Python-based security telemetry and log analysis engine designed to detect suspicious web activity through behavioral heuristics and structured event analysis.

---

# Why I Built This

While studying cybersecurity, I realized most students learn attacks theoretically but rarely understand how defenders actually detect suspicious behavior from real telemetry.

After reading about incidents like the Colonial Pipeline ransomware attack and seeing how modern SOC teams rely heavily on logs, I wanted to understand the defensive side of cybersecurity more deeply.

Instead of building another basic CRUD project, I decided to build a system that processes real web server logs and tries to identify attacker behavior such as:

* vulnerability scanning
* brute-force login attempts
* suspicious large downloads

The goal was not to create a perfect SIEM, but to learn how security telemetry pipelines and detection engineering actually work internally.

---

# How It Works 

Web servers generate logs every time someone visits a website.

These logs contain information like:

* visitor IP address
* request type
* visited URL
* status codes
* response size

LogSentinel reads those logs line-by-line and converts them into structured security events.

After processing the logs, the system analyzes behavior patterns such as:

* too many failed requests
* repeated login attempts
* unusually large file downloads

If suspicious behavior crosses certain thresholds, the system generates alerts.

In simple terms:

```text id="6n9"
Raw Logs
→ Organized Events
→ Behavior Analysis
→ Security Alerts
```

---

# Hardest Problem I Solved

The hardest challenge was designing the telemetry pipeline correctly.

At first, I only stored suspicious events like 404 errors. Later I realized this architecture prevented future detections from working properly because other analytics required full event visibility.

This taught me an important engineering lesson:
good detection systems depend heavily on how telemetry is modeled and stored.

Another difficult part was handling time-window analysis for scanner detection. Counting events alone created false positives, so I added timestamp-based logic to detect bursts of suspicious activity within short periods.

---

# What Surprised Me Most

I was surprised by how difficult log parsing and telemetry normalization actually are.

At first glance, server logs look simple. But once I started building detections, I discovered many hidden problems:

* malformed log entries
* inconsistent data
* detection false positives
* regex complexity
* architecture decisions affecting future analytics

I also realized cybersecurity engineering is much more about handling messy real-world data and operational tradeoffs than simply writing attack scripts.

---

# Current Detection Capabilities

## Vulnerability Scanner Detection

Detects excessive 404 errors from the same IP within a short time window.

Possible indicators:

* directory enumeration
* automated vulnerability scanning
* reconnaissance activity

---

## Credential Brute-Force Detection

Detects repeated POST requests targeting login endpoints.

Possible indicators:

* password spraying
* brute-force attacks
* credential stuffing

---

## Large File Transfer Detection

Flags unusually large downloads that may indicate possible data exfiltration attempts.

Possible indicators:

* abnormal outbound transfers
* suspicious downloads
* potential data leakage

---

# Project Architecture

```text id="0ua"
Access Logs
     ↓
Parser Engine
     ↓
Normalized Telemetry Events
     ↓
IP-Based Aggregation
     ↓
Detection Engine
     ↓
Alert System
```

---

# Technologies Used

* Python
* Regex
* defaultdict
* datetime
* Structured telemetry modeling

---

# What’s Next

The next major improvement is separating the pipeline into cleaner modular stages.

Currently, parsing, analytics, and alerting are still tightly connected. I want to redesign the architecture so that:

* parser handles only telemetry extraction
* detector handles only analytics
* reporter handles alert generation

Long-term, I also want to add:

* SQLite event storage
* real-time monitoring
* threat scoring
* cloud log ingestion
* entropy-based anomaly detection

---

# Disclaimer

LogSentinel is an educational cybersecurity engineering project built for learning detection engineering, telemetry analysis, and security automation concepts.

It is not intended to replace enterprise SIEM or SOC platforms.
