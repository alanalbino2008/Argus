# Argus // University & Apprenticeship Portfolio Interview Playbook

> **Target 1:** BSc (Hons) in Ethical Hacking – Abertay University  
> **Target 2:** Cyber Security Degree Apprenticeship – Amazon  
> **Project Role:** Lead Developer & Security Architect

---

## Part 1: How to Present "Argus" in Interviews

When interviewing at Abertay University and Amazon, interviewers do not just want to see a generic script or a tutorial clone. They want to hear:
1. **Why** you built it (the gap in existing tools).
2. **How** you solved complex technical challenges (asynchronous concurrency, data graph modeling, rate limiting).
3. **What** foundational security concepts you mastered through the build process.

---

## Part 2: Amazon Leadership Principles (STAR Stories)

Amazon evaluates candidates using behavioral questions framed around their **Leadership Principles**. Here is how to speak directly to them using Argus:

### 1. "Dive Deep" & "Learn and Be Curious"
* **The Question:** *"Tell me about a time you had to learn a technology from scratch to solve a technical challenge."*
* **Situation:** When starting Argus, I only had basic Python skills and initially struggled with slow, sequential network requests when scanning multiple domains and accounts.
* **Task:** I needed to build a high-performance system capable of querying over 60+ platforms and resolving DNS, TLS, and WHOIS protocols simultaneously without freezing the application.
* **Action:** I dove deep into Python's `asyncio` framework and `aiohttp`. I studied how non-blocking I/O event loops, TCP connection pooling, and asynchronous semaphores function under the hood. I implemented connection pooling with an asynchronous queue that automatically rate-limits requests to avoid socket starvation.
* **Result:** Reduced reconnaissance runtime from several minutes down to under 2 seconds for deep multi-vector scans while maintaining clean, modular, and readable code.

### 2. "Ownership" & "Customer Obsession"
* **The Question:** *"Give an example of how you designed a system with the end-user's workflow in mind."*
* **Situation:** Many open-source reconnaissance tools (like standard CLI scanners) dump massive terminal text logs that are hard to correlate, while enterprise tools like Maltego can be heavy and require expensive licenses.
* **Task:** I wanted Argus to deliver an intuitive, frictionless experience for security researchers, analysts, and incident responders.
* **Action:** I engineered an interactive web dashboard using Cytoscape.js and WebSockets. Discovered entities and relationships stream live into an animated physics-driven graph in real time. I also implemented an export system that outputs both JSON and Maltego-compatible CSV formats so analysts can easily transfer data into their existing enterprise workflows.
* **Result:** Analysts can visually trace an attacker's infrastructure or attack surface in seconds, spotting single points of failure (hubs) and pivoting seamlessly across domains, IPs, and usernames.

### 3. "Bias for Action"
* **The Question:** *"Describe a scenario where you faced ambiguity or an error and took initiative to fix it."*
* **Situation:** During early testing, different websites returned varying HTTP error status codes (e.g. 200 with 'Not Found' text, 403 blocks, or 302 redirects) leading to false positives in username enumeration.
* **Task:** Eliminate false positives without slowing down the scan speed.
* **Action:** I designed a signature-based engine (`argus/core/signatures.py`) that classifies rejection rules into status code checks, response body text analysis, and JSON payload inspection.
* **Result:** Achieved over 95% accuracy in cross-platform account identification across 60+ platforms.

---

## Part 3: Abertay University Ethical Hacking Talking Points

Abertay's faculty is world-renowned for practical, hands-on offensive security and defensive engineering. When speaking with professors or writing your UCAS personal statement:

### 1. Passive Reconnaissance vs. Active Exploitation
* Emphasize that Argus focuses on **Passive OSINT**: gathering intelligence without triggering intrusion detection systems (IDS) or violating computer misuse laws.
* Highlight how you used **Certificate Transparency (CT) logs** (`crt.sh`) to find subdomains cryptographically without invasive port scanning or DNS brute forcing.

### 2. Protocol Knowledge You Can Explain with Confidence
* **DNS:** Explain how Argus interrogates A, AAAA, MX, NS, CNAME, and TXT records, specifically parsing **SPF** and **DMARC** to audit domain spoofing vulnerabilities.
* **TLS Handshakes:** Explain how connecting on port 443 allows you to extract **Subject Alternative Names (SANs)**, revealing internal infrastructure that developers thought was hidden.
* **RDAP vs WHOIS:** Explain that Argus uses the modern, RESTful **RDAP (RFC 7480)** protocol rather than legacy port 43 WHOIS, ensuring structured, machine-parsable JSON output.

### 3. Graph Theory & Threat Modeling
* Explain that you didn't just store data in a flat list: you implemented a **Directed Property Graph** (`NetworkX`).
* Discuss how **Degree Centrality** reveals "crown jewel" assets and pivotal infrastructure that attackers would target first.

---

## Part 4: Technical Glossary to Master

Be prepared to explain these concepts effortlessly:

| Term | Interview Definition |
| :--- | :--- |
| **OSINT** | Open Source Intelligence: legal intelligence collected from publicly accessible sources. |
| **Asynchronous I/O** | Single-threaded concurrency where tasks pause during I/O wait times, allowing other tasks to run without blocking the CPU. |
| **Certificate Transparency** | An open framework of append-only public logs where Certificate Authorities must log every issued TLS certificate. |
| **DMARC / SPF** | Email authentication protocols designed to prevent email spoofing and phishing by specifying authorized mail servers. |
| **Directed Property Graph** | A graph where edges have a direction and both nodes and edges can store arbitrary key-value properties. |
| **Rate Limiting** | Controlling the rate of outgoing requests to avoid triggering anti-bot protections or overwhelming destination servers. |
