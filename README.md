# StegoSwarm v2.0

**AI-Driven Digital Forensics & Steganalysis Platform**

StegoSwarm is a full-stack, real-time digital forensics platform that automates file triage by combining deterministic risk scoring, a multi-agent AI swarm, YARA-Lite signature scanning, PE binary analysis, Authenticode signature verification, and global threat intelligence — all streamed live to a React dashboard.

---

## What's New in v2

| Feature | Description |
|---|---|
| **Hard Risk Scorer** | Deterministic, pre-AI numeric scoring engine (`riskScorer.js`). Computes a 0–100 score based on extension mismatch, entropy, digital signature trust, VirusTotal detections, YARA hits, and IAT classification — before any AI runs. Bands: `<20 LOW`, `20–60 SUSPICIOUS`, `>60 HIGH`. |
| **3-Agent Swarm (Deep Swarm Inspection)** | Agent 1 (Static Analyst) → Agent 2 (Threat OSINT) → Agent 3 (Lead Investigator). Each agent is grounded by the Hard Risk Score and cannot override or escalate it. |
| **PE Binary Parser** | Pure-JS portable executable parser (`peParser.js`) — extracts architecture (x86/x64), sections, entry point, and full Import Address Table (IAT). Zero native dependencies. |
| **YARA-Lite Engine** | Regex and byte-pattern matching engine (`yaraEngine.js`) with 5 rule families: Crypto Wallet, Ransomware, C2/Network, Suspicious PE Imports, and Obfuscation. Includes `validate` callbacks for false-positive prevention (e.g., PDF checksums vs real BTC addresses). |
| **Authenticode Signature Verification** | Manual ASN.1 PKCS#7 walker using `node-forge` — extracts publisher, issuer, validity dates, and trust status. Trusted vendor signatures act as a Trust Anchor that reduces risk. |
| **Risk Score UI Card** | Frontend displays a prominent risk badge with numeric score, color-coded classification (green/yellow/red), and full signal-by-signal breakdown with +/− deltas. |
| **429 Retry with Backoff** | Agent API calls automatically retry up to 3 times on HTTP 429 (rate limit) with exponential backoff and `Retry-After` header support. |
| **Security Hardening** | `helmet` security headers, `express-rate-limit` (30 req/15min), CORS restricted to dev origins, 100 MB upload limit, filename sanitization, auto-cleanup of uploaded files, static file access guard (reports only). |
| **False-Positive Prevention** | BTC regex requires non-hex Base58 chars (rejects MD5/SHA hashes). PE imports rule requires the full injection triad (VirtualAllocEx + WriteProcessMemory + CreateRemoteThread). AI prompts are score-grounded and explicitly told not to flag benign APIs. |

---

## Key Features

- **Byte-Level File Signatures (Magic Bytes):** Extracts the first 4 hex bytes and cross-references against the claimed extension to catch spoofed executables (e.g., `.exe` disguised as `.pdf`).

- **Shannon Entropy Calculation:** Computes binary data unpredictability (0.0–8.0 bits/byte). Contextualised per file type — compressed formats (.zip, .png, .pdf) naturally have high entropy.

- **Threat Intelligence (VirusTotal v3):** Queries 70+ global AV engines against the file's SHA-256 hash with timeout handling and graceful fallback notes.

- **AI Agent Swarm Analysis:** Streams real-time forensic reports via SSE. Each agent is bound by the deterministic Hard Risk Score — AI explains the score, it doesn't invent it.

- **PE Import Address Table (IAT) Analysis:** Parses and clusters Windows API imports into BENIGN / HIGH-RISK / ANTI-ANALYSIS categories. Only the injection triad triggers YARA alerts.

- **YARA-Lite Signature Scanning:** 5 rule families with strict validation callbacks to prevent false positives on hex hashes, PDF internals, and benign system APIs.

- **Digital Signature Trust Anchoring:** Authenticode verification acts as the strongest trust signal — trusted vendor signatures with 0 VT detections = safe, no escalation.

- **ASCII String Extraction:** Surfaces printable strings (6+ chars) to reveal hardcoded IPs, URLs, PE artifacts, or tool marks indicating malware staging.

- **EXIF/Metadata Analysis:** Parses filesystem and EXIF metadata to detect spoofed provenance, tampered images, or privacy-sensitive leaks.

- **Exportable HTML Reports:** Generates polished, downloadable forensic reports from the full 3-agent swarm analysis.

- **Hard Risk Score Display:** Frontend card shows the numeric score, classification badge (LOW/SUSPICIOUS/HIGH), and a full breakdown of every scoring signal with +/− deltas.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    React + Vite Frontend                │
│  FileUploadZone → FileDetailsCard (Risk Score + IAT)    │
│  LiveTerminal (SSE stream) → InvestigationTimeline      │
└────────────────────────┬────────────────────────────────┘
                         │ POST /upload + GET /stream
┌────────────────────────▼────────────────────────────────┐
│                   Express Backend (port 5000)           │
│                                                         │
│  1. SHA-256 + Entropy + Magic Bytes + Strings + EXIF    │
│  2. PE Parser → IAT extraction                          │
│  3. Authenticode Digital Signature (node-forge ASN.1)   │
│  4. VirusTotal v3 lookup                                │
│  5. YARA-Lite scan (5 rules, validate callbacks)        │
│  6. ═══ Hard Risk Scorer (deterministic, pre-AI) ═══   │
│  7. JSON response → frontend renders Risk Score card    │
│  8. SSE stream → Agent 1 → Agent 2 → Agent 3 (AI)     │
│  9. HTML report generation + download link              │
└─────────────────────────────────────────────────────────┘
```

---

## Tech Stack

- **Frontend:** React 19, Vite 7, Tailwind CSS v4
- **Backend:** Node.js, Express 5, Multer
- **AI:** OpenRouter API (free tier)
- **Threat Intel:** VirusTotal API v3
- **Crypto:** node-forge (ASN.1 / PKCS#7 parsing)
- **Security:** helmet, express-rate-limit, CORS
- **Architecture:** Server-Sent Events (SSE) for real-time streaming

---

## Local Setup

### 1. Clone the Repository

```bash
git clone https://github.com/waris206/StegoSwarm.git
cd StegoSwarm/project
```

### 2. Install Dependencies

```bash
npm install
```

### 3. Configure Environment Variables

Create a `.env` file in the `project/` directory:

```env
OPENROUTER_API_KEY=your_openrouter_key
VIRUSTOTAL_API_KEY=your_virustotal_key
```

### 4. Start the Servers

**Terminal 1 (Backend API):**

```bash
node server.js
```

Server runs on `http://localhost:5000`

**Terminal 2 (Frontend UI):**

```bash
npm run dev
```

Frontend runs on `http://localhost:5173`

---

## Risk Scoring Logic

| Signal | Delta | Condition |
|---|---|---|
| Extension mismatch | +30 | Magic bytes don't match claimed extension |
| Trusted digital signature | −50 | Valid Authenticode from known vendor |
| Untrusted signature | −10 | Signed but by unknown publisher |
| Unsigned PE | +20 | PE file with no digital signature |
| VT clean (0 malicious) | −20 | All engines report clean |
| VT low detections (1–3) | +20 | Few engines flag it |
| VT medium (4–10) | +40 | Multiple engines flag it |
| VT high (>10) | +60 | Widespread detection |
| High entropy (non-compressed) | +15 | >7.2 bits/byte on non-archive types |
| YARA critical hit | +35 | Critical severity rule triggered |
| YARA high hit | +25 | High severity rule triggered |
| No YARA hits | −10 | Passed all automated signature screening |
| Injection triad in IAT | +40 | VirtualAllocEx + WriteProcessMemory + CreateRemoteThread |

**Bands:** Score < 20 → **LOW** | 20–60 → **SUSPICIOUS** | > 60 → **HIGH**

---

## License

This project is licensed under the MIT License.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Author

Developed by [waris206](https://github.com/waris206)
