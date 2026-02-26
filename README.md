# StegoSwarm 
**AI-Driven Digital Forensics & Steganalysis Platform**

StegoSwarm is a full-stack, real-time digital forensics platform designed to automate the triage of suspicious files. By combining mathematical file analysis with an AI Agent Swarm and global threat intelligence, it instantly detects extension spoofing, packed malware, and potential steganography.

##  Key Features (v1.0)
* **Byte-Level File Signatures (Magic Bytes):** Extracts the first 4 hexadecimal bytes of an uploaded file to cross-reference against its claimed extension, instantly catching spoofed or masqueraded executables (e.g., an `.exe` disguised as a `.pdf`).
* **Shannon Entropy Calculation:** Computes the mathematical unpredictability of the file's binary data (0.0 to 8.0 bits/byte) to flag densely packed, encrypted, or steganographically altered payloads.
* **Threat Intelligence Integration:** Automatically queries the VirusTotal v3 API to cross-reference the file's SHA-256 hash against 70+ global antivirus engines.
* **AI Agent Swarm Analysis:** Streams a real-time, context-aware forensic report to the UI using Server-Sent Events (SSE). The AI (powered by DeepSeek via OpenRouter) synthesizes the entropy, magic bytes, and VT scores to provide a court-ready security assessment.
* **Exportable HTML Reports:** Generates polished, downloadable forensic reports directly from the AI's markdown output.
* **ASCII String Extraction (Malware Triage):** Extracts and surfaces long printable ASCII strings from the file to quickly reveal hardcoded IPs, URLs, PE artifacts, or tool marks that indicate malware staging or data exfiltration.
* **EXIF/Metadata Stripping (Image Forensics):** Parses and summarizes EXIF and filesystem metadata (timestamps, authors, GPS coordinates) to detect spoofed provenance, tampered images, or privacy-sensitive location leaks.

##  Tech Stack
* **Frontend:** React, Vite, Tailwind CSS
* **Backend:** Node.js, Express.js
* **Architecture:** Server-Sent Events (SSE) for real-time AI UI streaming.

## ⚙️ Local Setup (v1.0 Complete — v2 Coming Soon)
1. Clone the repository:
   ```bash
   git clone [https://github.com/waris206/StegoSwarm.git](https://github.com/waris206/StegoSwarm.git)
   cd StegoSwarm