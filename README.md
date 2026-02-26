# StegoSwarm v1.0

**AI-Driven Digital Forensics & Steganalysis Platform**

StegoSwarm is a full-stack, real-time digital forensics platform designed to automate the triage of suspicious files. By combining mathematical file analysis with an AI Agent Swarm and global threat intelligence, it instantly detects extension spoofing, packed malware, and potential steganography.

---

## Key Features

- **Byte-Level File Signatures (Magic Bytes):** Extracts the first 4 hexadecimal bytes of an uploaded file to cross-reference against its claimed extension, instantly catching spoofed or masqueraded executables (e.g., an `.exe` disguised as a `.pdf`).

- **Shannon Entropy Calculation:** Computes the mathematical unpredictability of the file's binary data (0.0 to 8.0 bits/byte) to flag densely packed, encrypted, or steganographically altered payloads.

- **Threat Intelligence Integration:** Automatically queries the VirusTotal v3 API to cross-reference the file's SHA-256 hash against 70+ global antivirus engines.

- **AI Agent Swarm Analysis:** Streams a real-time, context-aware forensic report to the UI using Server-Sent Events (SSE). The AI (powered by DeepSeek via OpenRouter) synthesizes the entropy, magic bytes, and VT scores to provide a court-ready security assessment.

- **ASCII String Extraction (Malware Triage):** Extracts and surfaces long printable ASCII strings from the file to quickly reveal hardcoded IPs, URLs, PE artifacts, or tool marks that indicate malware staging.

- **EXIF/Metadata Stripping (Image Forensics):** Parses and summarizes EXIF and filesystem metadata to detect spoofed provenance, tampered images, or privacy-sensitive location leaks.

- **Exportable HTML Reports:** Generates polished, downloadable forensic reports directly from the AI's markdown output.

---

## Tech Stack

- **Frontend:** React, Vite, Tailwind CSS v4
- **Backend:** Node.js, Express.js, Multer (Secure memory buffering)
- **APIs:** OpenRouter (DeepSeek-R1), VirusTotal API v3
- **Architecture:** Server-Sent Events (SSE) for real-time streaming

---

## Local Setup

### 1. Clone the Repository

```bash
git clone https://github.com/waris206/StegoSwarm.git
cd StegoSwarm
```

### 2. Install Dependencies

```bash
npm install
```

### 3. Configure Environment Variables

Create a `.env` file in the backend directory and add your API keys to prevent them from being pushed to public version control:

```env
OPENROUTER_API_KEY=your_openrouter_key
VIRUSTOTAL_API_KEY=your_virustotal_key
```

### 4. Start the Servers

Open two separate terminals:

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

## License

This project is licensed under the MIT License.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Author

Developed by [waris206](https://github.com/waris206)
