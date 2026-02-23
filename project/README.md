# StegoSwarm v1.0

A cutting-edge Digital Forensics and Steganalysis platform that uses an autonomous swarm of AI agents to analyze files for hidden data and malicious payloads.

## Features

- **Drag-and-Drop File Upload**: Intuitive interface for quick file submission
- **SHA-256 Hash Generation**: Ensures forensic integrity of uploaded files
- **Live Agent Terminal**: Real-time streaming of AI agent analysis activities
- **Investigation Timeline**: Visual tracking of analysis stages
- **Cybersecurity-Focused UI**: Dark mode interface with neon accents

## Tech Stack

- **Frontend**: React, Tailwind CSS v4, Lucide Icons
- **Backend**: Node.js, Express.js
- **File Handling**: Multer for secure file uploads

## Getting Started

### Running the Application

1. **Start the Backend Server** (in one terminal):
   ```bash
   npm run server
   ```
   The API server will run on `http://localhost:3001`

2. **Start the Frontend Development Server** (in another terminal):
   ```bash
   npm run dev
   ```
   The frontend will run on `http://localhost:5173`

3. Open your browser and navigate to the frontend URL

### Building for Production

```bash
npm run build
```

## Project Structure

```
├── server/
│   ├── index.js          # Express API server
│   └── uploads/          # Temporary file storage
├── src/
│   ├── components/       # React components
│   │   ├── Navbar.jsx
│   │   ├── FileUploadZone.jsx
│   │   ├── FileDetailsCard.jsx
│   │   ├── LiveTerminal.jsx
│   │   └── InvestigationTimeline.jsx
│   ├── App.jsx           # Main application
│   └── index.css         # Global styles
└── package.json
```

## API Endpoints

- `POST /api/upload` - Upload a file and receive SHA-256 hash
- `GET /api/agent-logs/:fileId` - Server-Sent Events stream for agent activity
- `GET /api/health` - Health check endpoint

## Features in Detail

### File Upload
Supports files up to 50MB with automatic SHA-256 hash generation for forensic verification.

### AI Agent Simulation
The platform simulates a swarm of 5 AI agents performing various analysis tasks:
- Agent 1: File initialization and entropy analysis
- Agent 2: Metadata extraction and structure analysis
- Agent 3: LSB steganography detection
- Agent 4: Malware signature scanning
- Agent 5: Report generation

### Investigation Timeline
Tracks the analysis through 5 stages:
1. Upload
2. Hashing
3. Metadata Analysis
4. Steganography Check
5. Report Generation

## Development Notes

This is v1.0 - a foundation for the platform. Future enhancements may include:
- Real AI/ML-powered steganalysis
- Database integration for historical analysis
- Advanced threat intelligence integration
- Multi-file batch processing
- Detailed forensic reports with downloadable artifacts

## License

MIT
