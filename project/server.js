import 'dotenv/config';
import express from 'express';
import multer from 'multer';
import cors from 'cors';
import crypto from 'crypto';
import fs from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { marked } from 'marked';
import { calculateShannonEntropy, extractMagicBytes, extractStrings, extractMetadata } from './forensics.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = express();
const PORT = 5000;

// Load environment variables
const OPENROUTER_API_KEY = process.env.OPENROUTER_API_KEY;
const SERVER_URL = process.env.SERVER_URL || `http://localhost:${PORT}`;
const VIRUSTOTAL_API_KEY = process.env.VIRUSTOTAL_API_KEY;

/**
 * Generate styled HTML report from Markdown content
 * @param {string} markdownContent - The Markdown content to convert
 * @returns {string} Complete HTML document string
 */
function generateHTMLReport(markdownContent) {
  const htmlContent = marked.parse(markdownContent);
  
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Forensic Analysis Report</title>
  <style>
    body {
      font-family: Arial, sans-serif;
      max-width: 800px;
      margin: 2rem auto;
      padding: 0 1rem;
      line-height: 1.6;
      color: #333;
      background-color: #fff;
    }
    h1, h2, h3, h4, h5, h6 {
      color: #222;
      margin-top: 1.5em;
      margin-bottom: 0.5em;
    }
    h1 {
      border-bottom: 2px solid #333;
      padding-bottom: 0.3em;
    }
    h2 {
      border-bottom: 1px solid #ccc;
      padding-bottom: 0.3em;
    }
    p {
      margin: 1em 0;
    }
    code {
      background-color: #f4f4f4;
      padding: 0.2em 0.4em;
      border-radius: 3px;
      font-family: 'Courier New', monospace;
      font-size: 0.9em;
    }
    pre {
      background-color: #f4f4f4;
      padding: 1em;
      border-radius: 5px;
      overflow-x: auto;
      border: 1px solid #ddd;
    }
    pre code {
      background-color: transparent;
      padding: 0;
    }
    table {
      border-collapse: collapse;
      width: 100%;
      margin: 1em 0;
      border: 1px solid #ddd;
    }
    th, td {
      border: 1px solid #ddd;
      padding: 0.75em;
      text-align: left;
    }
    th {
      background-color: #f2f2f2;
      font-weight: bold;
    }
    tr:nth-child(even) {
      background-color: #f9f9f9;
    }
    ul, ol {
      margin: 1em 0;
      padding-left: 2em;
    }
    li {
      margin: 0.5em 0;
    }
    blockquote {
      border-left: 4px solid #ddd;
      margin: 1em 0;
      padding-left: 1em;
      color: #666;
    }
    hr {
      border: none;
      border-top: 1px solid #ddd;
      margin: 2em 0;
    }
  </style>
</head>
<body>
${htmlContent}
</body>
</html>`;
}

/**
 * Stream AI analysis from OpenRouter Free Models API
 * @param {Object} fileData - File metadata (name, size, sha256, entropy, magicBytes, claimedExtension, strings, metadata)
 * @param {Object} streamResponse - SSE response object to write to
 */
async function streamForensicAnalysis(fileData, streamResponse) {
  let fullReport = '';

  const closeStream = (message) => {
    try {
      if (message) streamResponse.write(message);
      streamResponse.write(`data: [DONE]\n\n`);
      streamResponse.end();
    } catch (e) {
      console.error('Error closing SSE stream:', e);
      try { streamResponse.end(); } catch (_) {}
    }
  };

  if (!OPENROUTER_API_KEY) {
    streamResponse.write(`data: Error: OPENROUTER_API_KEY not configured. Please set it in your .env file.\n\n`);
    closeStream();
    return;
  }

  const systemPrompt = `You are a Lead Forensic Investigator analyzing a file for signs of steganography, malware, or suspicious activity.

File Details:
- Name: ${fileData.name}
- Size: ${fileData.size} bytes
- SHA-256 Hash: ${fileData.sha256}
- Shannon Entropy: ${fileData.entropy} bits/byte
- Claimed Extension: ${fileData.claimedExtension || 'N/A'}
- Magic Bytes (first 4 bytes, hex): ${fileData.magicBytes || 'N/A'}
- VirusTotal Intelligence: Malicious detections: ${fileData.virusTotal?.malicious ?? 0}, Undetected/Clean: ${fileData.virusTotal?.undetected ?? 0}
-
- Extracted ASCII Strings (sample): ${Array.isArray(fileData.strings) && fileData.strings.length > 0 ? fileData.strings.slice(0, 10).join(' | ') : 'None extracted or not available'}
- File Metadata Snapshot: ${
  fileData.metadata && fileData.metadata.tags && Object.keys(fileData.metadata.tags).length > 0
    ? Object.entries(fileData.metadata.tags)
        .slice(0, 5)
        .map(([k, v]) => `${k}: ${v}`)
        .join(' | ')
    : 'No EXIF/metadata tags discovered'
}

Analyze this forensic data and provide your findings in real-time. Act as an expert investigator explaining:
1. What the entropy score indicates about the file's randomness
2. Potential security concerns or anomalies
3. Recommendations for further investigation

Contextualize the Shannon Entropy score based on the file extension. Note that formats like .pdf, .zip, .png, and .jpg natively use heavy compression (like FlateDecode), which naturally results in high entropy (7.2 - 7.9 bits/byte). Do NOT immediately flag high entropy as malicious for these file types. Acknowledge that this is standard compression unless there are other supporting anomalies. Conversely, if an uncompressed file (.txt, .csv) has an entropy above 6.0, aggressively flag it as potentially encrypted or packed.

You are also given the file's claimed extension and its extracted magic bytes (first four bytes of the file, as a hex signature). Cross-reference these aggressively:
- Treat the magic bytes as ground truth for the actual file type.
- Compare the magic bytes against well-known signatures (for example, PDF files typically begin with 25 50 44 46, PNG with 89 50 4E 47, ZIP with 50 4B 03 04, JPEG with FF D8 FF, etc.).
- If the claimed extension does NOT match what the magic bytes strongly suggest, classify this as a HIGH-RISK EXTENSION SPOOFING attempt and clearly call it out.
- If the magic bytes are missing, incomplete, or ambiguous, explicitly state that the file type cannot be confidently verified from the signature and adjust your risk assessment accordingly.

You are also provided with aggregated VirusTotal threat intelligence for this hash. Treat this as a primary signal:
- Clearly state how many antivirus engines flagged the file as malicious, and how many reported it as undetected/clean.
- If any engines (malicious > 0) detect the file as malicious, treat this as a strong indicator of compromise and weigh it heavily in your final risk classification and recommendations.
- If all engines report the file as clean/undetected (malicious = 0), you may downgrade—but not automatically dismiss—other weaker anomalies, and explain why.

In addition, you are given:
- Extracted printable ASCII strings of length 6+ from the file, and
- A summarized view of the file's EXIF/metadata (when available).

Use these aggressively for static analysis:
- Examine strings for hardcoded IP addresses, domains/URLs, file paths, user names, registry keys, or PE artifacts (e.g., the classic \"This program cannot be run in DOS mode\" marker, import table names, or suspicious DLLs).
- Correlate any suspicious strings with the file type and entropy; for example, PE-style strings inside a document or image are highly anomalous.
- Inspect metadata for spoofed or inconsistent authors, tools, or timestamps (e.g., creation dates far in the future/past, authors that do not match the organization, or camera/software tags that don't align with the claimed file workflow).
- If strings or metadata strongly indicate malicious tooling, staging paths, or exfil domains, clearly elevate the risk classification and call out the indicators of compromise.

Respond in a professional, investigative tone as if you're reporting to a team.`;

  try {
    const response = await fetch('https://openrouter.ai/api/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${OPENROUTER_API_KEY}`,
        'Content-Type': 'application/json',
        'HTTP-Referer': SERVER_URL,
        'X-Title': 'StegoSwarm Forensics'
      },
      body: JSON.stringify({
        model: 'openrouter/free',
        messages: [
          { role: 'system', content: systemPrompt },
          { role: 'user', content: 'Begin your forensic analysis of this file.' }
        ],
        stream: true
      })
    });

    if (!response.ok) {
      let errorPayload;
      try {
        const errorText = await response.text();
        errorPayload = errorText ? JSON.parse(errorText) : { status: response.status };
      } catch (_) {
        errorPayload = { status: response.status };
      }
      console.error('OpenRouter API error:', response.status, errorPayload);
      streamResponse.write(`data: System Error: Agent Swarm upstream connection failed. Please try again later.\n\n`);
      closeStream();
      return;
    }

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';

    try {
      while (true) {
        const { done, value } = await reader.read();

        if (done) {
          const uploadsDir = join(__dirname, 'uploads');
          if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });
          const reportFilename = `report-${fileData.sha256.slice(0, 12)}.html`;
          const reportPath = join(uploadsDir, reportFilename);
          try {
            const htmlReport = generateHTMLReport(fullReport);
            fs.writeFileSync(reportPath, htmlReport, 'utf8');
            const downloadUrl = `${SERVER_URL}/uploads/${reportFilename}`;
            streamResponse.write(`event: fileReady\ndata: ${JSON.stringify({ url: downloadUrl })}\n\n`);
          } catch (writeErr) {
            console.error('Report write error:', writeErr);
            streamResponse.write(`data: System Error: Could not save report file: ${writeErr.message}\n\n`);
          }
          closeStream();
          break;
        }

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n');
        buffer = lines.pop() || '';

        for (const line of lines) {
          if (!line.startsWith('data: ')) continue;
          const data = line.slice(6);
          if (data === '[DONE]') {
            const uploadsDir = join(__dirname, 'uploads');
            if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });
            const reportFilename = `report-${fileData.sha256.slice(0, 12)}.html`;
            const reportPath = join(uploadsDir, reportFilename);
            try {
              const htmlReport = generateHTMLReport(fullReport);
              fs.writeFileSync(reportPath, htmlReport, 'utf8');
              const downloadUrl = `${SERVER_URL}/uploads/${reportFilename}`;
              streamResponse.write(`event: fileReady\ndata: ${JSON.stringify({ url: downloadUrl })}\n\n`);
            } catch (writeErr) {
              console.error('Report write error:', writeErr);
              streamResponse.write(`data: System Error: Could not save report file: ${writeErr.message}\n\n`);
            }
            closeStream();
            return;
          }
          try {
            const json = JSON.parse(data);
            const content = json.choices?.[0]?.delta?.content;
            if (content) {
              fullReport += content;
              streamResponse.write(`data: ${content}\n\n`);
            }
          } catch (_) {
            continue;
          }
        }
      }
    } catch (streamErr) {
      console.error('OpenRouter stream read error:', streamErr);
      streamResponse.write(`data: System Error: Agent Swarm upstream connection failed. Please try again later.\n\n`);
      closeStream();
    }
  } catch (error) {
    console.error('OpenRouter streaming error:', error);
    streamResponse.write(`data: System Error: Agent Swarm upstream connection failed. Please try again later.\n\n`);
    closeStream();
  }
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = join(__dirname, 'uploads');
    if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname)
});

const upload = multer({ storage: storage });

app.use(cors());
app.use(express.json());
app.use('/uploads', express.static(join(__dirname, 'uploads')));

// Global variable to hold our active SSE connection to the React GUI
let activeStreamResponse = null;

// The SSE Endpoint that React will connect to for live updates
app.get('/api/swarm-stream', (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  activeStreamResponse = res;
});

function calculateFileHash(filePath) {
  return new Promise((resolve) => {
    const hash = crypto.createHash('sha256');
    const stream = fs.createReadStream(filePath);
    stream.on('data', (data) => hash.update(data));
    stream.on('end', () => resolve(hash.digest('hex')));
  });
}

/**
 * Check a file hash against the VirusTotal v3 API.
 * Returns an object with malicious and undetected counts, or a safe default.
 * @param {string} sha256Hash
 * @returns {Promise<{ malicious: number, undetected: number, note?: string }>}
 */
async function checkVirusTotal(sha256Hash) {
  const safeDefault = {
    malicious: 0,
    undetected: 0,
    note: 'File not found in VirusTotal database or lookup unavailable'
  };

  if (!VIRUSTOTAL_API_KEY) {
    console.warn('VIRUSTOTAL_API_KEY not configured; skipping VirusTotal lookup.');
    return safeDefault;
  }

  try {
    const response = await fetch(`https://www.virustotal.com/api/v3/files/${sha256Hash}`, {
      method: 'GET',
      headers: {
        'x-apikey': VIRUSTOTAL_API_KEY
      }
    });

    if (response.status === 404) {
      return {
        malicious: 0,
        undetected: 0,
        note: '0 detections / File not found in VirusTotal database'
      };
    }

    if (!response.ok) {
      console.error('VirusTotal API error:', response.status);
      return safeDefault;
    }

    const payload = await response.json();
    const stats = payload?.data?.attributes?.last_analysis_stats || {};
    const malicious = typeof stats.malicious === 'number' ? stats.malicious : 0;
    const undetected = typeof stats.undetected === 'number' ? stats.undetected : 0;

    return {
      malicious,
      undetected
    };
  } catch (error) {
    console.error('VirusTotal lookup failed:', error);
    return safeDefault;
  }
}

// File upload endpoint
app.post('/upload', upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

  const filePath = req.file.path;
  const sha256Hash = await calculateFileHash(filePath);
  const fileBuffer = fs.readFileSync(filePath);
  const entropyScore = calculateShannonEntropy(filePath);
  const magicBytes = extractMagicBytes(filePath);
  const extractedStrings = extractStrings(fileBuffer);
  const fileMetadata = await extractMetadata(filePath);
  const vtStats = await checkVirusTotal(sha256Hash);
  const claimedExtension = (() => {
    const parts = req.file.originalname.split('.');
    if (parts.length < 2) return '';
    return parts.pop().toLowerCase();
  })();

  // 1. Send immediate data back to GUI
  res.json({
    success: true,
    file: {
      name: req.file.originalname,
      size: req.file.size,
      sha256: sha256Hash,
      entropy: entropyScore,
      magicBytes: magicBytes,
      virusTotal: vtStats,
      extractedStrings,
      fileMetadata
    }
  });

  // 2. Stream real AI analysis from OpenRouter DeepSeek API
  if (activeStreamResponse) {
    const fileData = {
      name: req.file.originalname,
      size: req.file.size,
      sha256: sha256Hash,
      entropy: entropyScore,
      magicBytes: magicBytes,
      claimedExtension,
      virusTotal: vtStats,
      strings: extractedStrings,
      metadata: fileMetadata
    };
    
    // Start streaming forensic analysis
    streamForensicAnalysis(fileData, activeStreamResponse).catch(error => {
      console.error('Forensic analysis streaming error:', error);
      if (activeStreamResponse) {
        try {
          activeStreamResponse.write(`data: System Error: Agent Swarm upstream connection failed. Please try again later.\n\n`);
          activeStreamResponse.write(`data: [DONE]\n\n`);
          activeStreamResponse.end();
        } catch (e) {
          console.error('Error closing SSE on analysis failure:', e);
        }
      }
    });
  }
});

app.listen(PORT, () => console.log(`StegoSwarm API Server running on http://localhost:${PORT}`));