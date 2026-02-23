import 'dotenv/config';
import express from 'express';
import multer from 'multer';
import cors from 'cors';
import crypto from 'crypto';
import fs from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { marked } from 'marked';
import { calculateShannonEntropy } from './forensics.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = express();
const PORT = 5000;

// Load environment variables
const OPENROUTER_API_KEY = process.env.OPENROUTER_API_KEY;

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
 * @param {Object} fileData - File metadata (name, size, sha256, entropy)
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

Analyze this forensic data and provide your findings in real-time. Act as an expert investigator explaining:
1. What the entropy score indicates about the file's randomness
2. Potential security concerns or anomalies
3. Recommendations for further investigation

Contextualize the Shannon Entropy score based on the file extension. Note that formats like .pdf, .zip, .png, and .jpg natively use heavy compression (like FlateDecode), which naturally results in high entropy (7.2 - 7.9 bits/byte). Do NOT immediately flag high entropy as malicious for these file types. Acknowledge that this is standard compression unless there are other supporting anomalies. Conversely, if an uncompressed file (.txt, .csv) has an entropy above 6.0, aggressively flag it as potentially encrypted or packed.

Respond in a professional, investigative tone as if you're reporting to a team.`;

  try {
    const response = await fetch('https://openrouter.ai/api/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${OPENROUTER_API_KEY}`,
        'Content-Type': 'application/json',
        'HTTP-Referer': 'http://localhost:5000',
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
            const downloadUrl = `http://localhost:5000/uploads/${reportFilename}`;
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
              const downloadUrl = `http://localhost:5000/uploads/${reportFilename}`;
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

// File upload endpoint
app.post('/upload', upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

  const filePath = req.file.path;
  const sha256Hash = await calculateFileHash(filePath);
  const entropyScore = calculateShannonEntropy(filePath);

  // 1. Send immediate data back to GUI
  res.json({
    success: true,
    file: { name: req.file.originalname, size: req.file.size, sha256: sha256Hash, entropy: entropyScore }
  });

  // 2. Stream real AI analysis from OpenRouter DeepSeek API
  if (activeStreamResponse) {
    const fileData = {
      name: req.file.originalname,
      size: req.file.size,
      sha256: sha256Hash,
      entropy: entropyScore
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