import express from 'express';
import multer from 'multer';
import cors from 'cors';
import crypto from 'crypto';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import fs from 'fs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = express();
const PORT = 3001;

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = join(__dirname, 'uploads');
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + '-' + file.originalname);
  }
});

const upload = multer({
  storage: storage,
  limits: { fileSize: 50 * 1024 * 1024 } // 50MB limit
});

// Middleware
app.use(cors());
app.use(express.json());

// Calculate SHA-256 hash of a file
function calculateFileHash(filePath) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256');
    const stream = fs.createReadStream(filePath);

    stream.on('data', (data) => hash.update(data));
    stream.on('end', () => resolve(hash.digest('hex')));
    stream.on('error', (err) => reject(err));
  });
}

// File upload endpoint
app.post('/api/upload', upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const filePath = req.file.path;
    const sha256Hash = await calculateFileHash(filePath);

    res.json({
      success: true,
      file: {
        name: req.file.originalname,
        size: req.file.size,
        sha256: sha256Hash,
        uploadedAt: new Date().toISOString()
      }
    });
  } catch (error) {
    console.error('Upload error:', error);
    res.status(500).json({ error: 'Failed to process file' });
  }
});

// Mock agent log stream endpoint
app.get('/api/agent-logs/:fileId', (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');

  const agentLogs = [
    { agent: 1, action: 'Initializing file analysis...', delay: 500 },
    { agent: 2, action: 'Extracting file metadata...', delay: 1000 },
    { agent: 1, action: 'Calculating entropy signature...', delay: 1500 },
    { agent: 3, action: 'Running LSB steganography detection...', delay: 2000 },
    { agent: 2, action: 'Analyzing file structure integrity...', delay: 2500 },
    { agent: 4, action: 'Scanning for known malware signatures...', delay: 3000 },
    { agent: 3, action: 'Performing deep packet inspection...', delay: 3500 },
    { agent: 1, action: 'Cross-referencing with threat intelligence...', delay: 4000 },
    { agent: 5, action: 'Generating forensic report...', delay: 4500 },
    { agent: 5, action: 'Analysis complete. Report ready.', delay: 5000 }
  ];

  let index = 0;

  const sendLog = () => {
    if (index < agentLogs.length) {
      const log = agentLogs[index];
      res.write(`data: ${JSON.stringify(log)}\n\n`);
      index++;
      setTimeout(sendLog, 500);
    } else {
      res.write('data: [DONE]\n\n');
      res.end();
    }
  };

  sendLog();
});

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.listen(PORT, () => {
  console.log(`StegoSwarm API Server running on http://localhost:${PORT}`);
});
