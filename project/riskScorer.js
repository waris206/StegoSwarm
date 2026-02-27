/**
 * StegoSwarm v2 — Hard Risk Scorer
 *
 * Deterministic, pre-AI numeric risk scoring.
 * Runs BEFORE any LLM call so that AI agents receive a BINDING
 * risk classification they must explain, not invent.
 *
 * Score bands:
 *   < 20  → LOW
 *   20–60 → SUSPICIOUS
 *   > 60  → HIGH
 */

// ─── Magic-byte → expected file type mapping ────────────────────────────────
const MAGIC_MAP = [
  { hex: '4D5A',         type: 'exe' },   // MZ → PE executable
  { hex: '25504446',     type: 'pdf' },   // %PDF
  { hex: '504B0304',     type: 'zip' },   // PK.. (zip / docx / xlsx / apk)
  { hex: '504B0506',     type: 'zip' },
  { hex: '504B0708',     type: 'zip' },
  { hex: '89504E47',     type: 'png' },   // .PNG
  { hex: 'FFD8FF',       type: 'jpg' },   // JPEG
  { hex: '47494638',     type: 'gif' },   // GIF8
  { hex: '52494646',     type: 'avi' },   // RIFF (avi / wav / webp)
  { hex: '1F8B08',       type: 'gz' },    // gzip
  { hex: '377ABCAF271C', type: '7z' },    // 7-Zip
  { hex: '7F454C46',     type: 'elf' },   // ELF binary
  { hex: 'CAFEBABE',     type: 'class' }, // Java class / Mach-O fat
  { hex: 'D0CF11E0',     type: 'doc' },   // OLE2 (doc / xls / ppt)
];

// Extension alias groups — extensions that share the same underlying format
const EXT_ALIASES = {
  exe:  ['exe', 'dll', 'sys', 'scr', 'ocx', 'cpl'],
  zip:  ['zip', 'docx', 'xlsx', 'pptx', 'odt', 'jar', 'apk', 'xpi'],
  jpg:  ['jpg', 'jpeg', 'jpe', 'jfif'],
  doc:  ['doc', 'xls', 'ppt', 'msi'],
  gz:   ['gz', 'tgz'],
  avi:  ['avi', 'wav', 'webp'],
};

/**
 * Map raw magic-bytes hex string to a canonical file type.
 */
function magicToType(magicHex) {
  if (!magicHex) return null;
  const clean = magicHex.replace(/\s+/g, '').toUpperCase();
  for (const entry of MAGIC_MAP) {
    if (clean.startsWith(entry.hex)) return entry.type;
  }
  return null;
}

/**
 * Check whether claimed extension and magic-byte type are compatible.
 */
function extensionsMatch(claimedExt, magicType) {
  if (!claimedExt || !magicType) return true; // can't determine → no penalty
  const ext = claimedExt.toLowerCase();
  if (ext === magicType) return true;

  // Check alias groups
  for (const aliases of Object.values(EXT_ALIASES)) {
    if (aliases.includes(ext) && aliases.includes(magicType)) return true;
  }
  return false;
}

// ─── IAT API Classification ─────────────────────────────────────────────────

const HIGH_RISK_APIS = new Set([
  'VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread',
  'NtCreateThreadEx', 'RtlCreateUserThread',
  'SetWindowsHookExA', 'SetWindowsHookExW',
  'CryptEncrypt',
  'InternetOpenA', 'InternetOpenW', 'InternetConnectA', 'InternetConnectW',
  'HttpSendRequestA', 'HttpSendRequestW',
  'URLDownloadToFileA', 'URLDownloadToFileW',
]);

const ANTI_ANALYSIS_APIS = new Set([
  'IsDebuggerPresent', 'CheckRemoteDebuggerPresent',
  'NtQueryInformationProcess', 'GetTickCount',
]);

const INJECTION_TRIAD = ['VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread'];

/**
 * Classify a PE's IAT imports and return risk signals.
 */
function classifyImports(peAnalysis) {
  const result = {
    classification: 'BENIGN',
    hasInjectionTriad: false,
    highRiskApis: [],
    antiAnalysisApis: [],
  };

  if (!peAnalysis?.isPE || !Array.isArray(peAnalysis.imports)) return result;

  const allFunctions = new Set();
  for (const imp of peAnalysis.imports) {
    for (const fn of imp.functions) {
      allFunctions.add(fn);
    }
  }

  // Check injection triad (all three must be present)
  result.hasInjectionTriad = INJECTION_TRIAD.every(api => allFunctions.has(api));

  // Collect high-risk and anti-analysis hits
  for (const api of allFunctions) {
    if (HIGH_RISK_APIS.has(api)) result.highRiskApis.push(api);
    if (ANTI_ANALYSIS_APIS.has(api)) result.antiAnalysisApis.push(api);
  }

  if (result.hasInjectionTriad) {
    result.classification = 'CRITICAL — Injection Triad Present';
  } else if (result.highRiskApis.length > 0) {
    result.classification = 'HIGH-RISK APIs detected';
  } else if (result.antiAnalysisApis.length > 0) {
    result.classification = 'ANTI-ANALYSIS APIs detected';
  }

  return result;
}

// ─── Compressed / high-entropy formats ───────────────────────────────────────
const HIGH_ENTROPY_FORMATS = new Set([
  'zip', 'gz', '7z', 'png', 'jpg', 'gif', 'pdf', 'avi',
  'mp3', 'mp4', 'webp', 'webm', 'flac', 'ogg',
]);

// ─── Main Scoring Function ──────────────────────────────────────────────────

/**
 * Calculate a deterministic hard risk score for a file.
 *
 * @param {object} params
 * @param {string} params.claimedExtension  e.g. 'pdf'
 * @param {string} params.magicBytes        e.g. '4D 5A 90 00'
 * @param {string|number} params.entropy    Shannon entropy (0-8)
 * @param {{ malicious: number, undetected: number }} params.virusTotal
 * @param {{ signed: boolean, trusted: boolean }} params.digitalSignature
 * @param {object} params.peAnalysis        from peParser.js
 * @param {Array}  params.yaraHits          from yaraEngine.js
 *
 * @returns {{ score: number, label: string, breakdown: Array, iatClassification: string }}
 */
export function calculateRiskScore({
  claimedExtension = '',
  magicBytes = '',
  entropy = 0,
  virusTotal = {},
  digitalSignature = {},
  peAnalysis = {},
  yaraHits = [],
}) {
  let score = 0;
  const breakdown = [];
  const entropyVal = parseFloat(entropy) || 0;
  const magicType = magicToType(magicBytes);

  // ── 1. Extension Mismatch ───────────────────────────────────────────────
  if (claimedExtension && magicType && !extensionsMatch(claimedExtension, magicType)) {
    score += 30;
    breakdown.push({
      signal: 'EXTENSION_MISMATCH',
      delta: +30,
      reason: `Claimed .${claimedExtension} but magic bytes indicate ${magicType}`,
    });
  }

  // ── 2. Digital Signature ────────────────────────────────────────────────
  if (digitalSignature?.signed && digitalSignature?.trusted) {
    score -= 50;
    breakdown.push({
      signal: 'TRUSTED_SIGNATURE',
      delta: -50,
      reason: `Signed by trusted vendor: ${digitalSignature.publisher}`,
    });
  } else if (digitalSignature?.signed && !digitalSignature?.trusted) {
    score -= 10;
    breakdown.push({
      signal: 'UNTRUSTED_SIGNATURE',
      delta: -10,
      reason: `Signed by: ${digitalSignature.publisher} (not in trusted list)`,
    });
  } else if (peAnalysis?.isPE) {
    score += 20;
    breakdown.push({
      signal: 'UNSIGNED_PE',
      delta: +20,
      reason: 'PE executable with no digital signature',
    });
  }

  // ── 3. VirusTotal ──────────────────────────────────────────────────────
  const vtMal = virusTotal?.malicious ?? 0;
  const vtClean = virusTotal?.undetected ?? 0;

  if (vtMal === 0 && vtClean > 0) {
    score -= 20;
    breakdown.push({
      signal: 'VT_CLEAN',
      delta: -20,
      reason: `0 malicious detections, ${vtClean} clean`,
    });
  } else if (vtMal > 0 && vtMal <= 3) {
    score += 20;
    breakdown.push({
      signal: 'VT_LOW_DETECT',
      delta: +20,
      reason: `${vtMal} malicious detections (low)`,
    });
  } else if (vtMal > 3 && vtMal <= 10) {
    score += 40;
    breakdown.push({
      signal: 'VT_MED_DETECT',
      delta: +40,
      reason: `${vtMal} malicious detections (medium)`,
    });
  } else if (vtMal > 10) {
    score += 60;
    breakdown.push({
      signal: 'VT_HIGH_DETECT',
      delta: +60,
      reason: `${vtMal} malicious detections (high)`,
    });
  }

  // ── 4. Entropy ─────────────────────────────────────────────────────────
  const isCompressedFormat = HIGH_ENTROPY_FORMATS.has(claimedExtension?.toLowerCase())
    || HIGH_ENTROPY_FORMATS.has(magicType);

  if (entropyVal >= 7.2 && !isCompressedFormat) {
    score += 15;
    breakdown.push({
      signal: 'HIGH_ENTROPY',
      delta: +15,
      reason: `Entropy ${entropyVal} in non-compressed format — possible packing/encryption`,
    });
  } else if (entropyVal <= 3.5 && peAnalysis?.isPE) {
    score -= 5;
    breakdown.push({
      signal: 'LOW_PE_ENTROPY',
      delta: -5,
      reason: `Low entropy (${entropyVal}) — not packed or encrypted`,
    });
  }

  // ── 5. YARA Hits ───────────────────────────────────────────────────────
  if (Array.isArray(yaraHits) && yaraHits.length > 0) {
    const maxSeverity = yaraHits.reduce((max, h) => {
      const sev = (h.severity || '').toLowerCase();
      if (sev === 'critical') return 'critical';
      if (sev === 'high' && max !== 'critical') return 'high';
      if (sev === 'medium' && max === 'none') return 'medium';
      return max;
    }, 'none');

    const yaraDeltas = { critical: 35, high: 25, medium: 15 };
    const delta = yaraDeltas[maxSeverity] || 10;
    score += delta;
    breakdown.push({
      signal: 'YARA_HIT',
      delta: +delta,
      reason: `YARA: ${yaraHits.length} rule(s) triggered (max severity: ${maxSeverity})`,
    });
  } else {
    score -= 10;
    breakdown.push({
      signal: 'YARA_CLEAN',
      delta: -10,
      reason: 'No YARA-Lite rules triggered',
    });
  }

  // ── 6. IAT Classification ──────────────────────────────────────────────
  const iat = classifyImports(peAnalysis);

  if (iat.hasInjectionTriad) {
    score += 40;
    breakdown.push({
      signal: 'INJECTION_TRIAD',
      delta: +40,
      reason: 'Process injection triad: VirtualAllocEx + WriteProcessMemory + CreateRemoteThread',
    });
  } else if (iat.highRiskApis.length > 0) {
    score += 15;
    breakdown.push({
      signal: 'HIGH_RISK_APIS',
      delta: +15,
      reason: `High-risk APIs: ${iat.highRiskApis.join(', ')}`,
    });
  }

  if (iat.antiAnalysisApis.length > 0) {
    score += 10;
    breakdown.push({
      signal: 'ANTI_ANALYSIS',
      delta: +10,
      reason: `Anti-analysis APIs: ${iat.antiAnalysisApis.join(', ')}`,
    });
  }

  // ── Final classification ───────────────────────────────────────────────
  let label;
  if (score < 20) label = 'LOW';
  else if (score <= 60) label = 'SUSPICIOUS';
  else label = 'HIGH';

  return {
    score,
    label,
    breakdown,
    iatClassification: iat.classification,
  };
}
