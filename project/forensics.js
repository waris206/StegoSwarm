import fs from 'fs';
import ExifReader from 'exifreader';
import forge from 'node-forge';

// Calculate the Shannon Entropy of a file (Mathematical randomness)
export function calculateShannonEntropy(filePath) {
  try {
    const buffer = fs.readFileSync(filePath);
    const frequencies = new Array(256).fill(0);
    
    // Count byte frequencies
    for (let i = 0; i < buffer.length; i++) {
      frequencies[buffer[i]]++;
    }
    
    let entropy = 0;
    // Apply the Shannon Entropy formula
    for (let i = 0; i < 256; i++) {
      if (frequencies[i] > 0) {
        const p = frequencies[i] / buffer.length;
        entropy -= p * Math.log2(p);
      }
    }
    return entropy.toFixed(4); // Returns a score between 0 and 8
  } catch (error) {
    console.error("Entropy calculation failed:", error);
    return "Error";
  }
}

// Extract the first four bytes ("magic bytes") of a file as an uppercase hex string
export function extractMagicBytes(filePath) {
  try {
    const fd = fs.openSync(filePath, 'r');
    const buffer = Buffer.alloc(4);
    const bytesRead = fs.readSync(fd, buffer, 0, 4, 0);
    fs.closeSync(fd);

    if (bytesRead <= 0) {
      return 'N/A';
    }

    const slice = buffer.subarray(0, bytesRead);
    return Array.from(slice)
      .map((b) => b.toString(16).padStart(2, '0').toUpperCase())
      .join(' ');
  } catch (error) {
    console.error('Magic bytes extraction failed:', error);
    return 'ERROR';
  }
}

// Extract top ASCII strings (6+ printable chars) from a buffer
export function extractStrings(buffer, maxStrings = 20) {
  try {
    if (!Buffer.isBuffer(buffer)) {
      return [];
    }

    const text = buffer.toString('binary');
    const matches = text.match(/[ -~]{6,}/g) || [];

    // Sort by length (descending) and take top N to avoid payload bloat
    const sorted = matches
      .map((s) => s.trim())
      .filter((s) => s.length >= 6)
      .sort((a, b) => b.length - a.length);

    return sorted.slice(0, maxStrings);
  } catch (error) {
    console.error('String extraction failed:', error);
    return [];
  }
}

// Extract EXIF/metadata when available; fall back to basic fs stats
export async function extractMetadata(filePath) {
  const metadata = {
    source: 'none',
    tags: {}
  };

  try {
    const buffer = fs.readFileSync(filePath);

    try {
      const tags = ExifReader.load(buffer);
      const interesting = {};

      const keysOfInterest = [
        'DateTimeOriginal',
        'CreateDate',
        'ModifyDate',
        'Artist',
        'Copyright',
        'XPAuthor',
        'GPSLatitude',
        'GPSLongitude'
      ];

      for (const key of keysOfInterest) {
        if (tags[key]) {
          interesting[key] = tags[key].description || tags[key].value || String(tags[key]);
        }
      }

      if (Object.keys(interesting).length > 0) {
        metadata.source = 'exif';
        metadata.tags = interesting;
        return metadata;
      }
    } catch (_exifError) {
      // Non-image or no EXIF data — silently fall through to fs.stat
    }

    const stats = fs.statSync(filePath);
    metadata.source = 'fs';
    metadata.tags = {
      birthtime: stats.birthtime?.toISOString?.() || String(stats.birthtime),
      mtime: stats.mtime?.toISOString?.() || String(stats.mtime),
      size: stats.size
    };

    return metadata;
  } catch (error) {
    console.error('Metadata extraction failed:', error);
    return {
      source: 'error',
      tags: {}
    };
  }
}

// ─── Authenticode Digital Signature Extraction ──────────────────────────────

/**
 * Well-known trusted publishers whose signatures act as trust anchors.
 * Extend this list as needed.
 */
const TRUSTED_PUBLISHERS = [
  'microsoft',
  'microsoft corporation',
  'microsoft windows',
  'microsoft code signing pca',
  'google llc',
  'google inc',
  'apple inc',
  'mozilla corporation',
  'adobe inc',
  'adobe systems',
  'intel corporation',
  'nvidia corporation',
  'advanced micro devices',
  'oracle corporation',
  'amazon.com',
  'cloudflare',
  'cisco systems',
  'dell technologies',
  'hp inc',
  'lenovo',
  'vmware',
  'symantec corporation',
  'digicert',
  'verisign',
];

/**
 * Recursively walk a PKCS#7 ContentInfo ASN.1 tree to find the
 * certificates SET — the [0] IMPLICIT tagged element inside SignedData.
 *
 * PKCS#7 ContentInfo structure:
 *   SEQUENCE {
 *     OID (1.2.840.113549.1.7.2 = signedData),
 *     [0] EXPLICIT SEQUENCE (SignedData) {
 *       INTEGER (version),
 *       SET (digestAlgorithms),
 *       SEQUENCE (contentInfo),
 *       [0] IMPLICIT SET OF Certificate (certs),
 *       ...
 *     }
 *   }
 */
function findCertificatesInPkcs7(asn1Root) {
  // asn1Root should be the outer ContentInfo SEQUENCE
  if (!asn1Root || !asn1Root.value || !Array.isArray(asn1Root.value)) return [];

  // ContentInfo → [0] → SignedData (SEQUENCE)
  let signedData = null;
  for (const child of asn1Root.value) {
    // Look for the [0] EXPLICIT (constructed, context-specific, class=0x80)
    if (child.tagClass === forge.asn1.Class.CONTEXT_SPECIFIC && child.constructed) {
      // Inside [0] there is the SignedData SEQUENCE
      if (Array.isArray(child.value) && child.value.length > 0) {
        signedData = child.value[0]; // the SEQUENCE inside [0]
      }
      break;
    }
  }

  if (!signedData || !Array.isArray(signedData.value)) return [];

  // Walk SignedData children to find [0] IMPLICIT (the certificates set)
  const certAsn1List = [];
  for (const child of signedData.value) {
    // Certificates are tagged [0] IMPLICIT — context-specific, constructed, tag=0
    if (
      child.tagClass === forge.asn1.Class.CONTEXT_SPECIFIC &&
      child.constructed &&
      child.type === 0 &&
      Array.isArray(child.value)
    ) {
      // Each child inside is a SEQUENCE (Certificate)
      for (const certNode of child.value) {
        if (certNode.tagClass === forge.asn1.Class.UNIVERSAL && certNode.type === forge.asn1.Type.SEQUENCE) {
          certAsn1List.push(certNode);
        }
      }
      break;
    }
  }

  return certAsn1List;
}

/**
 * Extract the Authenticode digital signature from a PE file buffer.
 *
 * Reads the PE Certificate Table (Data Directory #4), locates the
 * WIN_CERTIFICATE structure, parses the embedded PKCS#7 SignedData
 * via node-forge, and returns the signer's Common Name (CN).
 *
 * @param {Buffer} buffer  Raw file bytes
 * @returns {{
 *   signed: boolean,
 *   publisher: string|null,
 *   issuer: string|null,
 *   validFrom: string|null,
 *   validTo: string|null,
 *   trusted: boolean,
 *   status: string
 * }}
 */
export function checkSignature(buffer) {
  const result = {
    signed: false,
    publisher: null,
    issuer: null,
    validFrom: null,
    validTo: null,
    trusted: false,
    status: 'Unsigned / No Certificate',
  };

  try {
    if (!Buffer.isBuffer(buffer) || buffer.length < 64) {
      return result;
    }

    // ── 1. Verify MZ header ────────────────────────────────────────────
    if (buffer.readUInt16LE(0) !== 0x5A4D) {
      result.status = 'Not a PE file';
      return result;
    }

    // ── 2. PE header offset ────────────────────────────────────────────
    const peOffset = buffer.readUInt32LE(0x3C);
    if (peOffset + 24 > buffer.length) return result;

    // ── 3. Verify PE signature ─────────────────────────────────────────
    if (buffer.readUInt32LE(peOffset) !== 0x00004550) return result;

    // ── 4. Optional header magic → PE32 or PE32+ ──────────────────────
    const optOff = peOffset + 4 + 20; // COFF header is 20 bytes
    if (optOff + 2 > buffer.length) return result;
    const optMagic = buffer.readUInt16LE(optOff);
    const is64 = optMagic === 0x020B;

    // ── 5. Data Directory #4 (Certificate Table / Security Directory) ─
    // Data Directory starts at optOff + 96 (PE32) or optOff + 112 (PE32+)
    const dataDirBase = optOff + (is64 ? 112 : 96);
    // Entry #4 → offset = dataDirBase + 4 * 8 = dataDirBase + 32
    const certTableEntryOff = dataDirBase + 32;
    if (certTableEntryOff + 8 > buffer.length) return result;

    const certTableOffset = buffer.readUInt32LE(certTableEntryOff);     // raw file offset (NOT RVA)
    const certTableSize   = buffer.readUInt32LE(certTableEntryOff + 4);

    if (certTableOffset === 0 || certTableSize === 0) {
      return result; // No certificate table
    }

    if (certTableOffset + certTableSize > buffer.length) {
      result.status = 'Certificate table truncated';
      return result;
    }

    // ── 6. WIN_CERTIFICATE structure ──────────────────────────────────
    // dwLength (4) | wRevision (2) | wCertificateType (2) | bCertificate[]
    const winCertLen  = buffer.readUInt32LE(certTableOffset);
    const winCertType = buffer.readUInt16LE(certTableOffset + 6);

    if (winCertType !== 0x0002) {
      // 0x0002 = WIN_CERT_TYPE_PKCS_SIGNED_DATA
      result.status = 'Unknown certificate type (not PKCS#7)';
      return result;
    }

    const pkcs7Start = certTableOffset + 8;
    const pkcs7Len   = winCertLen - 8;
    if (pkcs7Start + pkcs7Len > buffer.length || pkcs7Len < 16) {
      result.status = 'PKCS#7 data truncated';
      return result;
    }

    // ── 7. Parse PKCS#7 SignedData ASN.1 manually ───────────────────
    const pkcs7Der = buffer.slice(pkcs7Start, pkcs7Start + pkcs7Len);

    // PE Authenticode certs are padded to 8-byte alignment;
    // trim trailing zeros that confuse DER parsing.
    let trimmedLen = pkcs7Der.length;
    while (trimmedLen > 0 && pkcs7Der[trimmedLen - 1] === 0) trimmedLen--;
    const cleanDer = pkcs7Der.slice(0, trimmedLen || pkcs7Der.length);

    let asn1;
    try {
      asn1 = forge.asn1.fromDer(forge.util.createBuffer(cleanDer), { strict: false });
    } catch (_) {
      asn1 = forge.asn1.fromDer(forge.util.createBuffer(pkcs7Der), { strict: false });
    }

    // ── 7b. Walk ASN.1 tree to extract certificates ───────────────────
    // node-forge's pkcs7.messageFromAsn1 only supports ContentType=data,
    // not Authenticode signedData. We manually traverse instead.
    //
    // PKCS#7 ContentInfo: SEQUENCE { OID, [0] EXPLICIT SignedData }
    // SignedData: SEQUENCE { version, digestAlgos, contentInfo, [0] certs, ... }
    const certsDer = findCertificatesInPkcs7(asn1);
    if (!certsDer || certsDer.length === 0) {
      result.status = 'PKCS#7 present but no certificates embedded';
      return result;
    }

    // Parse each certificate found
    const certs = [];
    for (const certAsn1 of certsDer) {
      try {
        certs.push(forge.pki.certificateFromAsn1(certAsn1));
      } catch (_) { /* skip malformed certs */ }
    }

    if (certs.length === 0) {
      result.status = 'PKCS#7 present but certificates could not be parsed';
      return result;
    }

    // Find the signer cert — prefer cert with Code Signing EKU, else first
    let signerCert = certs[0];
    for (const cert of certs) {
      try {
        const ekuExt = cert.getExtension('extKeyUsage');
        if (ekuExt && ekuExt.codeSigning) {
          signerCert = cert;
          break;
        }
      } catch (_) { /* skip */ }
    }

    // Extract fields
    const subjectCN = signerCert.subject.getField('CN');
    const subjectO  = signerCert.subject.getField('O');
    const issuerCN  = signerCert.issuer.getField('CN');
    const issuerO   = signerCert.issuer.getField('O');

    const publisher = subjectCN?.value || subjectO?.value || 'Unknown Publisher';
    const issuer    = issuerCN?.value || issuerO?.value || 'Unknown Issuer';

    result.signed    = true;
    result.publisher = publisher;
    result.issuer    = issuer;
    result.validFrom = signerCert.validity.notBefore?.toISOString?.() || null;
    result.validTo   = signerCert.validity.notAfter?.toISOString?.() || null;

    // ── 8. Trust evaluation ───────────────────────────────────────────
    const pubLower = publisher.toLowerCase();
    const isTrusted = TRUSTED_PUBLISHERS.some((tp) => pubLower.includes(tp));
    result.trusted = isTrusted;

    result.status = isTrusted
      ? `Signed & Trusted: ${publisher}`
      : `Signed: ${publisher} (not in trusted vendor list)`;

    return result;
  } catch (error) {
    // If parsing fails entirely, return unsigned status with detail
    console.error('Authenticode extraction error:', error.message || error);
    result.status = 'Signature parse error';
    return result;
  }
}