import fs from 'fs';
import ExifReader from 'exifreader';

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
    } catch (exifError) {
      // Non-image or no EXIF; fall through to fs.stat
      console.warn('EXIF parsing failed or not applicable:', exifError.message || exifError);
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