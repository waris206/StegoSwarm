/**
 * peParser.js — Pure-JS Windows PE Import Address Table (IAT) Parser
 *
 * Parses PE32 and PE32+ (64-bit) executables to extract the Import Directory
 * Table, revealing which DLLs and API functions the binary intends to call.
 *
 * Zero external dependencies.  Every RVA dereference and read is
 * bounds-checked so that malformed / weaponised headers cannot crash
 * the Node.js process.
 *
 * Reference: Microsoft PE/COFF Specification, Rev 11+
 */

// ─── Safety helpers ─────────────────────────────────────────────────────────

function safeReadUInt16LE(buf, offset) {
  if (offset < 0 || offset + 2 > buf.length) return null;
  return buf.readUInt16LE(offset);
}

function safeReadUInt32LE(buf, offset) {
  if (offset < 0 || offset + 4 > buf.length) return null;
  return buf.readUInt32LE(offset);
}

/**
 * Read a null-terminated ASCII string starting at `offset`.
 * Returns '' if the offset is out of bounds.
 */
function readAsciiZ(buf, offset, maxLen = 256) {
  if (offset < 0 || offset >= buf.length) return '';
  let end = offset;
  const limit = Math.min(offset + maxLen, buf.length);
  while (end < limit && buf[end] !== 0) end++;
  return buf.toString('ascii', offset, end);
}

// ─── RVA ↔ file-offset conversion ───────────────────────────────────────────

/**
 * Build a section table from the PE header.
 * Each entry: { name, virtualAddress, virtualSize, rawOffset, rawSize }
 */
function parseSections(buf, sectionHeadersOffset, count) {
  const sections = [];
  for (let i = 0; i < count; i++) {
    const off = sectionHeadersOffset + i * 40;
    if (off + 40 > buf.length) break;

    sections.push({
      name: buf.toString('ascii', off, off + 8).replace(/\0/g, ''),
      virtualSize: safeReadUInt32LE(buf, off + 8)  ?? 0,
      virtualAddress: safeReadUInt32LE(buf, off + 12) ?? 0,
      rawSize: safeReadUInt32LE(buf, off + 16) ?? 0,
      rawOffset: safeReadUInt32LE(buf, off + 20) ?? 0,
    });
  }
  return sections;
}

/**
 * Convert an RVA to a raw file offset using the section table.
 * Returns -1 if the RVA cannot be resolved.
 */
function rvaToOffset(rva, sections) {
  for (const s of sections) {
    if (rva >= s.virtualAddress && rva < s.virtualAddress + s.rawSize) {
      return rva - s.virtualAddress + s.rawOffset;
    }
  }
  return -1;
}

// ─── Main parser ────────────────────────────────────────────────────────────

/**
 * Parse a PE file buffer and extract the Import Address Table (IAT).
 *
 * @param {Buffer} buffer  Raw file bytes
 * @returns {{
 *   isPE: boolean,
 *   arch: string|null,
 *   imports: Array<{ dll: string, functions: string[] }>,
 *   error: string|null
 * }}
 */
export function parseImportTable(buffer) {
  const result = { isPE: false, arch: null, imports: [], error: null };

  try {
    if (!Buffer.isBuffer(buffer) || buffer.length < 64) {
      result.error = 'Buffer too small or not a Buffer';
      return result;
    }

    // ── 1. DOS Header — verify MZ signature ──────────────────────────────
    const mz = safeReadUInt16LE(buffer, 0);
    if (mz !== 0x5A4D) {                       // 'MZ'
      result.error = 'Not a PE file (missing MZ signature)';
      return result;
    }

    // ── 2. e_lfanew → PE header offset ───────────────────────────────────
    const peOffset = safeReadUInt32LE(buffer, 0x3C);
    if (peOffset === null || peOffset + 24 > buffer.length) {
      result.error = 'Invalid e_lfanew (PE offset out of bounds)';
      return result;
    }

    // ── 3. PE Signature ──────────────────────────────────────────────────
    const peSig = safeReadUInt32LE(buffer, peOffset);
    if (peSig !== 0x00004550) {                // 'PE\0\0'
      result.error = 'Invalid PE signature';
      return result;
    }
    result.isPE = true;

    // ── 4. COFF File Header (20 bytes at peOffset+4) ────────────────────
    const coffOff = peOffset + 4;
    const machine          = safeReadUInt16LE(buffer, coffOff)      ?? 0;
    const numberOfSections = safeReadUInt16LE(buffer, coffOff + 2)  ?? 0;
    const optionalHdrSize  = safeReadUInt16LE(buffer, coffOff + 16) ?? 0;

    const machineMap = {
      0x014C: 'x86 (PE32)',
      0x8664: 'x64 (PE32+)',
      0x01C4: 'ARMv7',
      0xAA64: 'ARM64',
    };
    result.arch = machineMap[machine] || `Unknown (0x${machine.toString(16)})`;

    // ── 5. Optional Header ───────────────────────────────────────────────
    const optOff = coffOff + 20;
    const optMagic = safeReadUInt16LE(buffer, optOff);
    if (optMagic === null) {
      result.error = 'Cannot read Optional Header magic';
      return result;
    }
    const is64 = optMagic === 0x020B;          // PE32+ → 64-bit

    // Data Directory starts at different offsets for PE32 vs PE32+
    //   PE32 : optOff + 96      PE32+: optOff + 112
    const dataDirOff = optOff + (is64 ? 112 : 96);

    // ── 6. Import Directory entry (Data Directory index 1) ───────────────
    // Each entry is 8 bytes: [RVA (4)] [Size (4)]
    const importRVA  = safeReadUInt32LE(buffer, dataDirOff + 8);
    const importSize = safeReadUInt32LE(buffer, dataDirOff + 12);

    if (!importRVA || !importSize) {
      // Not an error per se — some PE files genuinely have no imports
      result.error = 'No import table present';
      return result;
    }

    // ── 7. Section table ─────────────────────────────────────────────────
    const secHdrOff = optOff + optionalHdrSize;
    const sections  = parseSections(buffer, secHdrOff, numberOfSections);

    // ── 8. Walk the Import Directory Table ───────────────────────────────
    //  Each IMAGE_IMPORT_DESCRIPTOR is 20 bytes:
    //    OriginalFirstThunk (4)  |  TimeDateStamp (4)
    //    ForwarderChain     (4)  |  Name RVA      (4)
    //    FirstThunk         (4)
    //  Terminated by an all-zero entry.

    const importFileOff = rvaToOffset(importRVA, sections);
    if (importFileOff < 0) {
      result.error = 'Cannot resolve Import Directory RVA';
      return result;
    }

    const MAX_DLLS = 256;                      // sanity limit
    let descOff = importFileOff;

    for (let d = 0; d < MAX_DLLS; d++) {
      if (descOff + 20 > buffer.length) break;

      const origFirstThunk = safeReadUInt32LE(buffer, descOff)      ?? 0;
      const nameRVA        = safeReadUInt32LE(buffer, descOff + 12) ?? 0;
      const firstThunk     = safeReadUInt32LE(buffer, descOff + 16) ?? 0;

      if (nameRVA === 0) break;                // end sentinel

      // 8a. DLL name
      const dllNameOff = rvaToOffset(nameRVA, sections);
      const dllName    = readAsciiZ(buffer, dllNameOff);
      if (!dllName) { descOff += 20; continue; }

      // 8b. Import Lookup Table (ILT) — prefer OriginalFirstThunk
      const iltRVA = origFirstThunk || firstThunk;
      const functions = [];

      if (iltRVA) {
        const iltOff   = rvaToOffset(iltRVA, sections);
        const entryLen = is64 ? 8 : 4;
        const MAX_FUNCS = 1024;

        if (iltOff >= 0) {
          for (let f = 0; f < MAX_FUNCS; f++) {
            const eOff = iltOff + f * entryLen;
            if (eOff + entryLen > buffer.length) break;

            if (is64) {
              const lo = safeReadUInt32LE(buffer, eOff)     ?? 0;
              const hi = safeReadUInt32LE(buffer, eOff + 4) ?? 0;
              if (lo === 0 && hi === 0) break;

              // Ordinal flag = bit 63
              if (hi & 0x80000000) {
                functions.push(`Ordinal(${lo & 0xFFFF})`);
                continue;
              }
              // lo = RVA → IMAGE_IMPORT_BY_NAME (Hint:2 | Name:asciiZ)
              const hintOff = rvaToOffset(lo, sections);
              if (hintOff >= 0 && hintOff + 2 < buffer.length) {
                const fn = readAsciiZ(buffer, hintOff + 2);
                if (fn) functions.push(fn);
              }
            } else {
              const val = safeReadUInt32LE(buffer, eOff) ?? 0;
              if (val === 0) break;

              // Ordinal flag = bit 31
              if (val & 0x80000000) {
                functions.push(`Ordinal(${val & 0xFFFF})`);
                continue;
              }
              const hintOff = rvaToOffset(val, sections);
              if (hintOff >= 0 && hintOff + 2 < buffer.length) {
                const fn = readAsciiZ(buffer, hintOff + 2);
                if (fn) functions.push(fn);
              }
            }
          }
        }
      }

      result.imports.push({ dll: dllName, functions });
      descOff += 20;
    }

    return result;
  } catch (err) {
    result.error = `PE parse error: ${err.message}`;
    return result;
  }
}
