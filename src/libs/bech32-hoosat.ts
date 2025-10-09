/**
 * Hoosat Bech32 implementation
 * Portable from github.com/Hoosat-Oy/HTND/util/bech32
 */

const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const CHECKSUM_LENGTH = 8;
const GENERATOR = [0x98f2bc8e61n, 0x79b76d99e2n, 0xf33e5fb3c4n, 0xae2eabe2a8n, 0x1e4f43e470n];

/**
 * Encodes data to Hoosat Bech32 format
 */
export function encode(prefix: string, payload: Buffer, version: number): string {
  // Prepend version byte
  const data = Buffer.concat([Buffer.from([version]), payload]);

  // Convert from 8-bit to 5-bit
  const converted = convertBits(data, 8, 5, true);

  // Calculate checksum
  const checksum = calculateChecksum(prefix, converted);
  const combined = Buffer.concat([converted, checksum]);

  // Encode to base32
  const base32String = encodeToBase32(combined);

  return `${prefix}:${base32String}`;
}

/**
 * Decodes Hoosat Bech32 address
 */
export function decode(encoded: string): { prefix: string; payload: Buffer; version: number } {
  // Validation
  if (encoded.length < CHECKSUM_LENGTH + 2) {
    throw new Error(`Invalid bech32 string length ${encoded.length}`);
  }

  // ASCII validation
  for (let i = 0; i < encoded.length; i++) {
    const charCode = encoded.charCodeAt(i);
    if (charCode < 33 || charCode > 126) {
      throw new Error(`Invalid character in string: '${encoded[i]}'`);
    }
  }

  // Must be lowercase or uppercase
  const lower = encoded.toLowerCase();
  const upper = encoded.toUpperCase();
  if (encoded !== lower && encoded !== upper) {
    throw new Error('String not all lowercase or all uppercase');
  }

  // Work with lowercase
  const normalized = lower;

  // Find last colon
  const colonIndex = normalized.lastIndexOf(':');
  if (colonIndex < 1 || colonIndex + CHECKSUM_LENGTH + 1 > normalized.length) {
    throw new Error('Invalid index of ":"');
  }

  // Split prefix and data
  const prefix = normalized.slice(0, colonIndex);
  const dataString = normalized.slice(colonIndex + 1);

  // Decode from base32
  const decoded = decodeFromBase32(dataString);

  // Verify checksum
  if (!verifyChecksum(prefix, decoded)) {
    const checksum = dataString.slice(-CHECKSUM_LENGTH);
    const expected = encodeToBase32(calculateChecksum(prefix, decoded.slice(0, -CHECKSUM_LENGTH)));
    throw new Error(`Checksum failed. Expected ${expected}, got ${checksum}`);
  }

  // Remove checksum (last 8 bytes)
  const dataWithoutChecksum = decoded.slice(0, -CHECKSUM_LENGTH);

  // Convert from 5-bit to 8-bit
  const converted = convertBits(dataWithoutChecksum, 5, 8, false);

  // Extract version and payload
  const version = converted[0];
  const payload = converted.slice(1);

  return { prefix, payload, version };
}

/**
 * Converts between bit groups
 */
function convertBits(data: Buffer, fromBits: number, toBits: number, pad: boolean): Buffer {
  const regrouped: number[] = [];
  let nextByte = 0;
  let filledBits = 0;

  for (const value of data) {
    // Accumulate bits from input
    nextByte = (nextByte << fromBits) | value;
    filledBits += fromBits;

    // Extract complete groups
    while (filledBits >= toBits) {
      filledBits -= toBits;
      regrouped.push((nextByte >> filledBits) & ((1 << toBits) - 1));
      nextByte &= (1 << filledBits) - 1;
    }
  }

  // Handle remaining bits
  if (pad && filledBits > 0) {
    regrouped.push((nextByte << (toBits - filledBits)) & ((1 << toBits) - 1));
  } else if (filledBits >= fromBits || (filledBits > 0 && nextByte !== 0)) {
    throw new Error('Invalid padding in conversion');
  }

  return Buffer.from(regrouped);
}

/**
 * Encodes to base32
 */
function encodeToBase32(data: Buffer): string {
  let result = '';
  for (const b of data) {
    if (b >= CHARSET.length) {
      return '';
    }
    result += CHARSET[b];
  }
  return result;
}

/**
 * Decodes from base32
 */
function decodeFromBase32(str: string): Buffer {
  const result: number[] = [];
  for (const char of str) {
    const index = CHARSET.indexOf(char);
    if (index < 0) {
      throw new Error(`Invalid character not part of charset: ${char}`);
    }
    result.push(index);
  }
  return Buffer.from(result);
}

/**
 * Calculates checksum (ИСПРАВЛЕНО: используем BigInt для 40-бит)
 */
function calculateChecksum(prefix: string, payload: Buffer): Buffer {
  const prefixLower5Bits = prefixToUint5Array(prefix);
  const payloadInts = Array.from(payload);
  const templateZeroes = [0, 0, 0, 0, 0, 0, 0, 0];

  // Concatenate: prefix + 0 + payload + zeros
  const concat = [...prefixLower5Bits, 0, ...payloadInts, ...templateZeroes];

  const polyModResult = polyMod(concat);

  const res: number[] = [];
  for (let i = 0; i < CHECKSUM_LENGTH; i++) {
    res.push(Number((polyModResult >> BigInt(5 * (CHECKSUM_LENGTH - 1 - i))) & 31n));
  }

  return Buffer.from(res);
}

/**
 * Verifies checksum (polyMod returns BigInt)
 */
function verifyChecksum(prefix: string, payload: Buffer): boolean {
  const prefixLower5Bits = prefixToUint5Array(prefix);
  const payloadInts = Array.from(payload);

  // Concatenate: prefix + 0 + payload
  const dataToVerify = [...prefixLower5Bits, 0, ...payloadInts];

  return polyMod(dataToVerify) === 0n; // BigInt сравнение
}

/**
 * Converts prefix to uint5 array
 */
function prefixToUint5Array(prefix: string): number[] {
  const result: number[] = [];
  for (let i = 0; i < prefix.length; i++) {
    const char = prefix.charCodeAt(i);
    result.push(char & 31);
  }
  return result;
}

/**
 * Polynomial modulus for checksum
 */
function polyMod(values: number[]): bigint {
  let checksum = 1n;

  for (const value of values) {
    const topBits = checksum >> 35n;
    checksum = ((checksum & 0x07ffffffffn) << 5n) ^ BigInt(value);

    for (let i = 0; i < GENERATOR.length; i++) {
      if (((topBits >> BigInt(i)) & 1n) === 1n) {
        checksum ^= GENERATOR[i];
      }
    }
  }

  return checksum ^ 1n;
}
