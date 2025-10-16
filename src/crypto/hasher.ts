/**
 * Message hashing utilities for Hoosat signatures
 */

import { HoosatCrypto } from '@crypto/crypto-web';
import { Buffer } from 'buffer';

/**
 * Standard message prefix for Hoosat signatures
 * Similar to Bitcoin's "Bitcoin Signed Message:\n"
 * This prevents transaction replay attacks
 */
export const MESSAGE_PREFIX = 'Hoosat Signed Message:\n';

/**
 * Format message with Hoosat standard prefix
 *
 * @param message - The message to format
 * @returns Formatted message with prefix
 *
 * @example
 * formatMessage("Hello World")
 * // Returns: "Hoosat Signed Message:\nHello World"
 */
export function formatMessage(message: string): string {
  return `${MESSAGE_PREFIX}${message}`;
}

/**
 * Hash a message using BLAKE3
 *
 * @param message - The message to hash (will be prefixed automatically)
 * @returns BLAKE3 hash as Uint8Array (32 bytes)
 *
 * @example
 * const hash = hashMessage("Hello World");
 * // Returns 32-byte Uint8Array
 */
export function hashMessage(message: string): Uint8Array {
  const prefixedMessage = formatMessage(message);
  const messageBuffer = Buffer.from(prefixedMessage, 'utf8');
  return HoosatCrypto.blake3Hash(messageBuffer);
}

/**
 * Hash a raw buffer (without prefix)
 * Use this for signing already-formatted data
 *
 * @param buffer - Raw buffer to hash
 * @returns BLAKE3 hash as Uint8Array (32 bytes)
 */
export function hashBuffer(buffer: Buffer | Uint8Array): Uint8Array {
  return HoosatCrypto.blake3Hash(buffer);
}
