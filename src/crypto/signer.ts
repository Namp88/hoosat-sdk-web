/**
 * Hoosat Message Signer
 *
 * Provides ECDSA message signing and verification using secp256k1
 * Compatible with standard Web3 signing practices
 *
 * IMPORTANT: HMAC-SHA256 is already initialized in crypto-web.ts
 * No additional initialization is required before using this module
 */

import { sign, verify, getPublicKey, Signature } from '@noble/secp256k1';
import { hashMessage, formatMessage, MESSAGE_PREFIX } from '@crypto/hasher';
import type { SignedMessage, VerificationResult } from '@crypto/signer.types';
import { Buffer } from 'buffer';

/**
 * Main class for message signing operations
 *
 * @example
 * ```typescript
 * import { HoosatSigner } from 'hoosat-sdk-web';
 *
 * // Sign a message
 * const privateKey = 'a1b2c3d4...'; // 64 hex chars
 * const signature = HoosatSigner.signMessage(privateKey, 'Hello World');
 *
 * // Verify a signature
 * const isValid = HoosatSigner.verifyMessage(signature, 'Hello World', publicKey);
 * ```
 */
export class HoosatSigner {
  /**
   * Sign a message with a private key
   *
   * @param privateKey - Hex string private key (64 chars without 0x prefix)
   * @param message - Message to sign (plain text)
   * @returns Compact signature in hex format (128 chars)
   *
   * @throws Error if private key is invalid
   * @throws Error if signing fails
   *
   * @example
   * ```typescript
   * const privateKey = 'a1b2c3d4...'; // 64 char hex
   * const signature = HoosatSigner.signMessage(privateKey, 'Hello World');
   * console.log(signature); // "3045022100ab12cd34..."
   * ```
   */
  static signMessage(privateKey: string, message: string): string {
    try {
      // Remove 0x prefix if present
      const cleanPrivateKey = privateKey.replace(/^0x/, '');

      // Validate private key length
      if (cleanPrivateKey.length !== 64) {
        throw new Error('Private key must be 64 hex characters');
      }

      // Hash the message with BLAKE3
      const messageHash = hashMessage(message);

      // Sign using ECDSA with security options
      // Note: RFC6979 deterministic signing is enabled by HMAC-SHA256 initialization in crypto-web.ts
      const signature = sign(messageHash, cleanPrivateKey, {
        lowS: true, // Prevent signature malleability (BIP-62)
      });

      // Return compact signature format (128 hex chars)
      return signature.toCompactHex();
    } catch (error: any) {
      throw new Error(`Message signing failed: ${error.message}`);
    }
  }

  /**
   * Verify a message signature
   *
   * @param signature - Compact signature hex (128 chars)
   * @param message - Original message that was signed
   * @param publicKey - Public key hex (66 chars, compressed format with 02/03 prefix)
   * @returns True if signature is valid
   *
   * @example
   * ```typescript
   * const isValid = HoosatSigner.verifyMessage(
   *   signature,
   *   'Hello World',
   *   publicKey
   * );
   * console.log(isValid); // true or false
   * ```
   */
  static verifyMessage(signature: string, message: string, publicKey: string): boolean {
    try {
      // Clean inputs
      const cleanSignature = signature.replace(/^0x/, '');
      const cleanPublicKey = publicKey.replace(/^0x/, '');

      // Hash the message
      const messageHash = hashMessage(message);

      // Parse signature from compact hex
      const sig = Signature.fromCompact(cleanSignature);

      // Verify signature
      return verify(sig, messageHash, cleanPublicKey);
    } catch (error: any) {
      console.error('Signature verification failed:', error);
      return false;
    }
  }

  /**
   * Recover public key from signature
   *
   * Note: This method requires trying different recovery IDs (0-3)
   * to find the correct public key. Use verifyMessage() when possible.
   *
   * @param signature - Compact signature hex (128 chars)
   * @param message - Original message
   * @param recoveryId - Recovery ID (0-3), default 0
   * @returns Recovered public key in compressed format (66 hex chars)
   *
   * @throws Error if recovery fails
   *
   * @example
   * ```typescript
   * const publicKey = HoosatSigner.recoverPublicKey(
   *   signature,
   *   'Hello World',
   *   0
   * );
   * ```
   */
  static recoverPublicKey(signature: string, message: string, recoveryId: number = 0): string {
    try {
      const cleanSignature = signature.replace(/^0x/, '');
      const messageHash = hashMessage(message);

      const sig = Signature.fromCompact(cleanSignature);

      // Add recovery ID to signature
      const sigWithRecovery = sig.addRecoveryBit(recoveryId);
      const publicKey = sigWithRecovery.recoverPublicKey(messageHash);

      return publicKey.toHex(true); // Compressed format
    } catch (error: any) {
      throw new Error(`Public key recovery failed: ${error.message}`);
    }
  }

  /**
   * Get public key from private key
   *
   * @param privateKey - Private key hex (64 chars)
   * @param compressed - Return compressed format (default: true)
   * @returns Public key hex string (66 chars if compressed, 130 if uncompressed)
   *
   * @example
   * ```typescript
   * const publicKey = HoosatSigner.getPublicKey(privateKey);
   * console.log(publicKey); // "02a1b2c3d4..."
   * ```
   */
  static getPublicKey(privateKey: string, compressed: boolean = true): string {
    try {
      const cleanPrivateKey = privateKey.replace(/^0x/, '');
      const publicKey = getPublicKey(cleanPrivateKey, compressed);
      return Buffer.from(publicKey).toString('hex');
    } catch (error: any) {
      throw new Error(`Failed to derive public key: ${error.message}`);
    }
  }

  /**
   * Create a complete signed message object
   *
   * @param privateKey - Private key to sign with
   * @param message - Message to sign
   * @param address - Hoosat address (for metadata)
   * @returns Complete SignedMessage object with timestamp
   *
   * @example
   * ```typescript
   * const signedMsg = HoosatSigner.createSignedMessage(
   *   privateKey,
   *   'Hello World',
   *   'hoosat:qyp...'
   * );
   * // Returns: { message, signature, address, timestamp }
   * ```
   */
  static createSignedMessage(privateKey: string, message: string, address: string): SignedMessage {
    const signature = this.signMessage(privateKey, message);

    return {
      message,
      signature,
      address,
      timestamp: Date.now(),
    };
  }

  /**
   * Verify a complete signed message object
   *
   * @param signedMessage - SignedMessage object to verify
   * @param publicKey - Public key to verify against
   * @returns Verification result with details
   *
   * @example
   * ```typescript
   * const result = HoosatSigner.verifySignedMessage(signedMsg, publicKey);
   * if (result.valid) {
   *   console.log('Signature is valid');
   * } else {
   *   console.log('Invalid:', result.error);
   * }
   * ```
   */
  static verifySignedMessage(signedMessage: SignedMessage, publicKey: string): VerificationResult {
    try {
      const valid = this.verifyMessage(signedMessage.signature, signedMessage.message, publicKey);

      if (valid) {
        return {
          valid: true,
          publicKey,
        };
      } else {
        return {
          valid: false,
          error: 'Invalid signature',
        };
      }
    } catch (error: any) {
      return {
        valid: false,
        error: error.message,
      };
    }
  }
}
