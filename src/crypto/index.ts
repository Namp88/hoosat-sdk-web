/**
 * Hoosat Crypto Module
 *
 * Provides cryptographic operations for Hoosat blockchain:
 * - Key generation and management (ECDSA)
 * - Transaction signing and verification
 * - Message signing and verification
 * - Address generation
 * - Hashing utilities (BLAKE3, SHA256)
 */

// Main crypto class
export { HoosatCrypto } from '@crypto/crypto-web';
export type { KeyPair, TransactionSignature, SighashReusedValues } from '@crypto/crypto-web.types';

// Message signing
export { HoosatSigner } from '@crypto/signer';
export { hashMessage, formatMessage, hashBuffer, MESSAGE_PREFIX } from '@crypto/hasher';
export type { SignedMessage, VerificationResult } from '@crypto/signer.types';
