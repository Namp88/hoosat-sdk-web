/**
 * TypeScript type definitions for Hoosat message signing
 */

/**
 * A signed message with metadata
 */
export interface SignedMessage {
  /** Original message that was signed */
  message: string;

  /** Compact signature in hex format (128 chars) */
  signature: string;

  /** Hoosat address that signed the message */
  address: string;

  /** Optional timestamp when message was signed */
  timestamp?: number;

  /** Optional metadata */
  metadata?: Record<string, any>;
}

/**
 * Message verification result
 */
export interface VerificationResult {
  /** True if signature is valid */
  valid: boolean;

  /** Recovered public key (if verification succeeded) */
  publicKey?: string;

  /** Error message (if verification failed) */
  error?: string;
}
