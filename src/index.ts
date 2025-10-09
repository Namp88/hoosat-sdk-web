// Browser-compatible exports for Hoosat SDK
// This version excludes Node.js-specific modules (gRPC, EventManager, etc.)

// Import Buffer polyfill for browser compatibility
import { Buffer } from 'buffer';

// Make Buffer globally available in browser environment
// This is critical for crypto operations and must happen before anything else
if (typeof globalThis !== 'undefined') {
  (globalThis as any).Buffer = Buffer;
  // Also set on window for compatibility
  if (typeof (globalThis as any).window !== 'undefined') {
    (globalThis as any).window.Buffer = Buffer;
  }
}

// Core crypto module (browser version)
export { HoosatCrypto } from '@crypto/crypto-browser';
export type { KeyPair, TransactionSignature } from '@crypto/crypto.types';

// Browser API client (NEW!)
export { HoosatBrowserClient } from '@client/browser-client';
export type {
  ApiResponse,
  AddressBalance,
  AddressUtxos,
  TransactionSubmission,
  TransactionInfo,
  NetworkInfo,
  BlockTip,
  TransactionHistory,
  FeeRecommendation,
  BrowserClientConfig,
  RequestOptions,
} from '@client/browser-client.types';

// Transaction builder (works with browser crypto)
export { HoosatTxBuilder } from '@transaction/tx-builder';
export type { TxBuilderOptions } from '@transaction/tx-builder.types';

// Utilities (pure JS, works in browser)
export { HoosatUtils } from '@utils/utils';

// QR code generator (browser-compatible)
export { HoosatQR } from '@qr/qr';
export type { PaymentURIParams, QRCodeOptions, ParsedPaymentURI } from '@qr/qr.types';

// Constants
export { HOOSAT_PARAMS } from '@constants/hoosat-params.const';
export { HOOSAT_MASS } from '@constants/hoosat-mass.const';

// Types
export type { Transaction, TransactionInput, TransactionOutput, UtxoEntry, UtxoForSigning } from '@models/transaction.types';
export type { HoosatNetwork } from '@models/network.type';

// Note: The following modules are NOT included in browser build:
// - HoosatClient (requires gRPC, Node.js only)
// - HoosatEventManager (requires gRPC streaming, Node.js only)
// - HoosatFeeEstimator (depends on HoosatClient)
//
// Instead, use HoosatBrowserClient for REST API access.
