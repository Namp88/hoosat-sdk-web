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

export { HoosatCrypto } from '@crypto/crypto-web';
export type { KeyPair, TransactionSignature } from '@crypto/crypto-web.types';

export { HoosatWebClient } from '@client/client-web';
export type {
  ApiResponse,
  AddressBalance,
  AddressUtxos,
  TransactionSubmission,
  NetworkInfo,
  FeeRecommendation,
  BrowserClientConfig,
  RequestOptions,
} from '@client/client-web.types';
export { PriorityFee } from '@client/client-web.types';

export { HoosatTxBuilder } from '@transaction/tx-builder';
export type { TxBuilderOptions } from '@transaction/tx-builder.types';

export { HoosatUtils } from '@utils/utils';

export { HoosatQR } from '@qr/qr-web';
export type { PaymentURIParams, QRCodeOptions, ParsedPaymentURI } from '@qr/qr-web.types';

export { HOOSAT_PARAMS } from '@constants/hoosat-params.const';
export { HOOSAT_MASS } from '@constants/hoosat-mass.const';

export type { Transaction, TransactionInput, TransactionOutput, UtxoEntry, UtxoForSigning } from '@models/transaction.types';
export type { HoosatNetwork } from '@models/network.type';
