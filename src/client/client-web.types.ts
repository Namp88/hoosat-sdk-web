/**
 * Type definitions for Hoosat Browser API Client
 */

// Base API response wrapper
export interface ApiResponse<T> {
  success: boolean;
  data?: T;
  error?: string;
  timestamp: number;
  path: string;
}

export interface AddressBalance {
  balance: string;
}

export interface AddressUtxos {
  address: string;
  utxos: UtxoEntry[];
}

// UTXO entry for transaction building
export interface UtxoEntry {
  outpoint: {
    transactionId: string;
    index: number;
  };
  utxoEntry: {
    amount: string;
    scriptPublicKey: {
      script: string;
      version: number;
    };
    blockDaaScore: string;
    isCoinbase: boolean;
  };
}

export interface TransactionSubmission {
  transactionId: string;
}

// Network information
export interface NetworkInfo {
  p2pId: string;
  mempoolSize: string;
  serverVersion: string;
  isUtxoIndexed: string[];
  isSynced: number;
}

// Fee recommendation
export interface FeeRecommendation {
  feeRate: number;
  totalFee: string;
  priority: PriorityFee;
  percentile: number;
  basedOnSamples: number;
}

export enum PriorityFee {
  Low = 'low',
  Normal = 'normal',
  High = 'high',
  Urgent = 'urgent',
}

// Client configuration
export interface BrowserClientConfig {
  baseUrl: string;
  timeout?: number;
  headers?: Record<string, string>;
  debug?: boolean;
}

// Request options
export interface RequestOptions {
  timeout?: number;
  headers?: Record<string, string>;
  retries?: number;
}
