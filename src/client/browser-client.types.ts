/**
 * Type definitions for Hoosat Browser API Client
 */

// Base API response wrapper
export interface ApiResponse<T> {
  success: boolean;
  data?: T;
  error?: string;
}

// Balance response
export interface AddressBalance {
  address: string;
  balance: string; // in sompi (1 HTN = 100,000,000 sompi)
  pendingBalance?: string;
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

// Multiple UTXOs response
export interface AddressUtxos {
  address: string;
  utxos: UtxoEntry[];
}

// Transaction submission response
export interface TransactionSubmission {
  transactionId: string;
}

// Transaction info
export interface TransactionInfo {
  transactionId: string;
  blockHash?: string;
  blockTime?: number;
  confirmations?: number;
  inputs: Array<{
    previousOutpoint: {
      transactionId: string;
      index: number;
    };
    signatureScript: string;
    sequence: string;
  }>;
  outputs: Array<{
    amount: string;
    scriptPublicKey: {
      scriptPublicKey: string;
      version: number;
    };
  }>;
  mass?: string;
  status: 'pending' | 'confirmed' | 'rejected';
}

// Network information
export interface NetworkInfo {
  networkName: string;
  blockCount: string;
  headerCount: string;
  tipHashes: string[];
  difficulty: number;
  medianTime: number;
  isSynced: boolean;
  isUtxoIndexed: boolean;
}

// Block tip information
export interface BlockTip {
  hash: string;
  height: string;
  timestamp: number;
  difficulty: number;
}

// Transaction history entry
export interface TransactionHistory {
  transactions: Array<{
    transactionId: string;
    blockHash?: string;
    timestamp?: number;
    confirmations: number;
    inputs: Array<{
      address?: string;
      amount: string;
    }>;
    outputs: Array<{
      address?: string;
      amount: string;
    }>;
    fee: string;
  }>;
  totalCount: number;
}

// Fee recommendation
export interface FeeRecommendation {
  low: number; // sompi per byte
  medium: number;
  high: number;
  fastest: number;
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
