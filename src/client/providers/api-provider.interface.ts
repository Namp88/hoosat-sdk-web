import type {
  AddressBalance,
  AddressUtxos,
  TransactionSubmission,
  NetworkInfo,
  FeeRecommendation,
} from '../client-web.types';
import type { Transaction } from '@models/transaction.types';

export interface ApiProvider {
  getBalance(address: string): Promise<AddressBalance>;
  getUtxos(addresses: string[]): Promise<AddressUtxos>;
  submitTransaction(tx: Transaction): Promise<TransactionSubmission>;
  getNetworkInfo(): Promise<NetworkInfo>;
  getFeeEstimate(): Promise<FeeRecommendation>;
  ping(): Promise<boolean>;
}

export interface ProviderConfig {
  baseUrl: string;
  timeout?: number;
  headers?: Record<string, string>;
  debug?: boolean;
}

export interface EndpointConfig {
  balance: string;
  utxos: string;
  submitTransaction: string;
  networkInfo: string;
  feeEstimate: string;
}