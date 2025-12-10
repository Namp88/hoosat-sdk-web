import { BaseProvider } from './base-provider';
import type { EndpointConfig } from './api-provider.interface';
import type {
  AddressBalance,
  AddressUtxos,
  TransactionSubmission,
  NetworkInfo,
  FeeRecommendation,
} from '../client-web.types';
import type { Transaction } from '@models/transaction.types';

export class HoosatNetworkProvider extends BaseProvider {
  protected get endpoints(): EndpointConfig {
    return {
      balance: '/addresses/:address/balance',
      utxos: '/addresses/:address/utxos',
      submitTransaction: '/transactions',
      networkInfo: '/info/network',
      feeEstimate: '/info/hashrate',
    };
  }

  protected transformResponse<T>(data: any): T {
    return data;
  }

  async getBalance(address: string): Promise<AddressBalance> {
    const endpoint = this.endpoints.balance.replace(':address', address);
    const data = await this.request<any>(endpoint);

    return {
      balance: data.balance || data.confirmedBalance || '0',
    };
  }

  async getUtxos(addresses: string[]): Promise<AddressUtxos> {
    const address = addresses[0];
    const endpoint = this.endpoints.utxos.replace(':address', address);
    const data = await this.request<any>(endpoint);

    return {
      address,
      utxos: data.utxos || data || [],
    };
  }

  async submitTransaction(transaction: Transaction): Promise<TransactionSubmission> {
    const data = await this.request<any>(this.endpoints.submitTransaction, {
      method: 'POST',
      body: JSON.stringify(transaction),
    });

    return {
      transactionId: data.transactionId || data.txId || data.id,
    };
  }

  async getNetworkInfo(): Promise<NetworkInfo> {
    const data = await this.request<any>(this.endpoints.networkInfo);

    return {
      p2pId: data.p2pId || '',
      mempoolSize: data.mempoolSize || '0',
      serverVersion: data.version || data.serverVersion || '1.0.0',
      isUtxoIndexed: data.isUtxoIndexed || [],
      isSynced: data.isSynced || data.synced || 1,
    };
  }

  async getFeeEstimate(): Promise<FeeRecommendation> {
    const data = await this.request<any>(this.endpoints.feeEstimate);

    return {
      feeRate: data.feeRate || 1000,
      totalFee: data.totalFee || '1000',
      priority: data.priority || 'normal' as any,
      percentile: data.percentile || 50,
      basedOnSamples: data.basedOnSamples || 100,
    };
  }
}