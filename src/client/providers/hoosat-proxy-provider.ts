import { BaseProvider } from './base-provider';
import type { EndpointConfig } from './api-provider.interface';
import type {
  AddressBalance,
  AddressUtxos,
  TransactionSubmission,
  NetworkInfo,
  FeeRecommendation,
  ApiResponse,
} from '../client-web.types';
import type { Transaction } from '@models/transaction.types';

export class HoosatProxyProvider extends BaseProvider {
  protected get endpoints(): EndpointConfig {
    return {
      balance: '/address/:address/balance',
      utxos: '/address/utxos',
      submitTransaction: '/transaction/submit',
      networkInfo: '/node/info',
      feeEstimate: '/mempool/fee-estimate',
    };
  }

  protected transformResponse<T>(data: any): T {
    if (data.success !== undefined) {
      const apiResponse = data as ApiResponse<T>;
      if (!apiResponse.success) {
        throw new Error(apiResponse.error || 'API request failed');
      }
      if (!apiResponse.data) {
        throw new Error('API response missing data field');
      }
      return apiResponse.data;
    }
    return data;
  }

  async getBalance(address: string): Promise<AddressBalance> {
    const endpoint = this.endpoints.balance.replace(':address', address);
    return this.request<AddressBalance>(endpoint);
  }

  async getUtxos(addresses: string[]): Promise<AddressUtxos> {
    const response = await this.request<any>(this.endpoints.utxos, {
      method: 'POST',
      body: JSON.stringify({ addresses }),
    });

    if (response.utxos) {
      response.utxos = response.utxos.map((utxo: any) => ({
        ...utxo,
        utxoEntry: {
          ...utxo.utxoEntry,
          scriptPublicKey: {
            version: utxo.utxoEntry.scriptPublicKey.version,
            script: utxo.utxoEntry.scriptPublicKey.scriptPublicKey,
          },
        },
      }));
    }

    return response;
  }

  async submitTransaction(transaction: Transaction): Promise<TransactionSubmission> {
    return this.request<TransactionSubmission>(this.endpoints.submitTransaction, {
      method: 'POST',
      body: JSON.stringify(transaction),
    });
  }

  async getNetworkInfo(): Promise<NetworkInfo> {
    return this.request<NetworkInfo>(this.endpoints.networkInfo);
  }

  async getFeeEstimate(): Promise<FeeRecommendation> {
    return this.request<FeeRecommendation>(this.endpoints.feeEstimate);
  }
}