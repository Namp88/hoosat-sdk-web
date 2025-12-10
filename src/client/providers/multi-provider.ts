import type { ApiProvider, ProviderConfig } from './api-provider.interface';
import type {
  AddressBalance,
  AddressUtxos,
  TransactionSubmission,
  NetworkInfo,
  FeeRecommendation,
} from '../client-web.types';
import type { Transaction } from '@models/transaction.types';

export interface MultiProviderConfig {
  providers: ApiProvider[];
  strategy?: 'failover' | 'fastest' | 'round-robin';
  maxRetries?: number;
  retryDelay?: number;
  debug?: boolean;
}

export class MultiProvider implements ApiProvider {
  private readonly providers: ApiProvider[];
  private readonly strategy: 'failover' | 'fastest' | 'round-robin';
  private readonly maxRetries: number;
  private readonly retryDelay: number;
  private readonly debug: boolean;
  private currentProviderIndex: number = 0;

  constructor(config: MultiProviderConfig) {
    if (!config.providers.length) {
      throw new Error('At least one provider is required');
    }

    this.providers = config.providers;
    this.strategy = config.strategy || 'failover';
    this.maxRetries = config.maxRetries || this.providers.length;
    this.retryDelay = config.retryDelay || 1000;
    this.debug = config.debug || false;
  }

  private async withFallback<T>(
    operation: (provider: ApiProvider) => Promise<T>,
    operationName?: string
  ): Promise<T> {
    const errors: Error[] = [];
    let attempts = 0;

    while (attempts < this.maxRetries) {
      let provider: ApiProvider;

      switch (this.strategy) {
        case 'round-robin':
          provider = this.providers[this.currentProviderIndex];
          this.currentProviderIndex = (this.currentProviderIndex + 1) % this.providers.length;
          break;

        case 'fastest':
          const results = await Promise.allSettled(
            this.providers.map(async p => ({ provider: p, result: await operation(p) }))
          );

          for (const result of results) {
            if (result.status === 'fulfilled') {
              return result.value.result;
            }
            if (result.status === 'rejected') {
              errors.push(result.reason);
            }
          }

          throw new Error(`All providers failed for ${operationName}: ${errors.map(e => e.message).join(', ')}`);

        case 'failover':
        default:
          provider = this.providers[attempts % this.providers.length];
          break;
      }

      try {
        if (this.debug) {
          console.log(`[MultiProvider] Attempting ${operationName} with provider ${attempts + 1}/${this.maxRetries}`);
        }

        const result = await operation(provider);

        if (this.debug) {
          console.log(`[MultiProvider] ${operationName} succeeded with provider ${attempts + 1}`);
        }

        return result;
      } catch (error: any) {
        errors.push(error);
        attempts++;

        if (this.debug) {
          console.warn(`[MultiProvider] Provider ${attempts} failed for ${operationName}:`, error.message);
        }

        if (attempts < this.maxRetries) {
          await new Promise(resolve => setTimeout(resolve, this.retryDelay));
        }
      }
    }

    throw new Error(`All ${this.maxRetries} providers failed for ${operationName}: ${errors.map(e => e.message).join(', ')}`);
  }

  async getBalance(address: string): Promise<AddressBalance> {
    return this.withFallback(provider => provider.getBalance(address), 'getBalance');
  }

  async getUtxos(addresses: string[]): Promise<AddressUtxos> {
    return this.withFallback(provider => provider.getUtxos(addresses), 'getUtxos');
  }

  async submitTransaction(tx: Transaction): Promise<TransactionSubmission> {
    return this.withFallback(provider => provider.submitTransaction(tx), 'submitTransaction');
  }

  async getNetworkInfo(): Promise<NetworkInfo> {
    return this.withFallback(provider => provider.getNetworkInfo(), 'getNetworkInfo');
  }

  async getFeeEstimate(): Promise<FeeRecommendation> {
    return this.withFallback(provider => provider.getFeeEstimate(), 'getFeeEstimate');
  }

  async ping(): Promise<boolean> {
    try {
      await this.getNetworkInfo();
      return true;
    } catch {
      return false;
    }
  }

  getProviders(): ApiProvider[] {
    return [...this.providers];
  }

  getStrategy(): string {
    return this.strategy;
  }
}