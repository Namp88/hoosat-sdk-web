import type { ApiProvider, ProviderConfig, EndpointConfig } from './api-provider.interface';
import type { RequestOptions } from '../client-web.types';

export abstract class BaseProvider implements ApiProvider {
  protected readonly baseUrl: string;
  protected readonly timeout: number;
  protected readonly headers: Record<string, string>;
  protected readonly debug: boolean;

  constructor(config: ProviderConfig) {
    this.baseUrl = config.baseUrl.replace(/\/$/, '');
    this.timeout = config.timeout || 30000;
    this.headers = {
      'Content-Type': 'application/json',
      ...config.headers,
    };
    this.debug = config.debug || false;
  }

  protected async request<T>(endpoint: string, options: RequestInit & RequestOptions = {}): Promise<T> {
    const url = `${this.baseUrl}${endpoint}`;
    const timeout = options.timeout || this.timeout;

    if (this.debug) {
      console.log(`[${this.constructor.name}] ${options.method || 'GET'} ${url}`);
      if (options.body) {
        console.log(`[${this.constructor.name}] Request body:`, options.body);
      }
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);

    try {
      const response = await fetch(url, {
        ...options,
        headers: {
          ...this.headers,
          ...options.headers,
        },
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      const data = await response.json();

      if (this.debug) {
        console.log(`[${this.constructor.name}] Response:`, data);
      }

      return this.transformResponse(data);
    } catch (error: any) {
      clearTimeout(timeoutId);

      if (error.name === 'AbortError') {
        throw new Error(`Request timeout after ${timeout}ms`);
      }

      if (this.debug) {
        console.error(`[${this.constructor.name}] Error:`, error);
      }

      throw error;
    }
  }

  protected abstract transformResponse<T>(data: any): T;
  protected abstract get endpoints(): EndpointConfig;

  abstract getBalance(address: string): Promise<import('../client-web.types').AddressBalance>;
  abstract getUtxos(addresses: string[]): Promise<import('../client-web.types').AddressUtxos>;
  abstract submitTransaction(tx: import('@models/transaction.types').Transaction): Promise<import('../client-web.types').TransactionSubmission>;
  abstract getNetworkInfo(): Promise<import('../client-web.types').NetworkInfo>;
  abstract getFeeEstimate(): Promise<import('../client-web.types').FeeRecommendation>;

  async ping(): Promise<boolean> {
    try {
      await this.getNetworkInfo();
      return true;
    } catch {
      return false;
    }
  }
}