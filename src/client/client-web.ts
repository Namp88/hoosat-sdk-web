import type {
  ApiResponse,
  AddressBalance,
  AddressUtxos,
  TransactionSubmission,
  NetworkInfo,
  FeeRecommendation,
  BrowserClientConfig,
  RequestOptions,
} from './client-web.types';
import type { Transaction } from '@models/transaction.types';

/**
 * HoosatWebClient - REST API client for browser-based Hoosat applications
 *
 * Provides methods to interact with Hoosat blockchain via REST API proxy.
 * All methods return promises and handle errors gracefully.
 *
 * @example
 * ```typescript
 * const client = new HoosatWebClient({
 *   baseUrl: 'https://proxy.hoosat.net/api/v1',
 *   timeout: 30000
 * });
 *
 * // Get balance
 * const balance = await client.getBalance('hoosat:qz7ulu...');
 * console.log(`Balance: ${balance.balance} sompi`);
 *
 * // Get UTXOs for transaction
 * const utxos = await client.getUtxos('hoosat:qz7ulu...');
 * ```
 */
export class HoosatWebClient {
  private readonly _baseUrl: string;
  private readonly _timeout: number;
  private readonly _headers: Record<string, string>;
  private readonly _debug: boolean;

  /**
   * Creates a new HoosatWebClient instance
   *
   * @param config - Client configuration
   * @param config.baseUrl - Base URL of the API (e.g., 'https://proxy.hoosat.net/api/v1')
   * @param config.timeout - Request timeout in milliseconds (default: 30000)
   * @param config.headers - Additional headers to include in requests
   * @param config.debug - Enable debug logging (default: false)
   */
  constructor(config: BrowserClientConfig) {
    this._baseUrl = config.baseUrl.replace(/\/$/, ''); // Remove trailing slash
    this._timeout = config.timeout || 30000;
    this._headers = {
      'Content-Type': 'application/json',
      ...config.headers,
    };
    this._debug = config.debug || false;
  }

  // ==================== PRIVATE HELPERS ====================

  /**
   * Make HTTP request with timeout and error handling
   * @private
   */
  private async request<T>(endpoint: string, options: RequestInit & RequestOptions = {}): Promise<T> {
    const url = `${this._baseUrl}${endpoint}`;
    const timeout = options.timeout || this._timeout;

    if (this._debug) {
      console.log(`[HoosatWebClient] ${options.method || 'GET'} ${url}`);
      if (options.body) {
        console.log('[HoosatWebClient] Request body:', options.body);
      }
    }

    // Create abort controller for timeout
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);

    try {
      const response = await fetch(url, {
        ...options,
        headers: {
          ...this._headers,
          ...options.headers,
        },
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      // Parse response
      const data: ApiResponse<T> = (await response.json()) as ApiResponse<T>;

      if (this._debug) {
        console.log('[HoosatWebClient] Response:', data);
      }

      // Check API response format
      if (!data.success) {
        throw new Error(data.error || 'API request failed');
      }

      if (!data.data) {
        throw new Error('API response missing data field');
      }

      return data.data;
    } catch (error: any) {
      clearTimeout(timeoutId);

      if (error.name === 'AbortError') {
        throw new Error(`Request timeout after ${timeout}ms`);
      }

      if (this._debug) {
        console.error('[HoosatWebClient] Error:', error);
      }

      throw error;
    }
  }

  // ==================== ADDRESS METHODS ====================

  /**
   * Get balance for a Hoosat address
   *
   * @param address - Hoosat address (e.g., 'hoosat:qz7ulu...')
   * @returns Address balance in sompi
   *
   * @example
   * ```typescript
   * const balance = await client.getBalance('hoosat:qz7ulu...');
   * console.log(`Balance: ${balance.balance} sompi`);
   * // Convert to HTN: parseFloat(balance.balance) / 100_000_000
   * ```
   */
  async getBalance(address: string): Promise<AddressBalance> {
    return this.request<AddressBalance>(`/address/${address}/balance`);
  }

  /**
   * Get UTXOs for Hoosat addresses
   * Required for building transactions
   *
   * @param addresses - Array of Hoosat addresses
   * @returns List of unspent transaction outputs
   *
   * @example
   * ```typescript
   * const utxos = await client.getUtxos(['hoosat:qz7ulu...']);
   * console.log(`Found ${utxos.utxos.length} UTXOs`);
   *
   * // Use with HoosatTxBuilder
   * const builder = new HoosatTxBuilder();
   * utxos.utxos.forEach(utxo => {
   *   builder.addInput(utxo, privateKey);
   * });
   * ```
   */
  async getUtxos(addresses: string[]): Promise<AddressUtxos> {
    const response = await this.request<any>('/address/utxos', {
      method: 'POST',
      body: JSON.stringify({ addresses }),
    });

    // Adapt API response to TxBuilder format
    // API returns: scriptPublicKey.scriptPublicKey
    // TxBuilder expects: scriptPublicKey.script
    if (response.utxos) {
      response.utxos = response.utxos.map((utxo: any) => ({
        ...utxo,
        utxoEntry: {
          ...utxo.utxoEntry,
          scriptPublicKey: {
            version: utxo.utxoEntry.scriptPublicKey.version,
            script: utxo.utxoEntry.scriptPublicKey.scriptPublicKey, // Rename field
          },
        },
      }));
    }

    return response;
  }

  // ==================== TRANSACTION METHODS ====================

  /**
   * Submit a signed transaction to the network
   *
   * @param transaction - Signed transaction object (from HoosatTxBuilder)
   * @returns Transaction ID
   *
   * @example
   * ```typescript
   * // Build and sign transaction
   * const builder = new HoosatTxBuilder();
   * // ... add inputs, outputs, sign ...
   * const signedTx = builder.sign(privateKey);
   *
   * // Submit to network
   * const result = await client.submitTransaction(signedTx);
   * console.log(`Transaction submitted: ${result.transactionId}`);
   * ```
   */
  async submitTransaction(transaction: Transaction): Promise<TransactionSubmission> {
    return this.request<TransactionSubmission>('/transaction/submit', {
      method: 'POST',
      body: JSON.stringify(transaction),
    });
  }

  // ==================== NETWORK METHODS ====================

  /**
   * Get network information
   *
   * @returns Network status and sync information
   *
   * @example
   * ```typescript
   * const info = await client.getNetworkInfo();
   * console.log(`Network: ${info.networkName}`);
   * console.log(`Synced: ${info.isSynced}`);
   * console.log(`Block height: ${info.blockCount}`);
   * ```
   */
  async getNetworkInfo(): Promise<NetworkInfo> {
    return this.request<NetworkInfo>('/node/info');
  }

  /**
   * Get recommended transaction fees
   *
   * @returns Fee recommendations in sompi per byte
   *
   * @example
   * ```typescript
   * const fees = await client.getFeeEstimate();
   * console.log(`Normal fee: ${fees.medium} sompi/byte`);
   *
   * // Use with HoosatCrypto.calculateFee()
   * const fee = HoosatCrypto.calculateFee(inputCount, outputCount, fees.medium);
   * ```
   */
  async getFeeEstimate(): Promise<FeeRecommendation> {
    return this.request<FeeRecommendation>('/mempool/fee-estimate');
  }

  // ==================== UTILITY METHODS ====================

  /**
   * Check if API is reachable
   *
   * @returns true if API responds successfully
   *
   * @example
   * ```typescript
   * const isOnline = await client.ping();
   * if (!isOnline) {
   *   console.error('API is unreachable');
   * }
   * ```
   */
  async ping(): Promise<boolean> {
    try {
      await this.getNetworkInfo();
      return true;
    } catch (error) {
      return false;
    }
  }

  /**
   * Get current configuration
   *
   * @returns Client configuration
   */
  getConfig(): BrowserClientConfig {
    return {
      baseUrl: this._baseUrl,
      timeout: this._timeout,
      headers: { ...this._headers },
      debug: this._debug,
    };
  }
}
