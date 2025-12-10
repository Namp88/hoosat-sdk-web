import type {
  AddressBalance,
  AddressUtxos,
  TransactionSubmission,
  NetworkInfo,
  FeeRecommendation,
  BrowserClientConfig,
} from './client-web.types';
import type { Transaction } from '@models/transaction.types';
import type { ApiProvider } from './providers/api-provider.interface';
import { HoosatProxyProvider } from './providers/hoosat-proxy-provider';
import type { MultiProvider } from './providers/multi-provider';

/**
 * HoosatWebClient - REST API client for browser-based Hoosat applications
 *
 * Now supports multiple API providers with automatic fallback and extensible architecture.
 * All methods return promises and handle errors gracefully.
 *
 * @example
 * ```typescript
 * // Using single provider (backward compatible)
 * const client = new HoosatWebClient({
 *   baseUrl: 'https://proxy.hoosat.net/api/v1',
 *   timeout: 30000
 * });
 *
 * // Using custom provider
 * const customProvider = new HoosatProxyProvider({ baseUrl: 'https://proxy.hoosat.net/api/v1' });
 * const client = new HoosatWebClient({ provider: customProvider });
 *
 * // Using multiple providers with fallback
 * const multiProvider = new MultiProvider({
 *   providers: [proxyProvider, networkProvider],
 *   strategy: 'failover'
 * });
 * const client = new HoosatWebClient({ provider: multiProvider });
 * ```
 */
export class HoosatWebClient {
  private readonly provider: ApiProvider;

  /**
   * Creates a new HoosatWebClient instance
   *
   * @param config - Client configuration
   * @param config.baseUrl - Base URL of the API (backward compatibility)
   * @param config.provider - Custom API provider instance
   * @param config.timeout - Request timeout in milliseconds (default: 30000)
   * @param config.headers - Additional headers to include in requests
   * @param config.debug - Enable debug logging (default: false)
   */
  constructor(config: BrowserClientConfig & { provider?: ApiProvider }) {
    if (config.provider) {
      this.provider = config.provider;
    } else if (config.baseUrl) {
      this.provider = new HoosatProxyProvider({
        baseUrl: config.baseUrl,
        timeout: config.timeout,
        headers: config.headers,
        debug: config.debug,
      });
    } else {
      throw new Error('Either baseUrl or provider must be specified');
    }
  }

  // ==================== PUBLIC API METHODS ====================

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
    return this.provider.getBalance(address);
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
    return this.provider.getUtxos(addresses);
  }

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
    return this.provider.submitTransaction(transaction);
  }

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
    return this.provider.getNetworkInfo();
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
   * // Use with HoosatCrypto.calculateMinFee()
   * const fee = HoosatCrypto.calculateMinFee(inputCount, outputCount);
   * ```
   */
  async getFeeEstimate(): Promise<FeeRecommendation> {
    return this.provider.getFeeEstimate();
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
    return this.provider.ping();
  }

  /**
   * Get the current API provider instance
   *
   * @returns Current provider
   */
  getProvider(): ApiProvider {
    return this.provider;
  }
}
