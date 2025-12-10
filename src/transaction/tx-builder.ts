import { HOOSAT_PARAMS } from '@constants/hoosat-params.const';
import { HoosatUtils } from '@utils/utils';
import { Transaction, TransactionOutput, UtxoForSigning } from '@models/transaction.types';
import { TxBuilderOptions } from '@transaction/tx-builder.types';
import { SighashReusedValues } from '@crypto/crypto-web.types';
import { HoosatCrypto } from '@crypto/crypto-web';

/**
 * Builder class for creating and signing Hoosat transactions
 *
 * @example
 * const builder = new TxBuilder({ debug: true });
 *
 * builder
 *   .addInput(utxo, privateKey)
 *   .addOutput(recipientAddress, '100000000')
 *   .addChangeOutput(changeAddress)
 *   .setFee('1000');
 *
 * const signedTx = builder.sign();
 */
export class HoosatTxBuilder {
  private _inputs: Array<{ utxo: UtxoForSigning; privateKey?: Buffer }> = [];
  private _outputs: TransactionOutput[] = [];
  private _lockTime = '0';
  private _fee = '1000';
  private _subnetworkId = '0000000000000000000000000000000000000000';
  private _payload = '';
  private _reusedValues: SighashReusedValues = {};
  private _debug: boolean;

  /**
   * Creates a new transaction builder
   * @param options - Builder options
   */
  constructor(options: TxBuilderOptions = {}) {
    this._debug = options.debug || false;
  }

  /**
   * Adds an input to the transaction
   * @param utxo - UTXO to spend
   * @param privateKey - Private key for this specific input (optional if using global key in sign())
   * @returns This builder instance for chaining
   * @example
   * builder.addInput(utxo, privateKey);
   */
  addInput(utxo: UtxoForSigning, privateKey?: Buffer): this {
    this._inputs.push({ utxo, privateKey });
    return this;
  }

  /**
   * Adds an output to the transaction (for recipients only)
   *
   * ⚠️ Use addChangeOutput() for change to avoid spam protection check
   *
   * @param address - Recipient address
   * @param amount - Amount in sompi as string
   * @returns This builder instance for chaining
   * @throws Error if address is invalid
   * @throws Error if exceeds spam protection limit (max 2 recipients)
   *
   * @remarks
   * **Spam Protection:** Hoosat inherits anti-dust-attack protection from Kaspa.
   * Transactions are limited to 3 total outputs (2 recipients + 1 change) to prevent
   * spam attacks. This is a hardcoded network rule, not a configuration setting.
   *
   * **Important:** This validation only counts recipient outputs, not change.
   * Always use `addChangeOutput()` for change outputs.
   *
   * @example
   * // ✅ Correct usage
   * builder.addOutput('hoosat:qz7ulu...', '100000000');     // recipient 1
   * builder.addOutput('hoosat:qr97kz...', '50000000');      // recipient 2
   * builder.addChangeOutput(wallet.address);                // change (no check)
   *
   * @example
   * // ❌ Wrong - manually adding change
   * builder.addOutput(wallet.address, changeAmount); // ← will trigger spam check!
   */
  addOutput(address: string, amount: string): this {
    if (!HoosatUtils.isValidAddress(address)) {
      throw new Error(`Invalid address: ${address}`);
    }

    // Count recipient outputs (change is added via addChangeOutput/addOutputRaw)
    const recipientOutputs = this._outputs.length;

    if (recipientOutputs >= 2) {
      throw new Error(
        'Maximum 2 recipients per transaction due to spam protection. ' +
          'This anti-dust-attack mechanism limits outputs to 3 total (2 recipients + 1 change). ' +
          'Inherited from Kaspa Golang. For more recipients, send multiple transactions. ' +
          'Note: Use addChangeOutput() for change, not addOutput().'
      );
    }

    const scriptPublicKey = HoosatCrypto.addressToScriptPublicKey(address);

    this._outputs.push({
      amount,
      scriptPublicKey: {
        scriptPublicKey: scriptPublicKey.toString('hex'),
        version: 0,
      },
    });

    return this;
  }

  /**
   * Adds change output with automatic amount calculation
   * Change outputs bypass spam protection check
   *
   * @param changeAddress - Address to receive change
   * @returns This builder instance for chaining
   * @throws Error if insufficient funds or invalid address
   * @example
   * builder.addChangeOutput('hoosat:qz7ulu...');
   */
  addChangeOutput(changeAddress: string): this {
    if (!HoosatUtils.isValidAddress(changeAddress)) {
      throw new Error(`Invalid change address: ${changeAddress}`);
    }

    const totalInput = this.getTotalInputAmount();
    const totalOutput = this.getTotalOutputAmount();
    const fee = BigInt(this._fee);
    const changeAmount = totalInput - totalOutput - fee;

    if (changeAmount < 0n) {
      throw new Error(`Insufficient funds for change: inputs ${totalInput}, outputs ${totalOutput}, fee ${fee}`);
    }

    // Only add change output if amount is meaningful (> dust threshold)
    if (changeAmount > BigInt(HOOSAT_PARAMS.MIN_FEE)) {
      // Use addOutputRaw to bypass spam protection check for change
      const scriptPublicKey = HoosatCrypto.addressToScriptPublicKey(changeAddress);

      this.addOutputRaw({
        amount: changeAmount.toString(),
        scriptPublicKey: {
          scriptPublicKey: scriptPublicKey.toString('hex'),
          version: 0,
        },
      });
    }

    return this;
  }

  /**
   * Adds a raw output to the transaction (bypasses validation)
   * Use for change outputs or advanced scenarios
   *
   * @param output - Pre-formatted transaction output
   * @returns This builder instance for chaining
   * @example
   * builder.addOutputRaw({ amount: '100000000', scriptPublicKey: {...} });
   */
  addOutputRaw(output: TransactionOutput): this {
    this._outputs.push(output);
    return this;
  }

  /**
   * Sets transaction fee
   * @param fee - Fee amount in sompi as string
   * @returns This builder instance for chaining
   * @example
   * builder.setFee('1000');
   */
  setFee(fee: string): this {
    this._fee = fee;
    return this;
  }

  /**
   * Sets transaction lock time
   * @param lockTime - Lock time as string
   * @returns This builder instance for chaining
   * @example
   * builder.setLockTime('0');
   */
  setLockTime(lockTime: string): this {
    this._lockTime = lockTime;
    return this;
  }

  /**
   * Sets subnetwork ID for the transaction
   *
   * ⚠️ Payload is disabled on the native subnetwork (0x00...00) until hardfork.
   * Alternative subnetwork IDs may allow payload before the hardfork.
   *
   * @param subnetworkId - Subnetwork ID as hex string (40 chars, 20 bytes)
   * @returns This builder instance for chaining
   * @throws Error if subnetworkId format is invalid
   *
   * @example
   * // Use alternative subnetwork that may support payload
   * builder.setSubnetworkId('0300000000000000000000000000000000000000');
   *
   * @example
   * // Use native subnetwork (default)
   * builder.setSubnetworkId('0000000000000000000000000000000000000000');
   */
  setSubnetworkId(subnetworkId: string): this {
    // Remove 0x prefix if present
    const cleanId = subnetworkId.toLowerCase().replace(/^0x/, '');

    if (!/^[0-9a-f]{40}$/.test(cleanId)) {
      throw new Error(
        `Invalid subnetwork ID format: ${subnetworkId}. ` +
        `Expected 40 hex characters (20 bytes), e.g., "0300000000000000000000000000000000000000"`
      );
    }

    this._subnetworkId = cleanId;
    return this;
  }

  /**
   * Sets payload data for the transaction
   *
   * ⚠️ Payload is disabled on the native subnetwork (0x00...00) until hardfork.
   * Use alternative subnetwork IDs to test payload functionality.
   *
   * @param payload - Payload data as hex string or Buffer
   * @returns This builder instance for chaining
   *
   * @example
   * // Set payload as hex string
   * builder.setPayload('48656c6c6f20576f726c64'); // "Hello World"
   *
   * @example
   * // Set payload from Buffer
   * const data = Buffer.from('Hello World', 'utf-8');
   * builder.setPayload(data.toString('hex'));
   *
   * @example
   * // With alternative subnetwork
   * builder
   *   .setSubnetworkId('0300000000000000000000000000000000000000')
   *   .setPayload('48656c6c6f');
   */
  setPayload(payload: string): this {
    // Remove 0x prefix if present
    const cleanPayload = payload.toLowerCase().replace(/^0x/, '');

    if (cleanPayload.length > 0 && !/^[0-9a-f]*$/.test(cleanPayload)) {
      throw new Error(
        `Invalid payload format: ${payload}. ` +
        `Expected hex string, e.g., "48656c6c6f"`
      );
    }

    this._payload = cleanPayload;
    return this;
  }

  /**
   * Builds unsigned transaction
   * @returns Unsigned transaction object
   * @throws Error if validation fails
   * @example
   * const unsignedTx = builder.build();
   */
  build(): Transaction {
    if (this._inputs.length === 0) {
      throw new Error('Transaction must have at least one input');
    }

    if (this._outputs.length === 0) {
      throw new Error('Transaction must have at least one output');
    }

    // Validate amounts
    this.validate();

    return {
      version: 0,
      inputs: this._inputs.map(({ utxo }) => ({
        previousOutpoint: utxo.outpoint,
        signatureScript: '',
        sequence: '0',
        sigOpCount: 1,
        utxoEntry: utxo.utxoEntry,
      })),
      outputs: this._outputs,
      lockTime: this._lockTime,
      subnetworkId: this._subnetworkId,
      gas: '0',
      payload: this._payload,
      fee: this._fee,
    };
  }

  /**
   * Signs the transaction with provided private key(s)
   * @param globalPrivateKey - Global private key to use for all inputs without specific keys
   * @returns Signed transaction ready for broadcast
   * @throws Error if no private key provided for any input
   * @example
   * const signedTx = builder.sign(privateKey);
   */
  sign(globalPrivateKey?: Buffer): Transaction {
    const transaction = this.build();

    if (this._debug) {
      console.log('\n🔐 === SIGNING PROCESS START ===\n');
    }

    for (let i = 0; i < this._inputs.length; i++) {
      const { utxo, privateKey } = this._inputs[i];
      const keyToUse = privateKey || globalPrivateKey;

      if (!keyToUse) {
        throw new Error(`No private key provided for input ${i}`);
      }

      if (this._debug) {
        console.log(`Input ${i} signing:`);
        console.log(`  UTXO amount: ${utxo.utxoEntry.amount}`);
        console.log(`  Script version: ${utxo.utxoEntry.scriptPublicKey.version}`);
        console.log(`  Script: ${utxo.utxoEntry.scriptPublicKey.script}\n`);
      }

      // Calculate signature hashes
      const schnorrHash = HoosatCrypto.getSignatureHashSchnorr(transaction, i, utxo, this._reusedValues);

      const ecdsaHash = HoosatCrypto.getSignatureHashECDSA(transaction, i, utxo, this._reusedValues);

      if (this._debug) {
        console.log(`  Schnorr Hash: ${schnorrHash.toString('hex')}`);
        console.log(`  ECDSA Hash: ${ecdsaHash.toString('hex')}`);
      }

      // Sign input
      const signature = HoosatCrypto.signTransactionInput(transaction, i, keyToUse, utxo, this._reusedValues);

      if (this._debug) {
        console.log(`  Raw Signature: ${signature.signature.toString('hex')}`);
      }

      // Build signature script: length + (64-byte sig + sigHashType)
      const sigWithType = Buffer.concat([signature.signature, Buffer.from([signature.sigHashType])]);
      const sigScript = Buffer.concat([Buffer.from([sigWithType.length]), sigWithType]);

      if (this._debug) {
        console.log(`  SigScript: ${sigScript.toString('hex')}`);
        console.log(`  SigScript length: ${sigScript.length} bytes\n`);
      }

      transaction.inputs[i].signatureScript = sigScript.toString('hex');
    }

    // Remove utxoEntry from inputs for final transaction
    transaction.inputs.forEach(input => {
      delete input.utxoEntry;
    });

    if (this._debug) {
      console.log('🔐 === SIGNING PROCESS COMPLETE ===\n');
      console.log(`Transaction ID: ${HoosatCrypto.getTransactionId(transaction)}\n`);
    }

    return transaction;
  }

  /**
   * Builds and signs transaction in one step
   * @param globalPrivateKey - Private key to use for all inputs
   * @returns Signed transaction
   * @example
   * const signedTx = builder.buildAndSign(privateKey);
   */
  buildAndSign(globalPrivateKey?: Buffer): Transaction {
    return this.sign(globalPrivateKey);
  }

  /**
   * Estimates minimum transaction fee based on inputs/outputs count
   * @param payloadSize - Payload size in bytes (default: 0)
   * @returns Minimum fee as string
   * @example
   * const fee = builder.estimateFee();
   */
  estimateFee(payloadSize: number = 0): string {
    return HoosatCrypto.calculateMinFee(this._inputs.length, this._outputs.length, payloadSize);
  }

  /**
   * Gets total amount of all inputs
   * @returns Total input amount as bigint
   * @example
   * const totalIn = builder.getTotalInputAmount();
   */
  getTotalInputAmount(): bigint {
    return this._inputs.reduce((sum, { utxo }) => sum + BigInt(utxo.utxoEntry.amount), 0n);
  }

  /**
   * Gets total amount of all outputs
   * @returns Total output amount as bigint
   * @example
   * const totalOut = builder.getTotalOutputAmount();
   */
  getTotalOutputAmount(): bigint {
    return this._outputs.reduce((sum, output) => sum + BigInt(output.amount), 0n);
  }

  /**
   * Validates transaction amounts
   * @throws Error if outputs + fee exceed inputs
   * @example
   * builder.validate(); // throws if invalid
   */
  validate(): void {
    const totalInput = this.getTotalInputAmount();
    const totalOutput = this.getTotalOutputAmount();
    const fee = BigInt(this._fee);

    if (totalOutput + fee > totalInput) {
      throw new Error(`Insufficient funds: inputs ${totalInput}, outputs ${totalOutput}, fee ${fee}`);
    }
  }

  /**
   * Resets builder to initial state
   * @returns This builder instance for chaining
   * @example
   * builder.clear().addInput(...).addOutput(...);
   */
  clear(): this {
    this._inputs = [];
    this._outputs = [];
    this._fee = '1000';
    this._lockTime = '0';
    this._subnetworkId = '0000000000000000000000000000000000000000';
    this._payload = '';
    this._reusedValues = {};
    return this;
  }

  /**
   * Gets current number of inputs
   * @returns Number of inputs
   */
  getInputCount(): number {
    return this._inputs.length;
  }

  /**
   * Gets current number of outputs
   * @returns Number of outputs
   */
  getOutputCount(): number {
    return this._outputs.length;
  }
}
