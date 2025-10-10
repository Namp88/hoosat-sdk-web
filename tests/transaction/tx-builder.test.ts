import { describe, it, expect, beforeEach } from 'vitest';
import { HoosatTxBuilder } from '@transaction/tx-builder';
import { HoosatCrypto } from '@crypto/crypto-web';
import type { UtxoForSigning } from '@models/transaction.types';

// Helper to create mock UTXO
const createMockUtxo = (amount: string, address: string): UtxoForSigning => {
  const scriptPubKey = HoosatCrypto.addressToScriptPublicKey(address);

  return {
    outpoint: {
      transactionId: 'a'.repeat(64),
      index: 0,
    },
    utxoEntry: {
      amount,
      scriptPublicKey: {
        script: scriptPubKey.toString('hex'),
        version: 0,
      },
      blockDaaScore: '1000000',
      isCoinbase: false,
    },
  };
};

describe('HoosatTxBuilder', () => {
  let builder: HoosatTxBuilder;
  let wallet: ReturnType<typeof HoosatCrypto.generateKeyPair>;
  let recipientAddress: string;

  beforeEach(() => {
    builder = new HoosatTxBuilder();
    wallet = HoosatCrypto.generateKeyPair();
    recipientAddress = HoosatCrypto.generateKeyPair().address;
  });

  describe('Constructor', () => {
    it('should create instance with default options', () => {
      expect(builder).toBeInstanceOf(HoosatTxBuilder);
    });

    it('should accept debug option', () => {
      const debugBuilder = new HoosatTxBuilder({ debug: true });
      expect(debugBuilder).toBeInstanceOf(HoosatTxBuilder);
    });

    it('should start with empty inputs and outputs', () => {
      expect(builder.getInputCount()).toBe(0);
      expect(builder.getOutputCount()).toBe(0);
    });
  });

  describe('addInput()', () => {
    it('should add input to transaction', () => {
      const utxo = createMockUtxo('100000000', wallet.address);

      builder.addInput(utxo, wallet.privateKey);

      expect(builder.getInputCount()).toBe(1);
    });

    it('should add multiple inputs', () => {
      const utxo1 = createMockUtxo('100000000', wallet.address);
      const utxo2 = createMockUtxo('200000000', wallet.address);

      builder.addInput(utxo1, wallet.privateKey);
      builder.addInput(utxo2, wallet.privateKey);

      expect(builder.getInputCount()).toBe(2);
    });

    it('should support chaining', () => {
      const utxo = createMockUtxo('100000000', wallet.address);

      const result = builder.addInput(utxo, wallet.privateKey);

      expect(result).toBe(builder);
    });

    it('should accept input without privateKey', () => {
      const utxo = createMockUtxo('100000000', wallet.address);

      expect(() => builder.addInput(utxo)).not.toThrow();
      expect(builder.getInputCount()).toBe(1);
    });
  });

  describe('addOutput()', () => {
    it('should add output to transaction', () => {
      builder.addOutput(recipientAddress, '50000000');

      expect(builder.getOutputCount()).toBe(1);
    });

    it('should throw error for invalid address', () => {
      expect(() => builder.addOutput('invalid', '50000000')).toThrow('Invalid address');
    });

    it('should allow max 2 recipient outputs (spam protection)', () => {
      const recipient1 = HoosatCrypto.generateKeyPair().address;
      const recipient2 = HoosatCrypto.generateKeyPair().address;

      builder.addOutput(recipient1, '50000000');
      builder.addOutput(recipient2, '50000000');

      expect(builder.getOutputCount()).toBe(2);
    });

    it('should throw error when exceeding 2 recipient outputs', () => {
      const recipient1 = HoosatCrypto.generateKeyPair().address;
      const recipient2 = HoosatCrypto.generateKeyPair().address;
      const recipient3 = HoosatCrypto.generateKeyPair().address;

      builder.addOutput(recipient1, '50000000');
      builder.addOutput(recipient2, '50000000');

      expect(() => builder.addOutput(recipient3, '50000000')).toThrow('spam protection');
    });

    it('should support chaining', () => {
      const result = builder.addOutput(recipientAddress, '50000000');

      expect(result).toBe(builder);
    });
  });

  describe('addChangeOutput()', () => {
    it('should calculate and add change output automatically', () => {
      const utxo = createMockUtxo('100000000', wallet.address);

      builder.addInput(utxo, wallet.privateKey);
      builder.addOutput(recipientAddress, '50000000');
      builder.setFee('2500');
      builder.addChangeOutput(wallet.address);

      expect(builder.getOutputCount()).toBe(2); // recipient + change
    });

    it('should not add change output if change is below dust threshold', () => {
      const utxo = createMockUtxo('100000', wallet.address); // Small amount

      builder.addInput(utxo, wallet.privateKey);
      builder.addOutput(recipientAddress, '95000');
      builder.setFee('2500'); // change would be ~2500 sompi (dust)
      builder.addChangeOutput(wallet.address);

      expect(builder.getOutputCount()).toBe(1); // Only recipient, no change
    });

    it('should support chaining', () => {
      const utxo = createMockUtxo('100000000', wallet.address);

      builder.addInput(utxo, wallet.privateKey);
      builder.addOutput(recipientAddress, '50000000');
      builder.setFee('2500');

      const result = builder.addChangeOutput(wallet.address);

      expect(result).toBe(builder);
    });

    it('should throw error for invalid change address', () => {
      const utxo = createMockUtxo('100000000', wallet.address);

      builder.addInput(utxo, wallet.privateKey);
      builder.addOutput(recipientAddress, '50000000');

      expect(() => builder.addChangeOutput('invalid')).toThrow('Invalid change address');
    });
  });

  describe('addOutputRaw()', () => {
    it('should add raw output bypassing validation', () => {
      const scriptPubKey = HoosatCrypto.addressToScriptPublicKey(recipientAddress);

      builder.addOutputRaw({
        amount: '50000000',
        scriptPublicKey: {
          scriptPublicKey: scriptPubKey.toString('hex'),
          version: 0,
        },
      });

      expect(builder.getOutputCount()).toBe(1);
    });

    it('should allow adding more than 2 outputs via addOutputRaw', () => {
      const scriptPubKey = HoosatCrypto.addressToScriptPublicKey(recipientAddress);

      builder.addOutputRaw({ amount: '10000000', scriptPublicKey: { scriptPublicKey: scriptPubKey.toString('hex'), version: 0 } });
      builder.addOutputRaw({ amount: '20000000', scriptPublicKey: { scriptPublicKey: scriptPubKey.toString('hex'), version: 0 } });
      builder.addOutputRaw({ amount: '30000000', scriptPublicKey: { scriptPublicKey: scriptPubKey.toString('hex'), version: 0 } });

      expect(builder.getOutputCount()).toBe(3);
    });

    it('should support chaining', () => {
      const scriptPubKey = HoosatCrypto.addressToScriptPublicKey(recipientAddress);

      const result = builder.addOutputRaw({
        amount: '50000000',
        scriptPublicKey: {
          scriptPublicKey: scriptPubKey.toString('hex'),
          version: 0,
        },
      });

      expect(result).toBe(builder);
    });
  });

  describe('setFee()', () => {
    it('should set transaction fee', () => {
      builder.setFee('5000');

      // Fee is set internally, check via validate or build
      expect(() => builder.setFee('5000')).not.toThrow();
    });

    it('should support chaining', () => {
      const result = builder.setFee('5000');

      expect(result).toBe(builder);
    });

    it('should accept fee as string', () => {
      expect(() => builder.setFee('10000')).not.toThrow();
    });
  });

  describe('setLockTime()', () => {
    it('should set transaction lock time', () => {
      builder.setLockTime('1000');

      expect(() => builder.setLockTime('1000')).not.toThrow();
    });

    it('should support chaining', () => {
      const result = builder.setLockTime('1000');

      expect(result).toBe(builder);
    });
  });

  describe('getTotalInputAmount()', () => {
    it('should return 0 for no inputs', () => {
      expect(builder.getTotalInputAmount()).toBe(0n);
    });

    it('should calculate total input amount', () => {
      const utxo1 = createMockUtxo('100000000', wallet.address);
      const utxo2 = createMockUtxo('200000000', wallet.address);

      builder.addInput(utxo1, wallet.privateKey);
      builder.addInput(utxo2, wallet.privateKey);

      expect(builder.getTotalInputAmount()).toBe(300000000n);
    });
  });

  describe('getTotalOutputAmount()', () => {
    it('should return 0 for no outputs', () => {
      expect(builder.getTotalOutputAmount()).toBe(0n);
    });

    it('should calculate total output amount', () => {
      const recipient1 = HoosatCrypto.generateKeyPair().address;
      const recipient2 = HoosatCrypto.generateKeyPair().address;

      builder.addOutput(recipient1, '50000000');
      builder.addOutput(recipient2, '30000000');

      expect(builder.getTotalOutputAmount()).toBe(80000000n);
    });
  });

  describe('estimateFee()', () => {
    it('should estimate fee based on inputs/outputs', () => {
      const utxo = createMockUtxo('100000000', wallet.address);

      builder.addInput(utxo, wallet.privateKey);
      builder.addOutput(recipientAddress, '50000000');

      const fee = builder.estimateFee();

      expect(fee).toBeTruthy();
      expect(parseInt(fee)).toBeGreaterThan(0);
    });

    it('should accept custom fee rate', () => {
      // Create large transaction with many inputs to exceed MIN_FEE
      for (let i = 0; i < 10; i++) {
        const utxo = createMockUtxo('10000000', wallet.address);
        builder.addInput(utxo, wallet.privateKey);
      }

      builder.addOutput(recipientAddress, '50000000');

      const feeRate1 = 1;
      const feeRate10 = 10;

      const fee1 = parseInt(builder.estimateFee(feeRate1));
      const fee10 = parseInt(builder.estimateFee(feeRate10));

      // With 10 inputs, fee should scale with rate
      expect(fee10).toBeGreaterThan(fee1);
    });
  });

  describe('validate()', () => {
    it('should pass validation for valid transaction', () => {
      const utxo = createMockUtxo('100000000', wallet.address);

      builder.addInput(utxo, wallet.privateKey);
      builder.addOutput(recipientAddress, '50000000');
      builder.setFee('2500');

      expect(() => builder.validate()).not.toThrow();
    });

    it('should throw error if outputs + fee exceed inputs', () => {
      const utxo = createMockUtxo('100000000', wallet.address);

      builder.addInput(utxo, wallet.privateKey);
      builder.addOutput(recipientAddress, '99000000');
      builder.setFee('2000000'); // Total > input

      expect(() => builder.validate()).toThrow('Insufficient funds');
    });
  });

  describe('build()', () => {
    it('should build unsigned transaction', () => {
      const utxo = createMockUtxo('100000000', wallet.address);

      builder.addInput(utxo, wallet.privateKey);
      builder.addOutput(recipientAddress, '50000000');
      builder.setFee('2500');

      const tx = builder.build();

      expect(tx).toHaveProperty('version');
      expect(tx).toHaveProperty('inputs');
      expect(tx).toHaveProperty('outputs');
      expect(tx.inputs.length).toBe(1);
      expect(tx.outputs.length).toBe(1);
    });

    it('should throw error if no inputs', () => {
      builder.addOutput(recipientAddress, '50000000');

      expect(() => builder.build()).toThrow('at least one input');
    });

    it('should throw error if no outputs', () => {
      const utxo = createMockUtxo('100000000', wallet.address);

      builder.addInput(utxo, wallet.privateKey);

      expect(() => builder.build()).toThrow('at least one output');
    });

    it('should validate amounts when building', () => {
      const utxo = createMockUtxo('100000000', wallet.address);

      builder.addInput(utxo, wallet.privateKey);
      builder.addOutput(recipientAddress, '150000000'); // More than input

      expect(() => builder.build()).toThrow('Insufficient funds');
    });
  });

  describe('sign()', () => {
    it('should sign transaction with global private key', () => {
      const utxo = createMockUtxo('100000000', wallet.address);

      builder.addInput(utxo); // No key per input
      builder.addOutput(recipientAddress, '50000000');
      builder.setFee('2500');

      const signedTx = builder.sign(wallet.privateKey);

      expect(signedTx.inputs[0].signatureScript).toBeTruthy();
      expect(signedTx.inputs[0].signatureScript.length).toBeGreaterThan(0);
    });

    it('should sign transaction with per-input private keys', () => {
      const utxo = createMockUtxo('100000000', wallet.address);

      builder.addInput(utxo, wallet.privateKey);
      builder.addOutput(recipientAddress, '50000000');
      builder.setFee('2500');

      const signedTx = builder.sign();

      expect(signedTx.inputs[0].signatureScript).toBeTruthy();
    });

    it('should throw error if no private key provided', () => {
      const utxo = createMockUtxo('100000000', wallet.address);

      builder.addInput(utxo); // No key
      builder.addOutput(recipientAddress, '50000000');

      expect(() => builder.sign()).toThrow('No private key');
    });

    it('should remove utxoEntry from signed transaction', () => {
      const utxo = createMockUtxo('100000000', wallet.address);

      builder.addInput(utxo, wallet.privateKey);
      builder.addOutput(recipientAddress, '50000000');
      builder.setFee('2500');

      const signedTx = builder.sign();

      expect(signedTx.inputs[0].utxoEntry).toBeUndefined();
    });

    it('should produce valid transaction ID', () => {
      const utxo = createMockUtxo('100000000', wallet.address);

      builder.addInput(utxo, wallet.privateKey);
      builder.addOutput(recipientAddress, '50000000');
      builder.setFee('2500');

      const signedTx = builder.sign();
      const txId = HoosatCrypto.getTransactionId(signedTx);

      expect(txId).toBeTruthy();
      expect(txId.length).toBe(64);
      expect(/^[0-9a-f]{64}$/.test(txId)).toBe(true);
    });
  });

  describe('buildAndSign()', () => {
    it('should build and sign in one step', () => {
      const utxo = createMockUtxo('100000000', wallet.address);

      builder.addInput(utxo, wallet.privateKey);
      builder.addOutput(recipientAddress, '50000000');
      builder.setFee('2500');

      const signedTx = builder.buildAndSign();

      expect(signedTx.inputs[0].signatureScript).toBeTruthy();
    });

    it('should accept global private key', () => {
      const utxo = createMockUtxo('100000000', wallet.address);

      builder.addInput(utxo);
      builder.addOutput(recipientAddress, '50000000');
      builder.setFee('2500');

      const signedTx = builder.buildAndSign(wallet.privateKey);

      expect(signedTx.inputs[0].signatureScript).toBeTruthy();
    });
  });

  describe('clear()', () => {
    it('should reset builder to initial state', () => {
      const utxo = createMockUtxo('100000000', wallet.address);

      builder.addInput(utxo, wallet.privateKey);
      builder.addOutput(recipientAddress, '50000000');
      builder.setFee('5000');

      builder.clear();

      expect(builder.getInputCount()).toBe(0);
      expect(builder.getOutputCount()).toBe(0);
    });

    it('should support chaining', () => {
      const result = builder.clear();

      expect(result).toBe(builder);
    });

    it('should allow rebuilding after clear', () => {
      const utxo = createMockUtxo('100000000', wallet.address);

      builder.addInput(utxo, wallet.privateKey);
      builder.addOutput(recipientAddress, '50000000');
      builder.clear();

      // Should be able to build new transaction
      builder.addInput(utxo, wallet.privateKey);
      builder.addOutput(recipientAddress, '30000000');
      builder.setFee('2500');

      expect(() => builder.build()).not.toThrow();
    });
  });

  describe('Complete Transaction Flow', () => {
    it('should create simple transaction (1 input, 1 output + change)', () => {
      const utxo = createMockUtxo('100000000', wallet.address);

      const signedTx = builder
        .addInput(utxo, wallet.privateKey)
        .addOutput(recipientAddress, '50000000')
        .setFee('2500')
        .addChangeOutput(wallet.address)
        .buildAndSign();

      expect(signedTx.inputs.length).toBe(1);
      expect(signedTx.outputs.length).toBe(2); // recipient + change
      expect(signedTx.inputs[0].signatureScript).toBeTruthy();
    });

    it('should create batch transaction (1 input, 2 recipients + change)', () => {
      const utxo = createMockUtxo('500000000', wallet.address);
      const recipient1 = HoosatCrypto.generateKeyPair().address;
      const recipient2 = HoosatCrypto.generateKeyPair().address;

      const signedTx = builder
        .addInput(utxo, wallet.privateKey)
        .addOutput(recipient1, '150000000')
        .addOutput(recipient2, '100000000')
        .setFee('2500')
        .addChangeOutput(wallet.address)
        .buildAndSign();

      expect(signedTx.inputs.length).toBe(1);
      expect(signedTx.outputs.length).toBe(3); // 2 recipients + change
    });

    it('should create transaction with multiple inputs', () => {
      const utxo1 = createMockUtxo('50000000', wallet.address);
      const utxo2 = createMockUtxo('80000000', wallet.address);

      const signedTx = builder
        .addInput(utxo1, wallet.privateKey)
        .addInput(utxo2, wallet.privateKey)
        .addOutput(recipientAddress, '100000000')
        .setFee('5000')
        .addChangeOutput(wallet.address)
        .buildAndSign();

      expect(signedTx.inputs.length).toBe(2);
      expect(signedTx.outputs.length).toBe(2); // recipient + change
    });

    it('should create transaction without change (exact amount)', () => {
      const utxo = createMockUtxo('100000000', wallet.address);

      const signedTx = builder.addInput(utxo, wallet.privateKey).addOutput(recipientAddress, '99997500').setFee('2500').buildAndSign();

      expect(signedTx.inputs.length).toBe(1);
      expect(signedTx.outputs.length).toBe(1); // Only recipient, no change
    });
  });
});
