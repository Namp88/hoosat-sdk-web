import { describe, it, expect } from 'vitest';
import { HoosatCrypto } from '@crypto/crypto-web';
import { HoosatUtils } from '@utils/utils';
import type { Transaction, UtxoForSigning } from '@models/transaction.types';

describe('HoosatCrypto', () => {
  // Test vectors from examples
  const TEST_PRIVATE_KEY = '33a4a81ecd31615c51385299969121707897fb1e167634196f31bd311de5fe43';
  const TEST_PRIVATE_KEY_TESTNET = 'c4f96415b32e27e2612345138cdbc53b5ca2b8bde69b81f852b00880950cb3d6';
  const SIMPLE_PRIVATE_KEY = '0000000000000000000000000000000000000000000000000000000000000001';

  describe('Key Generation', () => {
    it('should generate valid ECDSA keypair for mainnet', () => {
      const wallet = HoosatCrypto.generateKeyPair('mainnet');

      expect(wallet.privateKey).toBeInstanceOf(Buffer);
      expect(wallet.privateKey.length).toBe(32);
      expect(wallet.publicKey).toBeInstanceOf(Buffer);
      expect(wallet.publicKey.length).toBe(33); // Compressed ECDSA
      expect(wallet.address).toMatch(/^hoosat:/);
      expect(HoosatUtils.isValidAddress(wallet.address)).toBe(true);
    });

    it('should generate valid ECDSA keypair for testnet', () => {
      const wallet = HoosatCrypto.generateKeyPair('testnet');

      expect(wallet.privateKey).toBeInstanceOf(Buffer);
      expect(wallet.privateKey.length).toBe(32);
      expect(wallet.publicKey).toBeInstanceOf(Buffer);
      expect(wallet.publicKey.length).toBe(33);
      expect(wallet.address).toMatch(/^hoosattest:/);
      expect(HoosatUtils.isValidAddress(wallet.address)).toBe(true);
    });

    it('should generate different keypairs on multiple calls', () => {
      const wallet1 = HoosatCrypto.generateKeyPair();
      const wallet2 = HoosatCrypto.generateKeyPair();

      expect(wallet1.privateKey.equals(wallet2.privateKey)).toBe(false);
      expect(wallet1.publicKey.equals(wallet2.publicKey)).toBe(false);
      expect(wallet1.address).not.toBe(wallet2.address);
    });

    it('should default to mainnet when network not specified', () => {
      const wallet = HoosatCrypto.generateKeyPair();
      expect(wallet.address).toMatch(/^hoosat:/);
    });
  });

  describe('Key Import', () => {
    it('should import valid mainnet keypair from hex', () => {
      const wallet = HoosatCrypto.importKeyPair(TEST_PRIVATE_KEY, 'mainnet');

      expect(wallet.privateKey.toString('hex')).toBe(TEST_PRIVATE_KEY);
      expect(wallet.publicKey).toBeInstanceOf(Buffer);
      expect(wallet.publicKey.length).toBe(33);
      expect(wallet.address).toMatch(/^hoosat:/);
      expect(HoosatUtils.isValidAddress(wallet.address)).toBe(true);
    });

    it('should import valid testnet keypair from hex', () => {
      const wallet = HoosatCrypto.importKeyPair(TEST_PRIVATE_KEY_TESTNET, 'testnet');

      expect(wallet.privateKey.toString('hex')).toBe(TEST_PRIVATE_KEY_TESTNET);
      expect(wallet.publicKey).toBeInstanceOf(Buffer);
      expect(wallet.publicKey.length).toBe(33);
      expect(wallet.address).toMatch(/^hoosattest:/);
      expect(HoosatUtils.isValidAddress(wallet.address)).toBe(true);
    });

    it('should be deterministic - same private key produces same keypair', () => {
      const wallet1 = HoosatCrypto.importKeyPair(TEST_PRIVATE_KEY, 'mainnet');
      const wallet2 = HoosatCrypto.importKeyPair(TEST_PRIVATE_KEY, 'mainnet');

      expect(wallet1.privateKey.equals(wallet2.privateKey)).toBe(true);
      expect(wallet1.publicKey.equals(wallet2.publicKey)).toBe(true);
      expect(wallet1.address).toBe(wallet2.address);
    });

    it('should generate different addresses for different networks', () => {
      const mainnet = HoosatCrypto.importKeyPair(TEST_PRIVATE_KEY, 'mainnet');
      const testnet = HoosatCrypto.importKeyPair(TEST_PRIVATE_KEY, 'testnet');

      expect(mainnet.publicKey.equals(testnet.publicKey)).toBe(true); // Same pubkey
      expect(mainnet.address).not.toBe(testnet.address); // Different addresses
      expect(mainnet.address).toMatch(/^hoosat:/);
      expect(testnet.address).toMatch(/^hoosattest:/);
    });

    it('should throw error for invalid private key length', () => {
      expect(() => HoosatCrypto.importKeyPair('1234')).toThrow('Private key must be 32 bytes');
      expect(() => HoosatCrypto.importKeyPair('ab'.repeat(16))).toThrow(); // 16 bytes only
    });

    it('should throw error for invalid private key format', () => {
      const invalidKey = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';
      // secp256k1 curve order, invalid private key
      expect(() => HoosatCrypto.importKeyPair(invalidKey + 'ff')).toThrow();
    });

    it('should default to mainnet when network not specified', () => {
      const wallet = HoosatCrypto.importKeyPair(SIMPLE_PRIVATE_KEY);
      expect(wallet.address).toMatch(/^hoosat:/);
    });
  });

  describe('Public Key Derivation', () => {
    it('should derive correct public key from private key', () => {
      const privateKey = Buffer.from(TEST_PRIVATE_KEY, 'hex');
      const publicKey = HoosatCrypto.getPublicKey(privateKey);

      expect(publicKey).toBeInstanceOf(Buffer);
      expect(publicKey.length).toBe(33); // Compressed

      // Verify it matches imported keypair
      const wallet = HoosatCrypto.importKeyPair(TEST_PRIVATE_KEY);
      expect(publicKey.equals(wallet.publicKey)).toBe(true);
    });

    it('should be deterministic', () => {
      const privateKey = Buffer.from(SIMPLE_PRIVATE_KEY, 'hex');
      const pubKey1 = HoosatCrypto.getPublicKey(privateKey);
      const pubKey2 = HoosatCrypto.getPublicKey(privateKey);

      expect(pubKey1.equals(pubKey2)).toBe(true);
    });

    it('should throw error for invalid private key', () => {
      const invalidKey = Buffer.from('00'.repeat(32), 'hex'); // All zeros
      expect(() => HoosatCrypto.getPublicKey(invalidKey)).toThrow('Invalid private key');
    });
  });

  describe('ECDSA Address Generation', () => {
    it('should generate valid mainnet ECDSA address', () => {
      const wallet = HoosatCrypto.generateKeyPair('mainnet');
      const address = HoosatCrypto.publicKeyToAddressECDSA(wallet.publicKey, 'mainnet');

      expect(address).toMatch(/^hoosat:/);
      expect(HoosatUtils.isValidAddress(address)).toBe(true);
      expect(HoosatUtils.getAddressType(address)).toBe('ecdsa');
      expect(HoosatUtils.getAddressVersion(address)).toBe(0x01);
    });

    it('should generate valid testnet ECDSA address', () => {
      const wallet = HoosatCrypto.generateKeyPair('testnet');
      const address = HoosatCrypto.publicKeyToAddressECDSA(wallet.publicKey, 'testnet');

      expect(address).toMatch(/^hoosattest:/);
      expect(HoosatUtils.isValidAddress(address)).toBe(true);
      expect(HoosatUtils.getAddressType(address)).toBe('ecdsa');
      expect(HoosatUtils.getAddressVersion(address)).toBe(0x01);
    });

    it('should be deterministic', () => {
      const wallet = HoosatCrypto.importKeyPair(SIMPLE_PRIVATE_KEY);
      const addr1 = HoosatCrypto.publicKeyToAddressECDSA(wallet.publicKey, 'mainnet');
      const addr2 = HoosatCrypto.publicKeyToAddressECDSA(wallet.publicKey, 'mainnet');

      expect(addr1).toBe(addr2);
    });

    it('should throw error for invalid public key length', () => {
      const invalidPubKey = Buffer.from('02' + 'ab'.repeat(31), 'hex'); // 32 bytes instead of 33
      expect(() => HoosatCrypto.publicKeyToAddressECDSA(invalidPubKey)).toThrow('ECDSA public key must be 33 bytes');
    });

    it('should default to mainnet when network not specified', () => {
      const wallet = HoosatCrypto.generateKeyPair();
      const address = HoosatCrypto.publicKeyToAddressECDSA(wallet.publicKey);

      expect(address).toMatch(/^hoosat:/);
    });
  });

  describe('Schnorr Address Generation', () => {
    it('should generate valid mainnet Schnorr address', () => {
      const schnorrPubKey = Buffer.from('a'.repeat(64), 'hex'); // 32 bytes
      const address = HoosatCrypto.publicKeyToAddress(schnorrPubKey, 'mainnet');

      expect(address).toMatch(/^hoosat:/);
      expect(HoosatUtils.isValidAddress(address)).toBe(true);
      expect(HoosatUtils.getAddressType(address)).toBe('schnorr');
      expect(HoosatUtils.getAddressVersion(address)).toBe(0x00);
    });

    it('should generate valid testnet Schnorr address', () => {
      const schnorrPubKey = Buffer.from('b'.repeat(64), 'hex'); // 32 bytes
      const address = HoosatCrypto.publicKeyToAddress(schnorrPubKey, 'testnet');

      expect(address).toMatch(/^hoosattest:/);
      expect(HoosatUtils.isValidAddress(address)).toBe(true);
      expect(HoosatUtils.getAddressType(address)).toBe('schnorr');
      expect(HoosatUtils.getAddressVersion(address)).toBe(0x00);
    });

    it('should throw error for invalid Schnorr public key length', () => {
      const invalidPubKey = Buffer.from('a'.repeat(66), 'hex'); // 33 bytes instead of 32
      expect(() => HoosatCrypto.publicKeyToAddress(invalidPubKey)).toThrow('Schnorr public key must be 32 bytes');
    });

    it('should default to mainnet when network not specified', () => {
      const schnorrPubKey = Buffer.from('c'.repeat(64), 'hex');
      const address = HoosatCrypto.publicKeyToAddress(schnorrPubKey);

      expect(address).toMatch(/^hoosat:/);
    });
  });

  describe('Address to ScriptPublicKey', () => {
    it('should convert ECDSA address to correct script', () => {
      const wallet = HoosatCrypto.generateKeyPair('mainnet');
      const script = HoosatCrypto.addressToScriptPublicKey(wallet.address);

      expect(script).toBeInstanceOf(Buffer);
      expect(script.length).toBeGreaterThan(33); // pubkey + opcodes

      // Check ECDSA script format: length + pubkey + OP_CHECKSIGECDSA (0xab = 171)
      expect(script[0]).toBe(33); // Length of pubkey
      expect(script[script.length - 1]).toBe(0xab); // OP_CHECKSIGECDSA
    });

    it('should convert Schnorr address to correct script', () => {
      const schnorrPubKey = Buffer.from('d'.repeat(64), 'hex');
      const address = HoosatCrypto.publicKeyToAddress(schnorrPubKey, 'mainnet');
      const script = HoosatCrypto.addressToScriptPublicKey(address);

      expect(script).toBeInstanceOf(Buffer);
      expect(script.length).toBeGreaterThan(32); // pubkey + opcodes

      // Check Schnorr script format: length + pubkey + OP_CHECKSIG (0xac = 172)
      expect(script[0]).toBe(32); // Length of Schnorr pubkey
      expect(script[script.length - 1]).toBe(0xac); // OP_CHECKSIG
    });

    it('should throw error for invalid address', () => {
      expect(() => HoosatCrypto.addressToScriptPublicKey('invalid')).toThrow();
    });

    it('should be deterministic', () => {
      const wallet = HoosatCrypto.generateKeyPair();
      const script1 = HoosatCrypto.addressToScriptPublicKey(wallet.address);
      const script2 = HoosatCrypto.addressToScriptPublicKey(wallet.address);

      expect(script1.equals(script2)).toBe(true);
    });
  });

  describe('Blake3 Hashing', () => {
    it('should compute Blake3 hash correctly', () => {
      const data = Buffer.from('hello world', 'utf8');
      const hash = HoosatCrypto.blake3Hash(data);

      expect(hash).toBeInstanceOf(Buffer);
      expect(hash.length).toBe(32); // Blake3 always outputs 32 bytes
    });

    it('should be deterministic', () => {
      const data = Buffer.from('test data', 'utf8');
      const hash1 = HoosatCrypto.blake3Hash(data);
      const hash2 = HoosatCrypto.blake3Hash(data);

      expect(hash1.equals(hash2)).toBe(true);
    });

    it('should produce different hashes for different data', () => {
      const data1 = Buffer.from('data1', 'utf8');
      const data2 = Buffer.from('data2', 'utf8');

      const hash1 = HoosatCrypto.blake3Hash(data1);
      const hash2 = HoosatCrypto.blake3Hash(data2);

      expect(hash1.equals(hash2)).toBe(false);
    });

    it('should handle empty input', () => {
      const hash = HoosatCrypto.blake3Hash(Buffer.alloc(0));

      expect(hash).toBeInstanceOf(Buffer);
      expect(hash.length).toBe(32);
    });
  });

  describe('Double Blake3 Hashing', () => {
    it('should compute double Blake3 hash correctly', () => {
      const data = Buffer.from('transaction data', 'utf8');
      const hash = HoosatCrypto.doubleBlake3Hash(data);

      expect(hash).toBeInstanceOf(Buffer);
      expect(hash.length).toBe(32);
    });

    it('should be deterministic', () => {
      const data = Buffer.from('test', 'utf8');
      const hash1 = HoosatCrypto.doubleBlake3Hash(data);
      const hash2 = HoosatCrypto.doubleBlake3Hash(data);

      expect(hash1.equals(hash2)).toBe(true);
    });

    it('should produce different result than single hash', () => {
      const data = Buffer.from('data', 'utf8');
      const singleHash = HoosatCrypto.blake3Hash(data);
      const doubleHash = HoosatCrypto.doubleBlake3Hash(data);

      expect(singleHash.equals(doubleHash)).toBe(false);
    });
  });

  describe('Keyed Blake3 Hashing', () => {
    it('should compute keyed hash with Buffer key', () => {
      const key = Buffer.from('a'.repeat(64), 'hex'); // 32 bytes
      const data = Buffer.from('message', 'utf8');
      const hash = HoosatCrypto.blake3KeyedHash(key, data);

      expect(hash).toBeInstanceOf(Buffer);
      expect(hash.length).toBe(32);
    });

    it('should compute keyed hash with string key', () => {
      const key = 'TransactionSigningHash'; // Valid string key
      const data = Buffer.from('message', 'utf8');
      const hash = HoosatCrypto.blake3KeyedHash(key, data);

      expect(hash).toBeInstanceOf(Buffer);
      expect(hash.length).toBe(32);
    });

    it('should be deterministic with same key', () => {
      const key = Buffer.from('b'.repeat(64), 'hex');
      const data = Buffer.from('test', 'utf8');

      const hash1 = HoosatCrypto.blake3KeyedHash(key, data);
      const hash2 = HoosatCrypto.blake3KeyedHash(key, data);

      expect(hash1.equals(hash2)).toBe(true);
    });

    it('should produce different hashes for different keys', () => {
      const key1 = Buffer.from('a'.repeat(64), 'hex');
      const key2 = Buffer.from('b'.repeat(64), 'hex');
      const data = Buffer.from('data', 'utf8');

      const hash1 = HoosatCrypto.blake3KeyedHash(key1, data);
      const hash2 = HoosatCrypto.blake3KeyedHash(key2, data);

      expect(hash1.equals(hash2)).toBe(false);
    });

    it('should throw error for invalid key length', () => {
      const shortKey = Buffer.from('ab', 'hex'); // Only 1 byte
      const data = Buffer.from('data', 'utf8');

      expect(() => HoosatCrypto.blake3KeyedHash(shortKey, data)).toThrow('Blake3 key must be 32 bytes');
    });
  });

  describe('Transaction Signature Hashing', () => {
    // Create a minimal mock transaction for testing signature hashes
    const createMockTransaction = (): Transaction => ({
      version: 0,
      inputs: [
        {
          previousOutpoint: {
            transactionId: 'a'.repeat(64),
            index: 0,
          },
          signatureScript: '',
          sequence: '0',
          sigOpCount: 1,
        },
      ],
      outputs: [
        {
          amount: '100000000',
          scriptPublicKey: {
            version: 0,
            scriptPublicKey: '21' + 'b'.repeat(66) + 'ac', // Mock ECDSA script
          },
        },
      ],
      lockTime: '0',
      subnetworkId: '0000000000000000000000000000000000000000',
      gas: '0',
      payload: '',
    });

    const createMockUtxo = (): UtxoForSigning => ({
      outpoint: {
        transactionId: 'a'.repeat(64),
        index: 0,
      },
      utxoEntry: {
        amount: '200000000',
        scriptPublicKey: {
          version: 0,
          script: '21' + 'c'.repeat(66) + 'ac',
        },
        blockDaaScore: '0',
        isCoinbase: false,
      },
    });

    it('should compute Schnorr signature hash', () => {
      const tx = createMockTransaction();
      const utxo = createMockUtxo();

      const hash = HoosatCrypto.getSignatureHashSchnorr(tx, 0, utxo);

      expect(hash).toBeInstanceOf(Buffer);
      expect(hash.length).toBe(32); // Blake3 hash is always 32 bytes
    });

    it('should compute ECDSA signature hash', () => {
      const tx = createMockTransaction();
      const utxo = createMockUtxo();

      const hash = HoosatCrypto.getSignatureHashECDSA(tx, 0, utxo);

      expect(hash).toBeInstanceOf(Buffer);
      expect(hash.length).toBe(32); // SHA256 hash is always 32 bytes
    });

    it('should produce different hashes for Schnorr and ECDSA', () => {
      const tx = createMockTransaction();
      const utxo = createMockUtxo();

      const schnorrHash = HoosatCrypto.getSignatureHashSchnorr(tx, 0, utxo);
      const ecdsaHash = HoosatCrypto.getSignatureHashECDSA(tx, 0, utxo);

      expect(schnorrHash.equals(ecdsaHash)).toBe(false);
    });

    it('should be deterministic - same transaction produces same hashes', () => {
      const tx = createMockTransaction();
      const utxo = createMockUtxo();

      const hash1 = HoosatCrypto.getSignatureHashECDSA(tx, 0, utxo);
      const hash2 = HoosatCrypto.getSignatureHashECDSA(tx, 0, utxo);

      expect(hash1.equals(hash2)).toBe(true);
    });
  });

  describe('Transaction Input Signing', () => {
    const createMockTransaction = (): Transaction => ({
      version: 0,
      inputs: [
        {
          previousOutpoint: {
            transactionId: 'a'.repeat(64),
            index: 0,
          },
          signatureScript: '',
          sequence: '0',
          sigOpCount: 1,
        },
      ],
      outputs: [
        {
          amount: '100000000',
          scriptPublicKey: {
            version: 0,
            scriptPublicKey: '21' + 'b'.repeat(66) + 'ac',
          },
        },
      ],
      lockTime: '0',
      subnetworkId: '0000000000000000000000000000000000000000',
      gas: '0',
      payload: '',
    });

    const createMockUtxo = (): UtxoForSigning => ({
      outpoint: {
        transactionId: 'a'.repeat(64),
        index: 0,
      },
      utxoEntry: {
        amount: '200000000',
        scriptPublicKey: {
          version: 0,
          script: '21' + 'c'.repeat(66) + 'ac',
        },
        blockDaaScore: '0',
        isCoinbase: false,
      },
    });

    it('should sign transaction input correctly', () => {
      const wallet = HoosatCrypto.generateKeyPair();
      const tx = createMockTransaction();
      const utxo = createMockUtxo();

      const result = HoosatCrypto.signTransactionInput(tx, 0, wallet.privateKey, utxo);

      expect(result).toHaveProperty('signature');
      expect(result).toHaveProperty('publicKey');
      expect(result).toHaveProperty('sigHashType');
      expect(result.signature).toBeInstanceOf(Buffer);
      expect(result.signature.length).toBe(64); // Raw ECDSA signature
      expect(result.publicKey.equals(wallet.publicKey)).toBe(true);
      expect(result.sigHashType).toBe(1); // SIGHASH_ALL
    });

    it('should verify signed transaction input', () => {
      const wallet = HoosatCrypto.generateKeyPair();
      const tx = createMockTransaction();
      const utxo = createMockUtxo();

      const signature = HoosatCrypto.signTransactionInput(tx, 0, wallet.privateKey, utxo);

      const isValid = HoosatCrypto.verifyTransactionSignature(tx, 0, signature.signature, wallet.publicKey, utxo);

      expect(isValid).toBe(true);
    });

    it('should fail verification with wrong public key', () => {
      const wallet1 = HoosatCrypto.generateKeyPair();
      const wallet2 = HoosatCrypto.generateKeyPair();
      const tx = createMockTransaction();
      const utxo = createMockUtxo();

      const signature = HoosatCrypto.signTransactionInput(tx, 0, wallet1.privateKey, utxo);

      const isValid = HoosatCrypto.verifyTransactionSignature(
        tx,
        0,
        signature.signature,
        wallet2.publicKey, // Wrong public key
        utxo
      );

      expect(isValid).toBe(false);
    });

    it('should be deterministic - same input produces same signature', () => {
      const wallet = HoosatCrypto.generateKeyPair();
      const tx = createMockTransaction();
      const utxo = createMockUtxo();

      const sig1 = HoosatCrypto.signTransactionInput(tx, 0, wallet.privateKey, utxo);
      const sig2 = HoosatCrypto.signTransactionInput(tx, 0, wallet.privateKey, utxo);

      expect(sig1.signature.equals(sig2.signature)).toBe(true);
    });
  });

  describe('Transaction ID Calculation', () => {
    const createMockTransaction = (): Transaction => ({
      version: 0,
      inputs: [
        {
          previousOutpoint: {
            transactionId: 'a'.repeat(64),
            index: 0,
          },
          signatureScript: '41' + 'b'.repeat(130), // Mock signature
          sequence: '0',
          sigOpCount: 1,
        },
      ],
      outputs: [
        {
          amount: '100000000',
          scriptPublicKey: {
            version: 0,
            scriptPublicKey: '21' + 'c'.repeat(66) + 'ac',
          },
        },
      ],
      lockTime: '0',
      subnetworkId: '0000000000000000000000000000000000000000',
      gas: '0',
      payload: '',
    });

    it('should calculate transaction ID', () => {
      const tx = createMockTransaction();
      const txId = HoosatCrypto.getTransactionId(tx);

      expect(txId).toBeTruthy();
      expect(typeof txId).toBe('string');
      expect(txId.length).toBe(64); // Hex string of 32-byte hash
      expect(/^[0-9a-f]{64}$/.test(txId)).toBe(true); // Valid hex
    });

    it('should be deterministic - same transaction produces same ID', () => {
      const tx = createMockTransaction();

      const txId1 = HoosatCrypto.getTransactionId(tx);
      const txId2 = HoosatCrypto.getTransactionId(tx);

      expect(txId1).toBe(txId2);
    });

    it('should produce different IDs for different transactions', () => {
      const tx1 = createMockTransaction();
      const tx2 = createMockTransaction();
      tx2.outputs[0].amount = '200000000'; // Different amount

      const txId1 = HoosatCrypto.getTransactionId(tx1);
      const txId2 = HoosatCrypto.getTransactionId(tx2);

      expect(txId1).not.toBe(txId2);
    });

    it('should be valid transaction ID format', () => {
      const tx = createMockTransaction();
      const txId = HoosatCrypto.getTransactionId(tx);

      expect(HoosatUtils.isValidTransactionId(txId)).toBe(true);
    });
  });

  describe('Fee Calculation', () => {
    it('should calculate fee for simple transaction', () => {
      const fee = HoosatCrypto.calculateFee(1, 2); // 1 input, 2 outputs

      expect(fee).toBeTruthy();
      expect(typeof fee).toBe('string');
      expect(parseInt(fee)).toBeGreaterThan(0);
    });

    it('should respect minimum fee threshold', () => {
      const fee = HoosatCrypto.calculateFee(1, 1, 1); // Minimal transaction
      const feeValue = parseInt(fee);

      // Fee should be at least reasonable minimum (allow some flexibility)
      expect(feeValue).toBeGreaterThanOrEqual(1000);
      expect(feeValue).toBeLessThan(10000);
    });

    it('should use default fee rate when not specified', () => {
      const feeDefault = HoosatCrypto.calculateFee(1, 2);
      const feeExplicit = HoosatCrypto.calculateFee(1, 2, 1); // DEFAULT_FEE_PER_BYTE = 1

      expect(feeDefault).toBe(feeExplicit);
    });

    it('should return fee as string', () => {
      const fee = HoosatCrypto.calculateFee(2, 2, 5);

      expect(typeof fee).toBe('string');
      expect(/^\d+$/.test(fee)).toBe(true); // Valid integer string
    });
  });

  describe('Network Type Validation', () => {
    it('should accept "mainnet" network parameter', () => {
      expect(() => HoosatCrypto.generateKeyPair('mainnet')).not.toThrow();
      expect(() => HoosatCrypto.importKeyPair(SIMPLE_PRIVATE_KEY, 'mainnet')).not.toThrow();
    });

    it('should accept "testnet" network parameter', () => {
      expect(() => HoosatCrypto.generateKeyPair('testnet')).not.toThrow();
      expect(() => HoosatCrypto.importKeyPair(SIMPLE_PRIVATE_KEY, 'testnet')).not.toThrow();
    });

    it('should use mainnet as default', () => {
      const wallet = HoosatCrypto.generateKeyPair();
      expect(HoosatUtils.getAddressNetwork(wallet.address)).toBe('mainnet');
    });
  });
});
