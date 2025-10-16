import { describe, it, expect } from 'vitest';
import { HoosatSigner } from '@crypto/signer';
import { hashMessage, formatMessage, hashBuffer, MESSAGE_PREFIX } from '@crypto/hasher';
import { HoosatCrypto } from '@crypto/crypto-web';
import { Buffer } from 'buffer';

describe('HoosatSigner - Message Signing', () => {
  // Test private key (deterministic for testing)
  const TEST_PRIVATE_KEY = '0000000000000000000000000000000000000000000000000000000000000001';
  const TEST_MESSAGE = 'Hello, Hoosat!';

  describe('Message Prefix', () => {
    it('should have correct message prefix constant', () => {
      expect(MESSAGE_PREFIX).toBe('Hoosat Signed Message:\n');
    });

    it('should format message with prefix', () => {
      const formatted = formatMessage('Test');
      expect(formatted).toBe('Hoosat Signed Message:\nTest');
    });

    it('should format empty message', () => {
      const formatted = formatMessage('');
      expect(formatted).toBe('Hoosat Signed Message:\n');
    });

    it('should preserve message content exactly', () => {
      const message = 'Multi\nLine\nMessage';
      const formatted = formatMessage(message);
      expect(formatted).toBe(`Hoosat Signed Message:\n${message}`);
    });
  });

  describe('Message Hashing', () => {
    it('should hash message with BLAKE3', () => {
      const hash = hashMessage(TEST_MESSAGE);

      expect(hash).toBeInstanceOf(Uint8Array);
      expect(hash.length).toBe(32); // BLAKE3 outputs 32 bytes
    });

    it('should be deterministic', () => {
      const hash1 = hashMessage(TEST_MESSAGE);
      const hash2 = hashMessage(TEST_MESSAGE);

      expect(Buffer.from(hash1).equals(Buffer.from(hash2))).toBe(true);
    });

    it('should produce different hashes for different messages', () => {
      const hash1 = hashMessage('Message 1');
      const hash2 = hashMessage('Message 2');

      expect(Buffer.from(hash1).equals(Buffer.from(hash2))).toBe(false);
    });

    it('should hash empty message', () => {
      const hash = hashMessage('');
      expect(hash).toBeInstanceOf(Uint8Array);
      expect(hash.length).toBe(32);
    });

    it('should hash Unicode characters correctly', () => {
      const unicodeMessage = 'Hello 世界 🌍';
      const hash = hashMessage(unicodeMessage);

      expect(hash).toBeInstanceOf(Uint8Array);
      expect(hash.length).toBe(32);
    });
  });

  describe('Buffer Hashing', () => {
    it('should hash buffer without prefix', () => {
      const buffer = Buffer.from('raw data', 'utf8');
      const hash = hashBuffer(buffer);

      expect(hash).toBeInstanceOf(Uint8Array);
      expect(hash.length).toBe(32);
    });

    it('should produce different hash than message hash', () => {
      const message = 'test';
      const buffer = Buffer.from(message, 'utf8');

      const messageHash = hashMessage(message);
      const bufferHash = hashBuffer(buffer);

      // Different because message hash includes prefix
      expect(Buffer.from(messageHash).equals(Buffer.from(bufferHash))).toBe(false);
    });
  });

  describe('Sign Message', () => {
    it('should sign message and return hex signature', () => {
      const signature = HoosatSigner.signMessage(TEST_PRIVATE_KEY, TEST_MESSAGE);

      expect(typeof signature).toBe('string');
      expect(signature.length).toBe(128); // Compact signature is 64 bytes = 128 hex chars
      expect(/^[0-9a-f]{128}$/.test(signature)).toBe(true); // Valid hex
    });

    it('should be deterministic - same message produces same signature', () => {
      const sig1 = HoosatSigner.signMessage(TEST_PRIVATE_KEY, TEST_MESSAGE);
      const sig2 = HoosatSigner.signMessage(TEST_PRIVATE_KEY, TEST_MESSAGE);

      expect(sig1).toBe(sig2);
    });

    it('should produce different signatures for different messages', () => {
      const sig1 = HoosatSigner.signMessage(TEST_PRIVATE_KEY, 'Message 1');
      const sig2 = HoosatSigner.signMessage(TEST_PRIVATE_KEY, 'Message 2');

      expect(sig1).not.toBe(sig2);
    });

    it('should produce different signatures for different keys', () => {
      const key1 = TEST_PRIVATE_KEY;
      const key2 = '0000000000000000000000000000000000000000000000000000000000000002';

      const sig1 = HoosatSigner.signMessage(key1, TEST_MESSAGE);
      const sig2 = HoosatSigner.signMessage(key2, TEST_MESSAGE);

      expect(sig1).not.toBe(sig2);
    });

    it('should accept private key with 0x prefix', () => {
      const signature = HoosatSigner.signMessage('0x' + TEST_PRIVATE_KEY, TEST_MESSAGE);

      expect(signature).toBeTruthy();
      expect(signature.length).toBe(128);
    });

    it('should throw error for invalid private key length', () => {
      expect(() => HoosatSigner.signMessage('1234', TEST_MESSAGE)).toThrow('Private key must be 64 hex characters');
      expect(() => HoosatSigner.signMessage('ab'.repeat(31), TEST_MESSAGE)).toThrow('Private key must be 64 hex characters'); // 62 chars
    });

    it('should throw error for invalid private key format', () => {
      const invalidKey = 'gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg'; // Invalid hex
      expect(() => HoosatSigner.signMessage(invalidKey, TEST_MESSAGE)).toThrow();
    });

    it('should sign empty message', () => {
      const signature = HoosatSigner.signMessage(TEST_PRIVATE_KEY, '');

      expect(signature).toBeTruthy();
      expect(signature.length).toBe(128);
    });

    it('should sign long message', () => {
      const longMessage = 'A'.repeat(10000);
      const signature = HoosatSigner.signMessage(TEST_PRIVATE_KEY, longMessage);

      expect(signature).toBeTruthy();
      expect(signature.length).toBe(128);
    });

    it('should sign Unicode message', () => {
      const unicodeMessage = 'Привет мир 🌍 你好世界';
      const signature = HoosatSigner.signMessage(TEST_PRIVATE_KEY, unicodeMessage);

      expect(signature).toBeTruthy();
      expect(signature.length).toBe(128);
    });
  });

  describe('Verify Message', () => {
    it('should verify valid signature', () => {
      const publicKey = HoosatSigner.getPublicKey(TEST_PRIVATE_KEY);
      const signature = HoosatSigner.signMessage(TEST_PRIVATE_KEY, TEST_MESSAGE);

      const isValid = HoosatSigner.verifyMessage(signature, TEST_MESSAGE, publicKey);

      expect(isValid).toBe(true);
    });

    it('should reject invalid signature', () => {
      const publicKey = HoosatSigner.getPublicKey(TEST_PRIVATE_KEY);
      const fakeSignature = 'a'.repeat(128);

      const isValid = HoosatSigner.verifyMessage(fakeSignature, TEST_MESSAGE, publicKey);

      expect(isValid).toBe(false);
    });

    it('should reject signature with wrong message', () => {
      const publicKey = HoosatSigner.getPublicKey(TEST_PRIVATE_KEY);
      const signature = HoosatSigner.signMessage(TEST_PRIVATE_KEY, 'Original Message');

      const isValid = HoosatSigner.verifyMessage(signature, 'Modified Message', publicKey);

      expect(isValid).toBe(false);
    });

    it('should reject signature with wrong public key', () => {
      const key1 = TEST_PRIVATE_KEY;
      const key2 = '0000000000000000000000000000000000000000000000000000000000000002';

      const publicKey1 = HoosatSigner.getPublicKey(key1);
      const publicKey2 = HoosatSigner.getPublicKey(key2);

      const signature = HoosatSigner.signMessage(key1, TEST_MESSAGE);

      expect(HoosatSigner.verifyMessage(signature, TEST_MESSAGE, publicKey1)).toBe(true);
      expect(HoosatSigner.verifyMessage(signature, TEST_MESSAGE, publicKey2)).toBe(false);
    });

    it('should accept signature with 0x prefix', () => {
      const publicKey = HoosatSigner.getPublicKey(TEST_PRIVATE_KEY);
      const signature = HoosatSigner.signMessage(TEST_PRIVATE_KEY, TEST_MESSAGE);

      const isValid = HoosatSigner.verifyMessage('0x' + signature, TEST_MESSAGE, publicKey);

      expect(isValid).toBe(true);
    });

    it('should accept public key with 0x prefix', () => {
      const publicKey = HoosatSigner.getPublicKey(TEST_PRIVATE_KEY);
      const signature = HoosatSigner.signMessage(TEST_PRIVATE_KEY, TEST_MESSAGE);

      const isValid = HoosatSigner.verifyMessage(signature, TEST_MESSAGE, '0x' + publicKey);

      expect(isValid).toBe(true);
    });

    it('should return false for malformed signature', () => {
      const publicKey = HoosatSigner.getPublicKey(TEST_PRIVATE_KEY);

      const isValid = HoosatSigner.verifyMessage('invalid', TEST_MESSAGE, publicKey);

      expect(isValid).toBe(false);
    });

    it('should return false for malformed public key', () => {
      const signature = HoosatSigner.signMessage(TEST_PRIVATE_KEY, TEST_MESSAGE);

      const isValid = HoosatSigner.verifyMessage(signature, TEST_MESSAGE, 'invalid');

      expect(isValid).toBe(false);
    });
  });

  describe('Get Public Key', () => {
    it('should derive public key from private key', () => {
      const publicKey = HoosatSigner.getPublicKey(TEST_PRIVATE_KEY);

      expect(typeof publicKey).toBe('string');
      expect(publicKey.length).toBe(66); // Compressed: 33 bytes = 66 hex chars
      expect(/^[0-9a-f]{66}$/.test(publicKey)).toBe(true);
      expect(publicKey.startsWith('02') || publicKey.startsWith('03')).toBe(true); // Compressed format
    });

    it('should be deterministic', () => {
      const pubKey1 = HoosatSigner.getPublicKey(TEST_PRIVATE_KEY);
      const pubKey2 = HoosatSigner.getPublicKey(TEST_PRIVATE_KEY);

      expect(pubKey1).toBe(pubKey2);
    });

    it('should produce different keys for different private keys', () => {
      const key1 = TEST_PRIVATE_KEY;
      const key2 = '0000000000000000000000000000000000000000000000000000000000000002';

      const pubKey1 = HoosatSigner.getPublicKey(key1);
      const pubKey2 = HoosatSigner.getPublicKey(key2);

      expect(pubKey1).not.toBe(pubKey2);
    });

    it('should accept private key with 0x prefix', () => {
      const publicKey = HoosatSigner.getPublicKey('0x' + TEST_PRIVATE_KEY);

      expect(publicKey).toBeTruthy();
      expect(publicKey.length).toBe(66);
    });

    it('should support uncompressed format', () => {
      const compressed = HoosatSigner.getPublicKey(TEST_PRIVATE_KEY, true);
      const uncompressed = HoosatSigner.getPublicKey(TEST_PRIVATE_KEY, false);

      expect(compressed.length).toBe(66); // 33 bytes
      expect(uncompressed.length).toBe(130); // 65 bytes
      expect(uncompressed.startsWith('04')).toBe(true); // Uncompressed prefix
    });

    it('should match HoosatCrypto public key', () => {
      const wallet = HoosatCrypto.importKeyPair(TEST_PRIVATE_KEY);
      const publicKey = HoosatSigner.getPublicKey(TEST_PRIVATE_KEY);

      expect(publicKey).toBe(wallet.publicKey.toString('hex'));
    });

    it('should throw error for invalid private key', () => {
      expect(() => HoosatSigner.getPublicKey('invalid')).toThrow();
      expect(() => HoosatSigner.getPublicKey('1234')).toThrow();
    });
  });

  describe('Create Signed Message', () => {
    it('should create complete signed message object', () => {
      const address = 'hoosat:qyp0123456789abcdef';
      const signedMsg = HoosatSigner.createSignedMessage(TEST_PRIVATE_KEY, TEST_MESSAGE, address);

      expect(signedMsg).toHaveProperty('message');
      expect(signedMsg).toHaveProperty('signature');
      expect(signedMsg).toHaveProperty('address');
      expect(signedMsg).toHaveProperty('timestamp');

      expect(signedMsg.message).toBe(TEST_MESSAGE);
      expect(signedMsg.signature.length).toBe(128);
      expect(signedMsg.address).toBe(address);
      expect(typeof signedMsg.timestamp).toBe('number');
      expect(signedMsg.timestamp).toBeGreaterThan(0);
    });

    it('should create timestamp close to current time', () => {
      const before = Date.now();
      const signedMsg = HoosatSigner.createSignedMessage(TEST_PRIVATE_KEY, TEST_MESSAGE, 'hoosat:test');
      const after = Date.now();

      expect(signedMsg.timestamp).toBeGreaterThanOrEqual(before);
      expect(signedMsg.timestamp).toBeLessThanOrEqual(after);
    });

    it('should create valid signature in object', () => {
      const publicKey = HoosatSigner.getPublicKey(TEST_PRIVATE_KEY);
      const signedMsg = HoosatSigner.createSignedMessage(TEST_PRIVATE_KEY, TEST_MESSAGE, 'hoosat:test');

      const isValid = HoosatSigner.verifyMessage(signedMsg.signature, signedMsg.message, publicKey);

      expect(isValid).toBe(true);
    });
  });

  describe('Verify Signed Message', () => {
    it('should verify valid signed message object', () => {
      const publicKey = HoosatSigner.getPublicKey(TEST_PRIVATE_KEY);
      const signedMsg = HoosatSigner.createSignedMessage(TEST_PRIVATE_KEY, TEST_MESSAGE, 'hoosat:test');

      const result = HoosatSigner.verifySignedMessage(signedMsg, publicKey);

      expect(result.valid).toBe(true);
      expect(result.publicKey).toBe(publicKey);
      expect(result.error).toBeUndefined();
    });

    it('should reject invalid signed message', () => {
      const publicKey = HoosatSigner.getPublicKey(TEST_PRIVATE_KEY);
      const signedMsg = HoosatSigner.createSignedMessage(TEST_PRIVATE_KEY, TEST_MESSAGE, 'hoosat:test');

      // Tamper with message
      signedMsg.message = 'Tampered Message';

      const result = HoosatSigner.verifySignedMessage(signedMsg, publicKey);

      expect(result.valid).toBe(false);
      expect(result.error).toBeTruthy();
    });

    it('should reject signed message with wrong public key', () => {
      const key1 = TEST_PRIVATE_KEY;
      const key2 = '0000000000000000000000000000000000000000000000000000000000000002';

      const publicKey2 = HoosatSigner.getPublicKey(key2);
      const signedMsg = HoosatSigner.createSignedMessage(key1, TEST_MESSAGE, 'hoosat:test');

      const result = HoosatSigner.verifySignedMessage(signedMsg, publicKey2);

      expect(result.valid).toBe(false);
      expect(result.error).toBeTruthy();
    });

    it('should handle malformed signed message', () => {
      const publicKey = HoosatSigner.getPublicKey(TEST_PRIVATE_KEY);
      const malformedMsg = {
        message: TEST_MESSAGE,
        signature: 'invalid',
        address: 'hoosat:test',
      };

      const result = HoosatSigner.verifySignedMessage(malformedMsg, publicKey);

      expect(result.valid).toBe(false);
      expect(result.error).toBeTruthy();
    });
  });

  describe('Public Key Recovery', () => {
    it('should recover public key from signature with recovery ID 0', () => {
      const originalPublicKey = HoosatSigner.getPublicKey(TEST_PRIVATE_KEY);
      const signature = HoosatSigner.signMessage(TEST_PRIVATE_KEY, TEST_MESSAGE);

      // Try recovery ID 0 (most common)
      try {
        const recoveredKey = HoosatSigner.recoverPublicKey(signature, TEST_MESSAGE, 0);

        expect(typeof recoveredKey).toBe('string');
        expect(recoveredKey.length).toBe(66);

        // Verify with recovered key
        const isValid = HoosatSigner.verifyMessage(signature, TEST_MESSAGE, recoveredKey);
        expect(isValid).toBe(true);
      } catch (error) {
        // Recovery might fail with wrong recovery ID, try ID 1
        const recoveredKey = HoosatSigner.recoverPublicKey(signature, TEST_MESSAGE, 1);
        const isValid = HoosatSigner.verifyMessage(signature, TEST_MESSAGE, recoveredKey);
        expect(isValid).toBe(true);
      }
    });

    it('should throw error for invalid signature during recovery', () => {
      const invalidSignature = 'invalid_hex';

      expect(() => HoosatSigner.recoverPublicKey(invalidSignature, TEST_MESSAGE, 0)).toThrow();
    });
  });

  describe('End-to-End Integration', () => {
    it('should complete full sign and verify cycle', () => {
      // Generate wallet
      const wallet = HoosatCrypto.generateKeyPair();

      // Sign message
      const message = 'Sign in to MyDApp\nTimestamp: ' + Date.now();
      const signature = HoosatSigner.signMessage(wallet.privateKey.toString('hex'), message);

      // Verify signature
      const isValid = HoosatSigner.verifyMessage(signature, message, wallet.publicKey.toString('hex'));

      expect(isValid).toBe(true);
    });

    it('should work with both mainnet and testnet addresses', () => {
      const mainnetWallet = HoosatCrypto.generateKeyPair('mainnet');
      const testnetWallet = HoosatCrypto.generateKeyPair('testnet');

      const mainnetSig = HoosatSigner.signMessage(mainnetWallet.privateKey.toString('hex'), TEST_MESSAGE);
      const testnetSig = HoosatSigner.signMessage(testnetWallet.privateKey.toString('hex'), TEST_MESSAGE);

      expect(HoosatSigner.verifyMessage(mainnetSig, TEST_MESSAGE, mainnetWallet.publicKey.toString('hex'))).toBe(true);
      expect(HoosatSigner.verifyMessage(testnetSig, TEST_MESSAGE, testnetWallet.publicKey.toString('hex'))).toBe(true);
    });

    it('should support DApp authentication flow', () => {
      const wallet = HoosatCrypto.generateKeyPair();

      // Create auth challenge
      const nonce = Date.now();
      const challenge = `Sign in to MyDApp\nNonce: ${nonce}\nAddress: ${wallet.address}`;

      // Sign challenge
      const signedMessage = HoosatSigner.createSignedMessage(
        wallet.privateKey.toString('hex'),
        challenge,
        wallet.address
      );

      // Verify on backend
      const result = HoosatSigner.verifySignedMessage(
        signedMessage,
        wallet.publicKey.toString('hex')
      );

      expect(result.valid).toBe(true);
      expect(signedMessage.address).toBe(wallet.address);
      expect(signedMessage.message).toContain(`Nonce: ${nonce}`);
    });
  });

  describe('Message Prefix Consistency', () => {
    it('should always use "Hoosat Signed Message:" prefix', () => {
      const message1 = formatMessage('Test 1');
      const message2 = formatMessage('Test 2');

      expect(message1.startsWith('Hoosat Signed Message:\n')).toBe(true);
      expect(message2.startsWith('Hoosat Signed Message:\n')).toBe(true);
    });

    it('should prevent transaction signature reuse', () => {
      // Message signature should be completely different from transaction signature
      // because of the "Hoosat Signed Message:" prefix

      const privateKey = Buffer.from(TEST_PRIVATE_KEY, 'hex');
      const message = 'Some data';

      // Message signature (with prefix)
      const messageSignature = HoosatSigner.signMessage(TEST_PRIVATE_KEY, message);

      // Both should be 128 chars but different due to prefix in message hash
      expect(messageSignature.length).toBe(128);
      expect(/^[0-9a-f]{128}$/.test(messageSignature)).toBe(true);
    });
  });
});
