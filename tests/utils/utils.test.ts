import { describe, it, expect } from 'vitest';
import { HoosatUtils } from '@utils/utils';

describe('HoosatUtils', () => {
  describe('Address validation', () => {
    it('should validate mainnet address', () => {
      const validAddress = 'hoosat:qz95mwas8ja7ucsernv9z335rdxxqswff7wvzenl29qukn5qs3lsqfsa4pd74';
      expect(HoosatUtils.isValidAddress(validAddress)).toBe(true);
    });

    it('should validate testnet address', () => {
      const validTestnetAddress = 'hoosattest:qypaq8aera9ewdgqfd4xmz3z6hzyfkdg3cshwdeckn0gwn3vsd3zc8cmr0hd3s5';
      expect(HoosatUtils.isValidAddress(validTestnetAddress)).toBe(true);
    });

    it('should reject invalid prefix', () => {
      expect(HoosatUtils.isValidAddress('invalid:qz95mwas8ja7')).toBe(false);
    });

    it('should reject empty address', () => {
      expect(HoosatUtils.isValidAddress('')).toBe(false);
    });

    it('should reject non-string input', () => {
      expect(HoosatUtils.isValidAddress(null as any)).toBe(false);
      expect(HoosatUtils.isValidAddress(undefined as any)).toBe(false);
    });
  });

  describe('Amount conversion', () => {
    it('should convert sompi to HTN', () => {
      expect(HoosatUtils.sompiToAmount('100000000')).toBe('1.00000000');
      expect(HoosatUtils.sompiToAmount('50000000')).toBe('0.50000000');
      expect(HoosatUtils.sompiToAmount('1')).toBe('0.00000001');
    });

    it('should convert HTN to sompi', () => {
      expect(HoosatUtils.amountToSompi('1.5')).toBe('150000000');
      expect(HoosatUtils.amountToSompi('0.00000001')).toBe('1');
      expect(HoosatUtils.amountToSompi('10')).toBe('1000000000');
    });

    it('should handle bigint input in sompiToAmount', () => {
      expect(HoosatUtils.sompiToAmount(100000000n)).toBe('1.00000000');
    });
  });

  describe('Amount formatting', () => {
    it('should format amount with thousands separators', () => {
      expect(HoosatUtils.formatAmount('1234567.89')).toBe('1,234,567.89000000');
      expect(HoosatUtils.formatAmount('1000')).toBe('1,000.00000000');
    });

    it('should respect custom decimal places', () => {
      expect(HoosatUtils.formatAmount('123.456', 2)).toBe('123.46');
      expect(HoosatUtils.formatAmount('123.456', 4)).toBe('123.4560');
    });
  });

  describe('Amount validation', () => {
    it('should validate correct amounts', () => {
      expect(HoosatUtils.isValidAmount('1.5')).toBe(true);
      expect(HoosatUtils.isValidAmount('1.12345678')).toBe(true);
      expect(HoosatUtils.isValidAmount('0')).toBe(true);
      expect(HoosatUtils.isValidAmount('1000000')).toBe(true);
    });

    it('should reject invalid amounts', () => {
      expect(HoosatUtils.isValidAmount('1.123456789')).toBe(false); // Too many decimals
      expect(HoosatUtils.isValidAmount('-5')).toBe(false); // Negative
      expect(HoosatUtils.isValidAmount('abc')).toBe(false); // Not a number
      expect(HoosatUtils.isValidAmount('')).toBe(false); // Empty string
    });
  });

  describe('Address truncation', () => {
    it('should truncate long addresses', () => {
      const address = 'hoosat:qz95mwas8ja7ucsernv9z335rdxxqswff7wvzenl29qukn5qs3lsqfsa4pd74';
      const truncated = HoosatUtils.truncateAddress(address);

      expect(truncated).toContain('hoosat:qz95');
      expect(truncated).toContain('...');
      expect(truncated).toContain('a4pd74');
      expect(truncated.length).toBeLessThan(address.length);
    });

    it('should handle short addresses', () => {
      const shortAddress = 'hoosat:qz95';
      const truncated = HoosatUtils.truncateAddress(shortAddress);

      expect(truncated).toBe(shortAddress);
    });
  });

  describe('Address comparison', () => {
    it('should compare addresses case-insensitively', () => {
      const addr1 = 'hoosat:qz95mwas8ja7ucsernv9z335rdxxqswff7wvzenl29qukn5qs3lsqfsa4pd74';
      const addr2 = 'HOOSAT:QZ95MWAS8JA7UCSERNV9Z335RDXXQSWFF7WVZENL29QUKN5QS3LSQFSA4PD74';

      expect(HoosatUtils.compareAddresses(addr1, addr2)).toBe(true);
    });

    it('should detect different addresses', () => {
      const addr1 = 'hoosat:qz95mwas8ja7ucsernv9z335rdxxqswff7wvzenl29qukn5qs3lsqfsa4pd74';
      const addr2 = 'hoosat:qr97kz9ujwylwxd8jkh9zs0nexlkmscxl3cvjx3gg5r7qf3tq3u6qxjfdajku';

      expect(HoosatUtils.compareAddresses(addr1, addr2)).toBe(false);
    });
  });

  describe('Hash validation', () => {
    it('should validate transaction IDs', () => {
      const validTxId = '091ea22a707ac840c8291706fca5421a61ee03147f3f9655133d5b62ec38f29f';
      expect(HoosatUtils.isValidTransactionId(validTxId)).toBe(true);
    });

    it('should reject invalid transaction IDs', () => {
      expect(HoosatUtils.isValidTransactionId('invalid')).toBe(false);
      expect(HoosatUtils.isValidTransactionId('091ea22a')).toBe(false); // Too short
    });

    it('should validate block hashes', () => {
      const validBlockHash = 'f1e2d3c4b5a6978012345678901234567890123456789012345678901234cdef';
      expect(HoosatUtils.isValidBlockHash(validBlockHash)).toBe(true);
    });
  });

  describe('Key validation', () => {
    it('should validate private keys', () => {
      const validPrivateKey = '33a4a81ecd31615c51385299969121707897fb1e167634196f31bd311de5fe43';
      expect(HoosatUtils.isValidPrivateKey(validPrivateKey)).toBe(true);
    });

    it('should reject invalid private keys', () => {
      expect(HoosatUtils.isValidPrivateKey('short')).toBe(false);
      expect(HoosatUtils.isValidPrivateKey('33a4a81e')).toBe(false); // Too short
    });

    it('should validate compressed public keys', () => {
      const validPubKey = '02eddf8d68ad880ec15b9d0de338d62f53630af2efc2e2d3a03e2f7a65c379fbaa';
      expect(HoosatUtils.isValidPublicKey(validPubKey, true)).toBe(true);
    });

    it('should validate uncompressed public keys', () => {
      const validPubKey = '04' + 'e'.repeat(128);
      expect(HoosatUtils.isValidPublicKey(validPubKey, false)).toBe(true);
    });
  });

  describe('Hashrate formatting', () => {
    it('should format hashrate with correct units', () => {
      expect(HoosatUtils.formatHashrate(1500000000000)).toContain('TH/s');
      expect(HoosatUtils.formatHashrate(1500000000)).toContain('GH/s');
      expect(HoosatUtils.formatHashrate(1500000)).toContain('MH/s');
    });

    it('should handle string input', () => {
      expect(HoosatUtils.formatHashrate('1500000000')).toContain('GH/s');
    });

    it('should handle zero and negative values', () => {
      expect(HoosatUtils.formatHashrate(0)).toBe('0.00 H/s');
      expect(HoosatUtils.formatHashrate(-100)).toBe('0 H/s');
    });
  });

  describe('Buffer conversion', () => {
    it('should convert hex to buffer', () => {
      const hex = 'a1b2c3';
      const buffer = HoosatUtils.hexToBuffer(hex);

      expect(buffer).toBeInstanceOf(Buffer);
      expect(buffer?.toString('hex')).toBe(hex);
    });

    it('should convert buffer to hex', () => {
      const buffer = Buffer.from([161, 178, 195]);
      const hex = HoosatUtils.bufferToHex(buffer);

      expect(hex).toBe('a1b2c3');
    });

    it('should handle empty string', () => {
      expect(HoosatUtils.hexToBuffer('')).toBe(null);
    });

    it('should handle null/undefined input', () => {
      expect(HoosatUtils.hexToBuffer(null as any)).toBe(null);
      expect(HoosatUtils.hexToBuffer(undefined as any)).toBe(null);
    });

    it('should handle odd-length hex strings', () => {
      const buffer = HoosatUtils.hexToBuffer('abc');
      expect(buffer).toBeInstanceOf(Buffer);
    });
  });
});
