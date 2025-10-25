import { Buffer } from 'buffer';

export const HOOSAT_PARAMS = {
  // Network prefixes
  MAINNET_PREFIX: 'hoosat',
  TESTNET_PREFIX: 'hoosattest',

  // Address prefixes (with colon for validation)
  MAINNET_ADDRESS_PREFIX: 'hoosat:',
  TESTNET_ADDRESS_PREFIX: 'hoosattest:',

  SIGHASH_ALL: 0x01,
  SIGHASH_NONE: 0x02,
  SIGHASH_SINGLE: 0x04,
  SIGHASH_ANYONECANPAY: 0x80,
  COINBASE_MATURITY: 100,
  MIN_FEE: 3250,
  SUBNETWORK_ID_NATIVE: Buffer.alloc(20, 0),
} as const;
