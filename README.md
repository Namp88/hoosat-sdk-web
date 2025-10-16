# hoosat-sdk-web

[![npm version](https://badge.fury.io/js/hoosat-sdk-web.svg)](https://www.npmjs.com/package/hoosat-sdk-web)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Browser-compatible TypeScript SDK for Hoosat blockchain.** Build wallets, web extensions, and dApps with full crypto support in the browser.

## 🚀 Features

- ✅ **Browser-native** - No Node.js dependencies, runs in any browser
- ✅ **Cryptography** - ECDSA key generation, signing, address creation
- ✅ **Message Signing** - Sign and verify messages for authentication and DApp integration
- ✅ **Transaction Builder** - Build and sign transactions with automatic fee calculation
- ✅ **REST API Client** - Connect to Hoosat proxy for balance, UTXOs, and submissions
- ✅ **QR Code Generator** - Payment URIs and address QR codes
- ✅ **TypeScript** - Full type safety with comprehensive types
- ✅ **Lightweight** - ~150KB gzipped

## 📦 Installation

```bash
npm install hoosat-sdk-web
```

## 🔧 Quick Start

### 1. Generate Wallet

```typescript
import { HoosatCrypto } from 'hoosat-sdk-web';

// Generate new wallet
const wallet = HoosatCrypto.generateKeyPair('mainnet');
console.log('Address:', wallet.address);
console.log('Private Key:', wallet.privateKey.toString('hex'));

// Or import existing wallet
const imported = HoosatCrypto.importKeyPair('your-private-key-hex', 'mainnet');
```

### 2. Check Balance

```typescript
import { HoosatBrowserClient, HoosatUtils } from 'hoosat-sdk-web';

const client = new HoosatBrowserClient({
  baseUrl: 'https://proxy.hoosat.net/api/v1'
});

const balance = await client.getBalance('hoosat:qz7ulu...');
console.log(`Balance: ${HoosatUtils.sompiToAmount(balance.balance)} HTN`);
```

### 3. Send Transaction

```typescript
import { HoosatTxBuilder, HoosatCrypto } from 'hoosat-sdk-web';

// Get UTXOs
const utxos = await client.getUtxos([wallet.address]);

// Build transaction
const builder = new HoosatTxBuilder();

utxos.utxos.forEach(utxo => {
  builder.addInput(utxo, wallet.privateKey);
});

builder
  .addOutput('hoosat:recipient...', '100000000') // 1 HTN in sompi
  .setFee('2500')
  .addChangeOutput(wallet.address);

// Sign and submit
const signedTx = builder.sign();
const result = await client.submitTransaction(signedTx);
console.log('TX ID:', result.transactionId);
```

### 4. Generate QR Code

```typescript
import { HoosatQR } from 'hoosat-sdk-web';

// Simple address QR
const qr = await HoosatQR.generateAddressQR('hoosat:qz7ulu...');
// Use in HTML: <img src="${qr}" />

// Payment request QR
const paymentQR = await HoosatQR.generatePaymentQR({
  address: 'hoosat:qz7ulu...',
  amount: 100, // HTN
  label: 'Coffee Shop',
  message: 'Order #12345'
});
```

### 5. Sign Messages (Authentication, DApp Integration)

```typescript
import { HoosatSigner } from 'hoosat-sdk-web';

// Sign a message with your wallet
const privateKey = wallet.privateKey.toString('hex');
const message = 'Sign in to MyDApp\nTimestamp: ' + Date.now();
const signature = HoosatSigner.signMessage(privateKey, message);

// Verify the signature
const publicKey = wallet.publicKey.toString('hex');
const isValid = HoosatSigner.verifyMessage(signature, message, publicKey);
console.log('Signature valid:', isValid);

// Create a complete signed message object
const signedMessage = HoosatSigner.createSignedMessage(
  privateKey,
  message,
  wallet.address
);
// Returns: { message, signature, address, timestamp }

// Verify signed message object
const result = HoosatSigner.verifySignedMessage(signedMessage, publicKey);
if (result.valid) {
  console.log('Authenticated!');
}
```

## 📚 API Reference

### HoosatCrypto

**Key Management:**
- `generateKeyPair(network?)` - Generate new ECDSA key pair
- `importKeyPair(privateKeyHex, network?)` - Import from private key
- `getPublicKey(privateKey)` - Derive public key

**Address Operations:**
- `publicKeyToAddressECDSA(publicKey, network?)` - Create ECDSA address
- `publicKeyToAddress(publicKey, network?)` - Create Schnorr address
- `addressToScriptPublicKey(address)` - Convert to script

**Transaction Signing:**
- `signTransactionInput(tx, inputIndex, privateKey, utxo)` - Sign input
- `verifyTransactionSignature(tx, inputIndex, sig, pubKey, utxo)` - Verify
- `getTransactionId(tx)` - Calculate TX ID

**Utilities:**
- `calculateFee(inputCount, outputCount, feePerByte?)` - Estimate fee
- `blake3Hash(data)` - BLAKE3 hash
- `sha256Hash(data)` - SHA256 hash

### HoosatSigner

**Message Signing:**
- `signMessage(privateKey, message)` - Sign message with ECDSA
- `verifyMessage(signature, message, publicKey)` - Verify signature
- `getPublicKey(privateKey, compressed?)` - Get public key from private key
- `recoverPublicKey(signature, message, recoveryId?)` - Recover public key from signature

**Signed Message Objects:**
- `createSignedMessage(privateKey, message, address)` - Create complete signed message with metadata
- `verifySignedMessage(signedMessage, publicKey)` - Verify signed message object

**Utilities:**
- `hashMessage(message)` - Hash message with BLAKE3 (includes prefix)
- `formatMessage(message)` - Format message with Hoosat prefix
- `MESSAGE_PREFIX` - Standard message prefix: "Hoosat Signed Message:\n"

### HoosatTxBuilder

**Building:**
- `addInput(utxo, privateKey?)` - Add input
- `addOutput(address, amount)` - Add output (max 2 recipients)
- `addChangeOutput(address)` - Add change automatically
- `setFee(fee)` - Set transaction fee
- `setLockTime(lockTime)` - Set lock time

**Info:**
- `getTotalInputAmount()` - Total input value
- `getTotalOutputAmount()` - Total output value
- `estimateFee(feePerByte?)` - Estimate fee

**Execution:**
- `build()` - Build unsigned transaction
- `sign(privateKey?)` - Sign transaction
- `buildAndSign(privateKey?)` - Build and sign
- `validate()` - Validate amounts
- `clear()` - Reset builder

### HoosatBrowserClient

**Constructor:**
```typescript
new HoosatBrowserClient({
  baseUrl: 'https://proxy.hoosat.net/api/v1',
  timeout: 30000,
  debug: false
})
```

**Methods:**
- `getBalance(address)` - Get address balance
- `getUtxos(addresses)` - Get UTXOs for addresses
- `submitTransaction(tx)` - Submit signed transaction
- `getFeeEstimate()` - Get recommended fees
- `getNetworkInfo()` - Get network information
- `checkHealth()` - Check API health
- `ping()` - Quick connectivity check

### HoosatUtils

**Amount Conversion:**
- `sompiToAmount(sompi)` - Convert sompi to HTN
- `amountToSompi(htn)` - Convert HTN to sompi
- `formatAmount(htn, decimals?)` - Format with separators

**Validation:**
- `isValidAddress(address)` - Validate Hoosat address
- `isValidTransactionId(txId)` - Validate TX ID
- `isValidHash(hash, length?)` - Validate hex hash
- `isValidPrivateKey(privateKey)` - Validate private key
- `isValidAmount(amount, maxDecimals?)` - Validate amount

**Address Info:**
- `getAddressVersion(address)` - Get address version (0x00, 0x01, 0x08)
- `getAddressType(address)` - Get type (schnorr, ecdsa, p2sh)
- `getAddressNetwork(address)` - Get network (mainnet, testnet)

**Formatting:**
- `truncateAddress(address, start?, end?)` - Truncate for UI
- `truncateHash(hash, start?, end?)` - Truncate hash
- `formatHashrate(hashrate, decimals?)` - Format hashrate (H/s, TH/s, etc)
- `formatDifficulty(difficulty, decimals?)` - Format difficulty

**Conversion:**
- `hexToBuffer(hex)` - Convert hex to Buffer
- `bufferToHex(buffer)` - Convert Buffer to hex

### HoosatQR

**Generation:**
- `generateAddressQR(address, options?)` - Generate address QR (Data URL)
- `generatePaymentQR(params, options?)` - Generate payment QR
- `generateQRSVG(address, options?)` - Generate as SVG
- `generateQRBuffer(address, options?)` - Generate as Buffer
- `generateQRTerminal(address)` - Generate ASCII QR

**Parsing:**
- `buildPaymentURI(params)` - Build payment URI string
- `parsePaymentURI(uri)` - Parse payment URI
- `isValidPaymentURI(uri)` - Validate URI

## 🌐 Network Support

- **Mainnet** - `hoosat:` addresses
- **Testnet** - `hoosattest:` addresses

## 🔒 Security Best Practices

```typescript
// ❌ Never hardcode private keys
const privateKey = '33a4a81e...'; 

// ✅ Use environment variables
const privateKey = process.env.WALLET_PRIVATE_KEY;

// ✅ Clear sensitive data
let keyBuffer = Buffer.from(privateKey, 'hex');
// ... use key ...
keyBuffer.fill(0);
keyBuffer = null;
```

## 🧪 Testing

```bash
# Run tests
npm test

# Run with coverage
npm run test:coverage

# Browser tests
npm run test:browser
```

## 📖 Examples

See [examples/](https://github.com/Namp88/hoosat-sdk-web/tree/main/examples) folder:
- `example-wallet.html` - Full wallet implementation
- `test-browser.html` - SDK functionality tests

## 🤝 Related Projects

- **[hoosat-sdk](https://www.npmjs.com/package/hoosat-sdk)** - Full Node.js SDK with gRPC
- **[hoosat-proxy](https://github.com/Namp88/hoosat-proxy)** - REST API proxy for Hoosat
- **[Hoosat](https://hoosat.fi)** - Official Hoosat blockchain

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details

## 🔗 Links

- **GitHub:** https://github.com/Namp88/hoosat-sdk-web
- **Issues:** https://github.com/Namp88/hoosat-sdk-web/issues
- **NPM:** https://www.npmjs.com/package/hoosat-sdk-web
- **Hoosat Website:** https://hoosat.fi

## 💬 Support

For questions and support:
- Open an [issue](https://github.com/Namp88/hoosat-sdk-web/issues)
- Email: namp2988@gmail.com

---

Made with ❤️ for the Hoosat community