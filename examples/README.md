# Hoosat SDK Browser Examples

## 🚀 Quick Start

### 1. Build the SDK

First, build the SDK (if not already built):

```bash
npm run build
```

### 2. Start a Local Server

You need to serve the files over HTTP (not file://). Choose one option:

**Option A: Using npx (recommended)**
```bash
npx serve .
```

Then open: http://localhost:3000/examples/test-browser.html

**Option B: Using Python**
```bash
python -m http.server 8000
```

Then open: http://localhost:8000/examples/test-browser.html

**Option C: Using Node.js http-server**
```bash
npx http-server -p 8000
```

Then open: http://localhost:8000/examples/test-browser.html

### 3. Test the Features

The test page includes:

#### **Cryptography Tests**
- 🔑 **Generate Key Pair** - Create new ECDSA wallet
- 📥 **Import Key** - Import wallet from private key
- ✅ **Validate Address** - Test address validation
- 🔐 **Test Hashing** - BLAKE3 and SHA256 hashing

#### **Message Signing Tests** (NEW!)
- ✍️ **Sign Message** - Sign a message with ECDSA
- ✅ **Verify Signature** - Test signature verification (valid/invalid)
- 🌐 **Test DApp Auth** - Complete DApp authentication flow
- 🔄 **Test Key Recovery** - Recover public key from signature

## 📁 Files

- **test-browser.html** - Interactive testing page with all SDK features
- **example-wallet.html** - Complete wallet implementation example

## 🔍 What to Test

### Message Signing Features

1. **Sign Message**
   - Generates random wallet
   - Signs a test message
   - Verifies signature
   - Tests deterministic signing (same message → same signature)

2. **Verify Signature**
   - Tests valid signature ✅
   - Tests wrong message rejection ❌
   - Tests wrong public key rejection ❌
   - Tests invalid signature format rejection ❌

3. **DApp Authentication**
   - Simulates full authentication flow:
     1. User generates wallet
     2. DApp creates challenge with nonce
     3. User signs challenge
     4. DApp verifies signature
     5. Security test: tampered message rejection

4. **Key Recovery**
   - Tests public key recovery from signature
   - Tries all recovery IDs (0-3)
   - Verifies recovered key works

## 🎯 Expected Results

All tests should show ✅ green success messages. If you see ❌ red errors, check:

1. SDK is built: `npm run build`
2. Using HTTP server (not file://)
3. Browser console for detailed errors

## 🐛 Troubleshooting

**SDK not loading:**
- Make sure you ran `npm run build`
- Check that `dist/hoosat-sdk.es.js` exists
- Use HTTP server, not file:// protocol

**"Buffer is not available" error:**
- The SDK should set Buffer automatically
- Check browser console for errors
- Try hard refresh (Ctrl+Shift+R)

**Tests failing:**
- Open browser DevTools (F12)
- Check Console tab for detailed errors
- Report issues on GitHub

## 💡 Usage in Your Code

After testing, you can use the same patterns in your app:

```javascript
import { HoosatSigner, HoosatCrypto } from 'hoosat-sdk-web';

// Generate wallet
const wallet = HoosatCrypto.generateKeyPair();

// Sign message
const signature = HoosatSigner.signMessage(
  wallet.privateKey.toString('hex'),
  'Hello, Hoosat!'
);

// Verify signature
const isValid = HoosatSigner.verifyMessage(
  signature,
  'Hello, Hoosat!',
  wallet.publicKey.toString('hex')
);
```

## 🔗 Resources

- [SDK Documentation](../README.md)
- [GitHub Repository](https://github.com/Namp88/hoosat-sdk-web)
- [NPM Package](https://www.npmjs.com/package/hoosat-sdk-web)
