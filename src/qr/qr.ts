import QRCode from 'qrcode';
import { HoosatUtils } from '@utils/utils';
import { ParsedPaymentURI, PaymentURIParams, QRCodeOptions } from '@qr/qr.types';

/**
 * QR Code generator and parser for Hoosat addresses and payment URIs
 *
 * @example
 * ```typescript
 * // Generate simple address QR
 * const qr = await HoosatQR.generateAddressQR('hoosat:qz7ulu...');
 * console.log(qr); // Data URL for <img src="...">
 *
 * // Generate payment request QR
 * const paymentQR = await HoosatQR.generatePaymentQR({
 *   address: 'hoosat:qz7ulu...',
 *   amount: 100, // 100 HTN
 *   label: 'Coffee Shop',
 *   message: 'Thank you!'
 * });
 *
 * // Parse QR from mobile wallet
 * const parsed = HoosatQR.parsePaymentURI('hoosat:qz7ulu...?amount=100');
 * console.log(parsed.amount); // Amount in sompi
 * ```
 */
export class HoosatQR {
  /**
   * Generate QR code for a simple Hoosat address
   *
   * @param address - Hoosat address (with or without 'hoosat:' prefix)
   * @param options - QR code generation options
   * @returns Data URL (base64 PNG image) for use in <img> tag
   *
   * @example
   * ```typescript
   * const qr = await HoosatQR.generateAddressQR('hoosat:qz7ulu...');
   * // Use in HTML: <img src="${qr}" />
   * ```
   */
  static async generateAddressQR(address: string, options: QRCodeOptions = {}): Promise<string> {
    if (!HoosatUtils.isValidAddress(address)) {
      throw new Error(`Invalid Hoosat address: ${address}`);
    }

    // Ensure address has 'hoosat:' prefix
    const formattedAddress = address.startsWith('hoosat:') ? address : `hoosat:${address}`;

    return this.generateQRDataURL(formattedAddress, options);
  }

  /**
   * Generate QR code for a payment request with amount and metadata
   *
   * @param params - Payment URI parameters
   * @param options - QR code generation options
   * @returns Data URL (base64 PNG image)
   *
   * @example
   * ```typescript
   * const qr = await HoosatQR.generatePaymentQR({
   *   address: 'hoosat:qz7ulu...',
   *   amount: 100,
   *   label: 'Coffee Shop',
   *   message: 'Order #12345'
   * });
   * ```
   */
  static async generatePaymentQR(params: PaymentURIParams, options: QRCodeOptions = {}): Promise<string> {
    const uri = this.buildPaymentURI(params);
    return this.generateQRDataURL(uri, options);
  }

  /**
   * Generate QR code as SVG string
   *
   * @param address - Hoosat address or payment URI
   * @param options - QR code generation options
   * @returns SVG string
   *
   * @example
   * ```typescript
   * const svg = await HoosatQR.generateQRSVG('hoosat:qz7ulu...');
   * document.getElementById('qr').innerHTML = svg;
   * ```
   */
  static async generateQRSVG(address: string, options: QRCodeOptions = {}): Promise<string> {
    const qrOptions = this.buildQROptions(options);
    return new Promise((resolve, reject) => {
      QRCode.toString(address, { ...qrOptions, type: 'svg' }, (err, svg) => {
        if (err) reject(err);
        else resolve(svg);
      });
    });
  }

  /**
   * Generate QR code as terminal string (ASCII art)
   * Useful for CLI applications
   *
   * @param address - Hoosat address or payment URI
   * @returns Terminal-friendly QR code string
   *
   * @example
   * ```typescript
   * const qr = await HoosatQR.generateQRTerminal('hoosat:qz7ulu...');
   * console.log(qr);
   * ```
   */
  static async generateQRTerminal(address: string): Promise<string> {
    return new Promise((resolve, reject) => {
      QRCode.toString(address, { type: 'terminal', small: true }, (err, qr) => {
        if (err) reject(err);
        else resolve(qr);
      });
    });
  }

  /**
   * Generate QR code as Buffer (for Node.js file saving)
   *
   * @param address - Hoosat address or payment URI
   * @param options - QR code generation options
   * @returns PNG image as Buffer
   *
   * @example
   * ```typescript
   * const buffer = await HoosatQR.generateQRBuffer('hoosat:qz7ulu...');
   * fs.writeFileSync('qr.png', buffer);
   * ```
   */
  static async generateQRBuffer(address: string, options: QRCodeOptions = {}): Promise<Buffer> {
    const qrOptions = this.buildQROptions(options);
    return new Promise((resolve, reject) => {
      QRCode.toBuffer(address, qrOptions, (err, buffer) => {
        if (err) reject(err);
        else resolve(buffer);
      });
    });
  }

  /**
   * Build payment URI from parameters
   * Format: hoosat:address?amount=X&label=Y&message=Z
   *
   * @param params - Payment parameters
   * @returns Formatted payment URI
   *
   * @example
   * ```typescript
   * const uri = HoosatQR.buildPaymentURI({
   *   address: 'hoosat:qz7ulu...',
   *   amount: 100,
   *   label: 'Coffee'
   * });
   * // Result: "hoosat:qz7ulu...?amount=100&label=Coffee"
   * ```
   */
  static buildPaymentURI(params: PaymentURIParams): string {
    // Validate address
    if (!HoosatUtils.isValidAddress(params.address)) {
      throw new Error(`Invalid Hoosat address: ${params.address}`);
    }

    // Remove 'hoosat:' prefix if present
    const address = params.address.replace('hoosat:', '');

    // Build query parameters
    const queryParams: string[] = [];

    if (params.amount !== undefined) {
      // Validate amount
      const amount = typeof params.amount === 'string' ? parseFloat(params.amount) : params.amount;

      if (isNaN(amount) || amount <= 0) {
        throw new Error(`Invalid amount: ${params.amount}`);
      }

      queryParams.push(`amount=${amount}`);
    }

    if (params.label) {
      queryParams.push(`label=${encodeURIComponent(params.label)}`);
    }

    if (params.message) {
      queryParams.push(`message=${encodeURIComponent(params.message)}`);
    }

    // Build final URI
    const baseUri = `hoosat:${address}`;
    return queryParams.length > 0 ? `${baseUri}?${queryParams.join('&')}` : baseUri;
  }

  /**
   * Parse payment URI from QR code
   *
   * @param uri - Payment URI string
   * @returns Parsed payment information
   * @throws Error if URI is invalid
   *
   * @example
   * ```typescript
   * const parsed = HoosatQR.parsePaymentURI(
   *   'hoosat:qz7ulu...?amount=100&label=Coffee'
   * );
   * console.log(parsed.address); // "hoosat:qz7ulu..."
   * console.log(parsed.amount);  // "10000000000" (sompi)
   * console.log(parsed.label);   // "Coffee"
   * ```
   */
  static parsePaymentURI(uri: string): ParsedPaymentURI {
    // Validate URI format
    if (!uri.startsWith('hoosat:')) {
      throw new Error('Invalid Hoosat URI: must start with "hoosat:"');
    }

    // Split URI into address and query
    const [addressPart, queryPart] = uri.substring(7).split('?');

    const address = `hoosat:${addressPart}`;

    // Validate address
    if (!HoosatUtils.isValidAddress(address)) {
      throw new Error(`Invalid Hoosat address in URI: ${address}`);
    }

    const result: ParsedPaymentURI = {
      address,
      rawUri: uri,
    };

    // Parse query parameters if present
    if (queryPart) {
      const params = new URLSearchParams(queryPart);

      // Parse amount (convert HTN to sompi)
      const amountStr = params.get('amount');
      if (amountStr) {
        const amountHTN = parseFloat(amountStr);
        if (!isNaN(amountHTN) && amountHTN > 0) {
          result.amount = HoosatUtils.amountToSompi(String(amountHTN));
        }
      }

      // Parse label
      const label = params.get('label');
      if (label) {
        result.label = decodeURIComponent(label);
      }

      // Parse message
      const message = params.get('message');
      if (message) {
        result.message = decodeURIComponent(message);
      }
    }

    return result;
  }

  /**
   * Validate if string is a valid Hoosat payment URI
   *
   * @param uri - URI string to validate
   * @returns true if valid payment URI
   *
   * @example
   * ```typescript
   * HoosatQR.isValidPaymentURI('hoosat:qz7ulu...'); // true
   * HoosatQR.isValidPaymentURI('bitcoin:...'); // false
   * ```
   */
  static isValidPaymentURI(uri: string): boolean {
    try {
      this.parsePaymentURI(uri);
      return true;
    } catch {
      return false;
    }
  }

  // ==================== PRIVATE HELPERS ====================

  /**
   * Generate QR code as Data URL (base64 PNG)
   */
  private static async generateQRDataURL(text: string, options: QRCodeOptions): Promise<string> {
    const qrOptions = this.buildQROptions(options);
    return new Promise((resolve, reject) => {
      QRCode.toDataURL(text, qrOptions, (err, url) => {
        if (err) reject(err);
        else resolve(url);
      });
    });
  }

  /**
   * Build QR code options from custom options
   */
  private static buildQROptions(options: QRCodeOptions): any {
    return {
      errorCorrectionLevel: options.errorCorrectionLevel || 'M',
      width: options.width || 300,
      margin: options.margin || 2,
      color: {
        dark: options.color?.dark || '#000000',
        light: options.color?.light || '#ffffff',
      },
    };
  }
}
