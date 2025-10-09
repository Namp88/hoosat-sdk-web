/**
 * Payment URI parameters for Hoosat transactions
 */
export interface PaymentURIParams {
  address: string;
  amount?: string | number; // Amount in HTN (not sompi)
  label?: string;
  message?: string;
}

/**
 * QR code generation options
 */
export interface QRCodeOptions {
  errorCorrectionLevel?: 'L' | 'M' | 'Q' | 'H'; // Error correction level
  width?: number; // Width in pixels
  margin?: number; // Margin in modules
  color?: {
    dark?: string; // Dark color (hex)
    light?: string; // Light color (hex)
  };
}

/**
 * Parsed payment URI result
 */
export interface ParsedPaymentURI {
  address: string;
  amount?: string; // Amount in sompi
  label?: string;
  message?: string;
  rawUri: string;
}
