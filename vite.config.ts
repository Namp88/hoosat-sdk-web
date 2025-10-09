import { defineConfig } from 'vite';
import { resolve } from 'path';

export default defineConfig({
  build: {
    lib: {
      entry: resolve(__dirname, 'src/index.ts'),
      name: 'HoosatSDK',
      formats: ['es', 'umd'],
      fileName: format => `hoosat-sdk.${format}.js`,
    },
    rollupOptions: {
      // Externalize dependencies that shouldn't be bundled
      external: [],
      output: {
        // Provide global variables for UMD build
        globals: {},
      },
    },
    // Generate source maps for debugging
    sourcemap: true,
    // Target modern browsers
    target: 'es2020',
    // Minify for production
    minify: 'esbuild', // Use esbuild for faster builds, or 'terser' for better compression
  },
  resolve: {
    alias: {
      '@crypto': resolve(__dirname, 'src/crypto'),
      '@transaction': resolve(__dirname, 'src/transaction'),
      '@utils': resolve(__dirname, 'src/utils'),
      '@qr': resolve(__dirname, 'src/qr'),
      '@constants': resolve(__dirname, 'src/constants'),
      '@models': resolve(__dirname, 'src/models'),
      '@libs': resolve(__dirname, 'src/libs'),
      '@enums': resolve(__dirname, 'src/enums'),
    },
  },
  define: {
    // Define process.env for browser compatibility
    'process.env.NODE_ENV': JSON.stringify(process.env.NODE_ENV || 'production'),
  },
  optimizeDeps: {
    // Include dependencies that need to be pre-bundled
    include: ['buffer', 'qrcode'],
  },
});
