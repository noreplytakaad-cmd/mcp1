/**
 * Root endpoint - returns service information
 * Vercel serverless handler
 */

import type { VercelRequest, VercelResponse } from '@vercel/node';

export default function handler(req: VercelRequest, res: VercelResponse): void {
  res.status(200).json({
    status: 'online',
    service: 'Party 1 MPC Node',
    version: '1.0.0',
    environment: process.env.NODE_ENV || 'production',
    endpoints: {
      'POST /api/mpc-party1': 'Store pre-split share or partial key from main website',
      'GET /api/mpc-party1?keyId=<id>': 'Retrieve stored partial key',
    },
    documentation: {
      store_share: {
        method: 'POST',
        url: '/api/mpc-party1',
        body: {
          shareId: 'unique identifier',
          party1Share: 'hex-encoded share',
          timestamp: 'milliseconds since epoch',
          nonce: 'unique request identifier',
        },
        requires: 'x-mpc-signature header (HMAC-SHA256)',
      },
      store_partial_key: {
        method: 'POST',
        url: '/api/mpc-party1',
        body: {
          keyId: 'unique key identifier',
          partialKey: 'hex or base64 encoded key',
          timestamp: 'milliseconds since epoch',
          nonce: 'unique request identifier',
        },
        requires: 'x-mpc-signature header (HMAC-SHA256)',
      },
      retrieve_partial_key: {
        method: 'GET',
        url: '/api/mpc-party1?keyId=<id>',
        description: 'Retrieves from local storage or fetches from main website',
      },
    },
    timestamp: new Date().toISOString(),
  });
}
