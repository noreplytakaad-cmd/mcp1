/**
 * Party 1 Serverless Handler (Vercel/Express compatible)
 *
 * Receives and processes secure share requests from the main website:
 * 1. Main website (sends pre-split shares to store)
 * 2. Other websites (requests to retrieve stored partial keys)
 *
 * Note: Share generation using Shamir's Secret Sharing is done by the main website
 * Party 1 only receives and stores pre-computed shares and partial keys
 *
 * Security features:
 * - HMAC-SHA256 signature verification
 * - Timestamp validation (prevents old requests)
 * - Nonce replay protection (prevents replay attacks)
 * - Rate limiting (basic request throttling)
 * - CORS headers (allow main website cross-origin requests)
 * - Input validation and sanitization
 */
import type { Request, Response } from 'express';
/**
 * Main handler for Party 1 endpoint
 * Supports:
 * - POST: Store pre-split share or store partial key from main website
 * - GET: Retrieve stored partial key
 */
export default function handler(req: Request, res: Response): Promise<void>;
