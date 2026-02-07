"use strict";
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
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.default = handler;
const crypto_1 = __importDefault(require("crypto"));
const party1_1 = require("./party1");
/**
 * Security state: track used nonces to prevent replay attacks
 * In production, use Redis or memcached instead of in-memory
 */
const usedNonces = new Set();
const nonceTTL = 5 * 60 * 1000; // 5 minutes
const nonceTimestamps = new Map();
/**
 * Rate limiting state: track request count per IP
 * In production, use Redis with TTL
 */
const requestCounts = new Map();
const requestTimestamps = new Map();
const RATE_LIMIT_WINDOW = 60 * 1000; // 1 minute
const RATE_LIMIT_MAX = 100; // Max 100 requests per minute per IP
/**
 * List of allowed origins for CORS (configure via env)
 */
const ALLOWED_ORIGINS = (process.env.MPC_ALLOWED_ORIGINS || 'http://localhost:3001,http://localhost:8080').split(',');
/**
 * Add CORS headers to response
 * Allows cross-origin requests from configured main website
 */
function addCORSHeaders(req, res) {
    const origin = req.headers.origin;
    // Only add CORS headers if origin is in allowed list
    if (ALLOWED_ORIGINS.includes(origin)) {
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type, x-mpc-signature');
        res.setHeader('Access-Control-Allow-Credentials', 'true');
    }
}
/**
 * Check and enforce rate limits per IP address
 * Prevents abuse and DDoS attacks
 */
function checkRateLimit(ip) {
    const now = Date.now();
    const lastRequest = requestTimestamps.get(ip) || 0;
    // Reset counter if window has passed
    if (now - lastRequest > RATE_LIMIT_WINDOW) {
        requestCounts.set(ip, 0);
        requestTimestamps.set(ip, now);
    }
    const count = requestCounts.get(ip) || 0;
    if (count >= RATE_LIMIT_MAX) {
        return false; // Rate limited
    }
    // Increment counter
    requestCounts.set(ip, count + 1);
    requestTimestamps.set(ip, now);
    return true;
}
/**
 * Clean up expired nonces to prevent memory leaks
 * Runs periodically to remove old entries
 */
function cleanupExpiredNonces() {
    const now = Date.now();
    const expiredNonces = [];
    for (const [nonce, timestamp] of nonceTimestamps.entries()) {
        if (now - timestamp > nonceTTL) {
            expiredNonces.push(nonce);
            usedNonces.delete(nonce);
            nonceTimestamps.delete(nonce);
        }
    }
    if (expiredNonces.length > 0) {
        console.log(`[Party 1] Cleaned up ${expiredNonces.length} expired nonces`);
    }
}
/**
 * Verify HMAC-SHA256 signature
 * Ensures request comes from authorized source
 *
 * @param payload Request body as JSON string
 * @param signature Hex-encoded HMAC from request header
 * @param secret Shared secret for HMAC computation
 * @returns true if signature is valid
 */
function verifySignature(payload, signature, secret) {
    try {
        const hmac = crypto_1.default.createHmac('sha256', secret).update(payload).digest('hex');
        // Use timingsafe comparison to prevent timing attacks
        return crypto_1.default.timingSafeEqual(Buffer.from(hmac), Buffer.from(signature));
    }
    catch (err) {
        // timingSafeEqual throws if lengths differ; return false
        console.warn('[Party 1] Signature verification error:', err instanceof Error ? err.message : String(err));
        return false;
    }
}
/**
 * Verify timestamp is within acceptable window
 * Prevents old requests from being replayed
 *
 * @param timestamp Milliseconds since epoch
 * @param windowMs Acceptable window (default ±2 minutes)
 * @returns true if timestamp is valid (within window)
 */
function verifyTimestamp(timestamp, windowMs = 2 * 60 * 1000) {
    if (!Number.isInteger(timestamp) || timestamp <= 0) {
        return false;
    }
    const now = Date.now();
    return Math.abs(now - timestamp) <= windowMs;
}
/**
 * Check if nonce has been used before (replay protection)
 * Prevents same request from being processed twice
 *
 * @param nonce Unique identifier for request
 * @returns true if nonce is valid (not previously used)
 */
function validateAndRecordNonce(nonce) {
    if (!nonce || nonce.trim().length === 0) {
        return false;
    }
    if (usedNonces.has(nonce)) {
        return false; // Nonce already used
    }
    // Record nonce and timestamp
    usedNonces.add(nonce);
    nonceTimestamps.set(nonce, Date.now());
    return true;
}
/**
 * Get requestor's IP address (handle proxies)
 */
function getClientIP(req) {
    return (req.headers['x-forwarded-for']?.split(',')[0].trim() ||
        req.headers['x-real-ip'] ||
        req.socket?.remoteAddress ||
        'unknown');
}
/**
 * Fetch partial key from main website (localhost:5000)
 *
 * @param keyId Key identifier
 * @returns Object with success status and details or null
 */
async function fetchPartialKeyFromMainWebsite(keyId) {
    try {
        const mainWebsiteUrl = process.env.MAIN_WEBSITE_URL || 'http://localhost:5000';
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 5000);
        console.log(`[Party 1] Fetching partial key from ${mainWebsiteUrl}/api/partial-key/${keyId}`);
        const response = await fetch(`${mainWebsiteUrl}/api/partial-key/${keyId}`, {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${process.env.MAIN_WEBSITE_SECRET || ''}`,
            },
            signal: controller.signal,
        });
        clearTimeout(timeout);
        if (!response.ok) {
            const statusText = response.statusText || `HTTP ${response.status}`;
            console.warn(`[Party 1] Main website responded with: ${response.status} ${statusText}`);
            return {
                success: false,
                reason: `Main website returned ${response.status}: ${statusText}`,
            };
        }
        const data = await response.json();
        if (!data.partialKey) {
            console.warn(`[Party 1] Main website did not return partialKey field`);
            return {
                success: false,
                reason: 'Main website response missing partialKey field',
            };
        }
        console.log(`[Party 1] Successfully fetched partial key from main website`);
        return {
            success: true,
            key: data.partialKey,
        };
    }
    catch (err) {
        const errorMsg = err instanceof Error ? err.message : String(err);
        if (err instanceof Error && err.name === 'AbortError') {
            console.error('[Party 1] Request timeout - main website took too long to respond');
            return {
                success: false,
                reason: 'Request timeout (5s) - main website not responding',
            };
        }
        console.error('[Party 1] Error fetching partial key from main website:', errorMsg);
        return {
            success: false,
            reason: `Connection error: ${errorMsg}`,
        };
    }
}
/**
 * Main handler for Party 1 endpoint
 * Supports:
 * - POST: Store pre-split share or store partial key from main website
 * - GET: Retrieve stored partial key
 */
async function handler(req, res) {
    // Add CORS headers to all responses
    addCORSHeaders(req, res);
    // Handle OPTIONS requests (CORS preflight)
    if (req.method === 'OPTIONS') {
        res.status(200).end();
        return;
    }
    // Handle GET requests - retrieve partial key
    if (req.method === 'GET') {
        const keyId = (req.query.keyId || req.query.key_id);
        if (!keyId) {
            res.status(400).json({
                error: 'Missing required parameter',
                required: ['keyId or key_id'],
                hint: 'Provide keyId as query parameter: ?keyId=<id>',
            });
            return;
        }
        try {
            const partialKey = party1_1.party1.getPartialKey(keyId);
            if (partialKey) {
                // Found in local storage
                res.status(200).json({
                    success: true,
                    operation: 'retrieve_partial_key',
                    keyId,
                    partialKey,
                    source: 'local_storage',
                    timestamp: new Date().toISOString(),
                });
                return;
            }
            // Not found locally, try to fetch from main website
            console.log(`[Party 1] Partial key ${keyId} not found locally. Attempting to fetch from main website...`);
            const fetchResult = await fetchPartialKeyFromMainWebsite(keyId);
            if (fetchResult.success && fetchResult.key) {
                // Successfully fetched from main website
                party1_1.party1.storePartialKey(keyId, fetchResult.key);
                res.status(200).json({
                    success: true,
                    operation: 'retrieve_partial_key',
                    keyId,
                    partialKey: fetchResult.key,
                    source: 'main_website',
                    message: 'Partial key successfully retrieved from main website and cached locally',
                    timestamp: new Date().toISOString(),
                });
                return;
            }
            // Failed to fetch from main website
            res.status(404).json({
                success: false,
                error: 'Partial key not found',
                keyId,
                sources_checked: ['local_storage', 'main_website'],
                reason: fetchResult.reason,
                message: 'No partial key found in local storage or from main website',
                timestamp: new Date().toISOString(),
            });
            return;
        }
        catch (err) {
            res.status(500).json({
                error: 'Failed to retrieve partial key',
                details: err instanceof Error ? err.message : String(err),
            });
            return;
        }
    }
    if (req.method !== 'POST') {
        res.status(405).json({
            error: 'Method not allowed',
            allowed: ['GET', 'POST', 'OPTIONS'],
        });
        return;
    }
    try {
        const clientIP = getClientIP(req);
        // Check rate limit
        if (!checkRateLimit(clientIP)) {
            console.warn(`[Party 1] Rate limit exceeded for IP: ${clientIP}`);
            res.status(429).json({
                error: 'Too many requests',
                message: `Rate limit: ${RATE_LIMIT_MAX} requests per minute`,
            });
            return;
        }
        // Clean up old nonces periodically
        if (Math.random() < 0.1) {
            // Run cleanup 10% of the time
            cleanupExpiredNonces();
        }
        // Parse request body
        const { shareId, // For storing pre-split share
        party1Share, // Pre-split share value
        keyId, // For partial key storage
        partialKey, // Partial key from main website
        timestamp, // Request timestamp
        nonce, // Unique request identifier
         } = req.body;
        const signature = req.headers['x-mpc-signature'];
        // STEP 1: Validate required fields
        if (!timestamp) {
            res.status(400).json({
                error: 'Missing required field',
                required: ['timestamp'],
                hint: 'timestamp must be current milliseconds since epoch',
            });
            return;
        }
        if (!signature) {
            res.status(400).json({
                error: 'Missing required header',
                required: ['x-mpc-signature'],
                hint: 'Compute HMAC-SHA256 of request body using MPC_PARTY1_SECRET',
            });
            return;
        }
        if (!nonce) {
            res.status(400).json({
                error: 'Missing required field',
                required: ['nonce'],
                hint: 'Provide unique nonce for replay protection',
            });
            return;
        }
        // STEP 2: Load secret and validate configuration
        const secret = process.env.MPC_PARTY1_SECRET;
        if (!secret) {
            console.error('[Party 1] MPC_PARTY1_SECRET not configured');
            res.status(500).json({
                error: 'Server configuration error',
                details: 'MPC_PARTY1_SECRET environment variable not set',
            });
            return;
        }
        // STEP 3: Verify timestamp
        if (!verifyTimestamp(timestamp)) {
            res.status(401).json({
                error: 'Invalid request timestamp',
                message: 'Request timestamp must be within ±2 minutes of server time',
                serverTime: Date.now(),
                requestTime: timestamp,
            });
            return;
        }
        // STEP 4: Verify nonce (replay protection)
        if (!validateAndRecordNonce(nonce)) {
            res.status(401).json({
                error: 'Invalid nonce',
                message: 'Nonce has already been used or is empty (possible replay attack)',
            });
            return;
        }
        // STEP 5: Verify HMAC signature
        const payload = JSON.stringify({
            shareId,
            party1Share,
            keyId,
            partialKey,
            timestamp,
            nonce,
        });
        if (!verifySignature(payload, signature, secret)) {
            console.warn(`[Party 1] Invalid signature from IP: ${clientIP}`);
            res.status(401).json({
                error: 'Invalid signature',
                message: 'HMAC-SHA256 signature verification failed',
            });
            return;
        }
        // STEP 6: Process request based on operation type
        // Operation 1: Store pre-split party1Share
        if (shareId && party1Share) {
            try {
                party1_1.party1.storeShareHex(shareId, party1Share);
                console.log(`[Party 1] Stored pre-split share for ID: ${shareId}`);
                res.status(200).json({
                    success: true,
                    operation: 'store_share',
                    shareId,
                    stored_at: new Date().toISOString(),
                });
                return;
            }
            catch (err) {
                res.status(400).json({
                    error: 'Failed to store share',
                    details: err instanceof Error ? err.message : String(err),
                });
                return;
            }
        }
        // Operation 2: Store partial key from main website
        if (keyId && partialKey) {
            try {
                party1_1.party1.storePartialKey(keyId, partialKey);
                console.log(`[Party 1] Stored partial key with ID: ${keyId}`);
                res.status(200).json({
                    success: true,
                    operation: 'store_partial_key',
                    keyId,
                    stored_at: new Date().toISOString(),
                });
                return;
            }
            catch (err) {
                res.status(400).json({
                    error: 'Failed to store partial key',
                    details: err instanceof Error ? err.message : String(err),
                });
                return;
            }
        }
        // No valid operation provided
        res.status(400).json({
            error: 'Missing operation fields',
            operations: [
                { name: 'store_share', requires: ['shareId', 'party1Share'] },
                { name: 'store_partial_key', requires: ['keyId', 'partialKey'] },
            ],
        });
        return;
    }
    catch (error) {
        console.error('[Party 1] Unexpected handler error:', error);
        res.status(500).json({
            error: 'Internal server error',
            details: error instanceof Error ? error.message : 'Unknown error',
            timestamp: new Date().toISOString(),
        });
    }
}
//# sourceMappingURL=mpc-party1.js.map