/**
 * Tether Name SDK - Official Node.js library for tether.name agent identity verification
 * 
 * @example
 * ```typescript
 * import { TetherClient } from 'tether-name';
 * 
 * const client = new TetherClient({
 *   credentialId: 'your-credential-id',
 *   privateKeyPath: '/path/to/key.der'
 * });
 * 
 * const result = await client.verify();
 * console.log(result.verified, result.agentName);
 * ```
 */

// Main exports
export { TetherClient } from './client.js';

// Types
export type {
  TetherClientConfig,
  ChallengeResponse,
  VerificationRequest,
  VerificationResponse,
  VerificationResult,
  KeyFormat
} from './types.js';

// Errors
export {
  TetherError,
  TetherAPIError,
  TetherVerificationError
} from './errors.js';

// Crypto utilities (for advanced use cases)
export {
  loadPrivateKey,
  signChallenge,
  detectKeyFormat
} from './crypto.js';