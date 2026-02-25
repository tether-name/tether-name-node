import { KeyObject } from 'crypto';
import { TetherError, TetherAPIError, TetherVerificationError } from './errors.js';
import { loadPrivateKey, signChallenge } from './crypto.js';
import type {
  TetherClientConfig,
  ChallengeResponse,
  VerificationRequest,
  VerificationResponse,
  VerificationResult
} from './types.js';

/**
 * TetherClient - Official SDK for tether.name agent identity verification
 */
export class TetherClient {
  private readonly credentialId: string;
  private readonly privateKey: KeyObject;
  private readonly baseUrl: string;

  constructor(config: TetherClientConfig) {
    // Get credential ID from config or environment
    this.credentialId = config.credentialId || process.env.TETHER_CREDENTIAL_ID || '';
    if (!this.credentialId) {
      throw new TetherError('Credential ID is required. Provide it in config or set TETHER_CREDENTIAL_ID environment variable.');
    }

    // Load private key
    const keyPath = config.privateKeyPath || process.env.TETHER_PRIVATE_KEY_PATH;
    this.privateKey = loadPrivateKey({
      keyPath,
      keyPem: config.privateKeyPem,
      keyBuffer: config.privateKeyBuffer
    });

    // Set base URL
    this.baseUrl = config.baseUrl || 'https://api.tether.name';
  }

  /**
   * Request a challenge from the Tether API
   */
  async requestChallenge(): Promise<string> {
    try {
      const response = await fetch(`${this.baseUrl}/challenge`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        }
      });

      if (!response.ok) {
        const errorText = await response.text().catch(() => 'Unknown error');
        throw new TetherAPIError(
          `Challenge request failed: ${response.status} ${response.statusText}`,
          response.status,
          errorText
        );
      }

      const data = await response.json() as ChallengeResponse;
      
      if (!data.code) {
        throw new TetherAPIError('Invalid challenge response: missing code');
      }

      return data.code;
    } catch (error) {
      if (error instanceof TetherError) {
        throw error;
      }
      throw new TetherAPIError(
        `Failed to request challenge: ${error instanceof Error ? error.message : String(error)}`,
        undefined,
        undefined,
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Sign a challenge string
   */
  sign(challenge: string): string {
    return signChallenge(this.privateKey, challenge);
  }

  /**
   * Submit proof for a challenge
   */
  async submitProof(challenge: string, proof: string): Promise<VerificationResult> {
    try {
      const payload: VerificationRequest = {
        challenge,
        proof,
        credentialId: this.credentialId
      };

      const response = await fetch(`${this.baseUrl}/challenge/verify`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(payload)
      });

      if (!response.ok) {
        const errorText = await response.text().catch(() => 'Unknown error');
        throw new TetherAPIError(
          `Verification failed: ${response.status} ${response.statusText}`,
          response.status,
          errorText
        );
      }

      const data = await response.json() as VerificationResponse;

      // Convert API response to our result format
      return {
        verified: data.valid,
        agentName: data.agentName,
        verifyUrl: data.verifyUrl,
        email: data.email,
        registeredSince: data.registeredSince,
        error: data.error,
        challenge
      };
    } catch (error) {
      if (error instanceof TetherError) {
        throw error;
      }
      throw new TetherAPIError(
        `Failed to submit proof: ${error instanceof Error ? error.message : String(error)}`,
        undefined,
        undefined,
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Perform complete verification in one call
   */
  async verify(): Promise<VerificationResult> {
    try {
      const challenge = await this.requestChallenge();
      const proof = this.sign(challenge);
      const result = await this.submitProof(challenge, proof);

      if (!result.verified) {
        throw new TetherVerificationError(
          result.error || 'Verification failed for unknown reason'
        );
      }

      return result;
    } catch (error) {
      if (error instanceof TetherError) {
        throw error;
      }
      throw new TetherVerificationError(
        `Verification failed: ${error instanceof Error ? error.message : String(error)}`,
        error instanceof Error ? error : undefined
      );
    }
  }
}