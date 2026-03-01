import { KeyObject } from 'crypto';
import { TetherError, TetherAPIError, TetherVerificationError } from './errors.js';
import { loadPrivateKey, signChallenge } from './crypto.js';
import type {
  TetherClientConfig,
  ChallengeResponse,
  Agent,
  IssueAgentResponse,
  VerificationRequest,
  VerificationResponse,
  VerificationResult
} from './types.js';

/**
 * TetherClient - Official SDK for tether.name agent identity verification
 */
export class TetherClient {
  private readonly agentId: string;
  private readonly privateKey: KeyObject | null;
  private readonly baseUrl: string;
  private readonly apiKey?: string;

  constructor(config: TetherClientConfig) {
    // Set base URL
    this.baseUrl = 'https://api.tether.name';

    // Get API key from config or environment
    this.apiKey = config.apiKey || process.env.TETHER_API_KEY;

    // Get agent ID from config or environment
    this.agentId = config.agentId || process.env.TETHER_AGENT_ID || '';

    // Load private key if key material is provided
    const keyPath = config.privateKeyPath || process.env.TETHER_PRIVATE_KEY_PATH;
    const hasKeyMaterial = keyPath || config.privateKeyPem || config.privateKeyBuffer;

    if (hasKeyMaterial) {
      this.privateKey = loadPrivateKey({
        keyPath,
        keyPem: config.privateKeyPem,
        keyBuffer: config.privateKeyBuffer
      });
    } else {
      this.privateKey = null;
    }

    // If no API key and no private key, agent ID and key are still needed for verify/sign
    // but we defer the error to when those methods are called
    if (!this.apiKey && !this.privateKey) {
      // Allow construction — errors thrown at method call time
    }

    if (!this.apiKey && !this.agentId) {
      // Allow construction — errors thrown at method call time
    }
  }

  /**
   * Returns authorization headers when an API key is configured
   */
  private _authHeaders(): Record<string, string> {
    if (this.apiKey) {
      return { 'Authorization': `Bearer ${this.apiKey}` };
    }
    return {};
  }

  /**
   * Ensures a private key is available, throwing if not
   */
  private _requirePrivateKey(): KeyObject {
    if (!this.privateKey) {
      throw new TetherError(
        'Private key is required for this operation. Provide privateKeyPath, privateKeyPem, or privateKeyBuffer in config, or set TETHER_PRIVATE_KEY_PATH environment variable.'
      );
    }
    return this.privateKey;
  }

  /**
   * Ensures an API key is available, throwing if not
   */
  private _requireApiKey(): void {
    if (!this.apiKey) {
      throw new TetherError(
        'API key is required for agent management operations. Provide apiKey in config or set TETHER_API_KEY environment variable.'
      );
    }
  }

  /**
   * Ensures an agent ID is available, throwing if not
   */
  private _requireAgentId(): string {
    if (!this.agentId) {
      throw new TetherError(
        'Agent ID is required for this operation. Provide it in config or set TETHER_AGENT_ID environment variable.'
      );
    }
    return this.agentId;
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
    const key = this._requirePrivateKey();
    return signChallenge(key, challenge);
  }

  /**
   * Submit proof for a challenge
   */
  async submitProof(challenge: string, proof: string): Promise<VerificationResult> {
    const agentId = this._requireAgentId();

    try {
      const payload: VerificationRequest = {
        challenge,
        proof,
        agentId
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
      const registeredSince = typeof data.registeredSince === 'number'
        ? new Date(data.registeredSince).toISOString()
        : data.registeredSince;

      return {
        verified: data.valid,
        agentName: data.agentName,
        verifyUrl: data.verifyUrl,
        email: data.email,
        registeredSince,
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

  /**
   * Create a new agent
   */
  async createAgent(agentName: string, description: string = ''): Promise<Agent> {
    this._requireApiKey();
    try {
      const response = await fetch(`${this.baseUrl}/agents/issue`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...this._authHeaders()
        },
        body: JSON.stringify({ agentName, description })
      });

      if (!response.ok) {
        const errorText = await response.text().catch(() => 'Unknown error');
        throw new TetherAPIError(
          `Create agent failed: ${response.status} ${response.statusText}`,
          response.status,
          errorText
        );
      }

      const data = await response.json() as IssueAgentResponse;
      return data;
    } catch (error) {
      if (error instanceof TetherError) {
        throw error;
      }
      throw new TetherAPIError(
        `Failed to create agent: ${error instanceof Error ? error.message : String(error)}`,
        undefined,
        undefined,
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * List all agents
   */
  async listAgents(): Promise<Agent[]> {
    this._requireApiKey();
    try {
      const response = await fetch(`${this.baseUrl}/agents`, {
        method: 'GET',
        headers: {
          ...this._authHeaders()
        }
      });

      if (!response.ok) {
        const errorText = await response.text().catch(() => 'Unknown error');
        throw new TetherAPIError(
          `List agents failed: ${response.status} ${response.statusText}`,
          response.status,
          errorText
        );
      }

      const data = await response.json() as Agent[];
      return data;
    } catch (error) {
      if (error instanceof TetherError) {
        throw error;
      }
      throw new TetherAPIError(
        `Failed to list agents: ${error instanceof Error ? error.message : String(error)}`,
        undefined,
        undefined,
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Delete an agent by ID
   */
  async deleteAgent(agentId: string): Promise<boolean> {
    this._requireApiKey();
    try {
      const response = await fetch(`${this.baseUrl}/agents/${agentId}`, {
        method: 'DELETE',
        headers: {
          ...this._authHeaders()
        }
      });

      if (!response.ok) {
        const errorText = await response.text().catch(() => 'Unknown error');
        throw new TetherAPIError(
          `Delete agent failed: ${response.status} ${response.statusText}`,
          response.status,
          errorText
        );
      }

      return true;
    } catch (error) {
      if (error instanceof TetherError) {
        throw error;
      }
      throw new TetherAPIError(
        `Failed to delete agent: ${error instanceof Error ? error.message : String(error)}`,
        undefined,
        undefined,
        error instanceof Error ? error : undefined
      );
    }
  }
}
