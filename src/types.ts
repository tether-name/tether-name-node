/**
 * Configuration options for TetherClient
 */
export interface TetherClientConfig {
  /** The agent ID */
  agentId?: string;
  /** Path to the private key file (DER or PEM format) */
  privateKeyPath?: string;
  /** Private key as a string (PEM format) */
  privateKeyPem?: string;
  /** Private key as a Buffer (DER format) */
  privateKeyBuffer?: Buffer;
  /** API key for management operations (alternative to agent auth) */
  apiKey?: string;
}

/**
 * Response from the challenge request endpoint
 */
export interface ChallengeResponse {
  code: string;
}

/**
 * Request payload for challenge verification
 */
export interface VerificationRequest {
  challenge: string;
  proof: string;
  agentId: string;
}

/**
 * Response from the challenge verification endpoint
 */
export interface VerificationResponse {
  valid: boolean;
  verifyUrl?: string;
  agentName?: string;
  email?: string;
  /** Raw API value (epoch ms from service; older services may return ISO strings) */
  registeredSince?: number | string;
  error?: string;
}

/**
 * Result of a tether verification attempt
 */
export interface VerificationResult {
  /** Whether the verification was successful */
  verified: boolean;
  /** The agent's registered name */
  agentName?: string;
  /** Public verification URL */
  verifyUrl?: string;
  /** The agent's registered email */
  email?: string;
  /** ISO date string of when the agent was registered */
  registeredSince?: string;
  /** Error message if verification failed */
  error?: string;
  /** The challenge that was verified */
  challenge?: string;
}

/**
 * Supported private key formats
 */
export type KeyFormat = 'pem' | 'der';

/**
 * An agent with its associated metadata
 */
export interface Agent {
  id: string;
  agentName: string;
  description: string;
  createdAt: number;
  registrationToken?: string;
  lastVerifiedAt?: number;
}

/**
 * Response from the issue agent endpoint
 */
export interface IssueAgentResponse {
  id: string;
  agentName: string;
  description: string;
  createdAt: number;
  registrationToken: string;
}
