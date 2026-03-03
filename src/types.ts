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
  domain?: string;
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
  /** Verified domain (if this agent has a domain assigned) */
  domain?: string;
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
  domainId?: string;
  domain?: string | null;
  createdAt: number;
  registrationToken?: string;
  lastVerifiedAt?: number;
}

/**
 * A domain registered to the authenticated account
 */
export interface Domain {
  id: string;
  domain: string;
  verified: boolean;
  verifiedAt: number;
  lastCheckedAt: number;
  createdAt: number;
}

/**
 * Response from the issue agent endpoint
 */
export interface IssueAgentResponse {
  id: string;
  agentName: string;
  description: string;
  domainId?: string;
  createdAt: number;
  registrationToken: string;
}

/**
 * Agent key lifecycle entry
 */
export interface AgentKey {
  id: string;
  status: 'active' | 'grace' | 'revoked';
  createdAt: number;
  activatedAt: number;
  graceUntil: number;
  revokedAt: number;
  revokedReason: string;
}

/**
 * Step-up authentication inputs for sensitive key operations
 */
export interface StepUpAuthInput {
  /** Optional email step-up code */
  stepUpCode?: string;
  /** Optional challenge code for key-proof step-up */
  challenge?: string;
  /** Optional signature for key-proof step-up */
  proof?: string;
}

/**
 * Rotate key request options
 */
export interface RotateAgentKeyRequest extends StepUpAuthInput {
  publicKey: string;
  gracePeriodHours?: number;
  reason?: string;
}

/**
 * Rotate key API response
 */
export interface RotateAgentKeyResponse {
  agentId: string;
  previousKeyId?: string | null;
  newKeyId: string;
  graceUntil: number;
  message: string;
}

/**
 * Revoke key request options
 */
export interface RevokeAgentKeyRequest extends StepUpAuthInput {
  reason?: string;
}

/**
 * Revoke key API response
 */
export interface RevokeAgentKeyResponse {
  agentId: string;
  keyId: string;
  revoked: boolean;
  promotedKeyId?: string | null;
  message: string;
}
