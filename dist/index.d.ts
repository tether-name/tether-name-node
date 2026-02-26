import { KeyObject } from 'crypto';

/**
 * Configuration options for TetherClient
 */
interface TetherClientConfig {
    /** The credential ID for the agent */
    credentialId?: string;
    /** Path to the private key file (DER or PEM format) */
    privateKeyPath?: string;
    /** Private key as a string (PEM format) */
    privateKeyPem?: string;
    /** Private key as a Buffer (DER format) */
    privateKeyBuffer?: Buffer;
    /** Base URL for the Tether API (defaults to https://api.tether.name) */
    baseUrl?: string;
    /** API key for management operations (alternative to credential auth) */
    apiKey?: string;
}
/**
 * Response from the challenge request endpoint
 */
interface ChallengeResponse {
    code: string;
}
/**
 * Request payload for challenge verification
 */
interface VerificationRequest {
    challenge: string;
    proof: string;
    credentialId: string;
}
/**
 * Response from the challenge verification endpoint
 */
interface VerificationResponse {
    valid: boolean;
    verifyUrl?: string;
    agentName?: string;
    email?: string;
    registeredSince?: string;
    error?: string;
}
/**
 * Result of a tether verification attempt
 */
interface VerificationResult {
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
type KeyFormat = 'pem' | 'der';
/**
 * A credential associated with an agent
 */
interface Credential {
    id: string;
    agentName: string;
    description: string;
    createdAt: number;
    registrationToken?: string;
    lastVerifiedAt?: number;
}
/**
 * Response from the issue credential endpoint
 */
interface IssueCredentialResponse {
    id: string;
    agentName: string;
    description: string;
    createdAt: number;
    registrationToken: string;
}

/**
 * TetherClient - Official SDK for tether.name agent identity verification
 */
declare class TetherClient {
    private readonly credentialId;
    private readonly privateKey;
    private readonly baseUrl;
    private readonly apiKey?;
    constructor(config: TetherClientConfig);
    /**
     * Returns authorization headers when an API key is configured
     */
    private _authHeaders;
    /**
     * Ensures a private key is available, throwing if not
     */
    private _requirePrivateKey;
    /**
     * Ensures a credential ID is available, throwing if not
     */
    private _requireCredentialId;
    /**
     * Request a challenge from the Tether API
     */
    requestChallenge(): Promise<string>;
    /**
     * Sign a challenge string
     */
    sign(challenge: string): string;
    /**
     * Submit proof for a challenge
     */
    submitProof(challenge: string, proof: string): Promise<VerificationResult>;
    /**
     * Perform complete verification in one call
     */
    verify(): Promise<VerificationResult>;
    /**
     * Create a new credential for an agent
     */
    createCredential(agentName: string, description?: string): Promise<Credential>;
    /**
     * List all credentials
     */
    listCredentials(): Promise<Credential[]>;
    /**
     * Delete a credential by ID
     */
    deleteCredential(credentialId: string): Promise<boolean>;
}

/**
 * Base error class for all Tether-related errors
 */
declare class TetherError extends Error {
    readonly cause?: Error | undefined;
    constructor(message: string, cause?: Error | undefined);
}
/**
 * Error thrown when verification fails
 */
declare class TetherVerificationError extends TetherError {
    constructor(message: string, cause?: Error);
}
/**
 * Error thrown when API requests fail
 */
declare class TetherAPIError extends TetherError {
    readonly status?: number | undefined;
    readonly response?: string | undefined;
    constructor(message: string, status?: number | undefined, response?: string | undefined, cause?: Error);
}

/**
 * Loads a private key from various sources
 */
declare function loadPrivateKey(options: {
    keyPath?: string;
    keyPem?: string;
    keyBuffer?: Buffer;
}): KeyObject;
/**
 * Signs a challenge string using RSA-SHA256
 * Returns URL-safe base64 encoded signature (no padding)
 */
declare function signChallenge(privateKey: KeyObject, challenge: string): string;
/**
 * Utility function to detect key format from file extension or content
 */
declare function detectKeyFormat(keyPath: string): KeyFormat;

export { type ChallengeResponse, type Credential, type IssueCredentialResponse, type KeyFormat, TetherAPIError, TetherClient, type TetherClientConfig, TetherError, TetherVerificationError, type VerificationRequest, type VerificationResponse, type VerificationResult, detectKeyFormat, loadPrivateKey, signChallenge };
