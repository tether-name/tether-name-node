// src/errors.ts
var TetherError = class _TetherError extends Error {
  constructor(message, cause) {
    super(message);
    this.cause = cause;
    this.name = "TetherError";
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, _TetherError);
    }
  }
};
var TetherVerificationError = class extends TetherError {
  constructor(message, cause) {
    super(message, cause);
    this.name = "TetherVerificationError";
  }
};
var TetherAPIError = class extends TetherError {
  constructor(message, status, response, cause) {
    super(message, cause);
    this.status = status;
    this.response = response;
    this.name = "TetherAPIError";
  }
};

// src/crypto.ts
import { createSign, createPrivateKey } from "crypto";
import { readFileSync } from "fs";
function importDerKey(derData) {
  try {
    return createPrivateKey({ key: derData, format: "der", type: "pkcs8" });
  } catch {
  }
  try {
    return createPrivateKey({ key: derData, format: "der", type: "pkcs1" });
  } catch {
  }
  throw new TetherError(
    "Failed to load DER private key: data is not valid PKCS#8 or PKCS#1. Ensure the file is an RSA private key in DER format."
  );
}
function loadPrivateKey(options) {
  const { keyPath, keyPem, keyBuffer } = options;
  try {
    if (keyPem) {
      return createPrivateKey(keyPem);
    }
    if (keyBuffer) {
      return importDerKey(keyBuffer);
    }
    if (keyPath) {
      const keyData = readFileSync(keyPath);
      if (keyPath.endsWith(".pem") || keyData.toString().includes("-----BEGIN")) {
        return createPrivateKey(keyData);
      } else {
        return importDerKey(keyData);
      }
    }
    throw new TetherError("No private key provided");
  } catch (error) {
    if (error instanceof TetherError) {
      throw error;
    }
    throw new TetherError(
      `Failed to load private key: ${error instanceof Error ? error.message : String(error)}`,
      error instanceof Error ? error : void 0
    );
  }
}
function signChallenge(privateKey, challenge) {
  try {
    const sign = createSign("SHA256");
    sign.update(challenge);
    sign.end();
    const signature = sign.sign(privateKey);
    return signature.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
  } catch (error) {
    throw new TetherError(
      `Failed to sign challenge: ${error instanceof Error ? error.message : String(error)}`,
      error instanceof Error ? error : void 0
    );
  }
}
function detectKeyFormat(keyPath) {
  if (keyPath.endsWith(".pem")) {
    return "pem";
  }
  if (keyPath.endsWith(".der")) {
    return "der";
  }
  try {
    const keyData = readFileSync(keyPath, { encoding: "utf8", flag: "r" });
    if (keyData.includes("-----BEGIN")) {
      return "pem";
    }
  } catch {
  }
  return "der";
}

// src/client.ts
var TetherClient = class {
  credentialId;
  privateKey;
  baseUrl;
  apiKey;
  constructor(config) {
    this.baseUrl = config.baseUrl || "https://api.tether.name";
    this.apiKey = config.apiKey || process.env.TETHER_API_KEY;
    this.credentialId = config.credentialId || process.env.TETHER_CREDENTIAL_ID || "";
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
    if (!this.apiKey && !this.privateKey) {
    }
    if (!this.apiKey && !this.credentialId) {
    }
  }
  /**
   * Returns authorization headers when an API key is configured
   */
  _authHeaders() {
    if (this.apiKey) {
      return { "Authorization": `Bearer ${this.apiKey}` };
    }
    return {};
  }
  /**
   * Ensures a private key is available, throwing if not
   */
  _requirePrivateKey() {
    if (!this.privateKey) {
      throw new TetherError(
        "Private key is required for this operation. Provide privateKeyPath, privateKeyPem, or privateKeyBuffer in config, or set TETHER_PRIVATE_KEY_PATH environment variable."
      );
    }
    return this.privateKey;
  }
  /**
   * Ensures an API key is available, throwing if not
   */
  _requireApiKey() {
    if (!this.apiKey) {
      throw new TetherError(
        "API key is required for agent management operations. Provide apiKey in config or set TETHER_API_KEY environment variable."
      );
    }
  }
  /**
   * Ensures a credential ID is available, throwing if not
   */
  _requireCredentialId() {
    if (!this.credentialId) {
      throw new TetherError(
        "Credential ID is required for this operation. Provide it in config or set TETHER_CREDENTIAL_ID environment variable."
      );
    }
    return this.credentialId;
  }
  /**
   * Request a challenge from the Tether API
   */
  async requestChallenge() {
    try {
      const response = await fetch(`${this.baseUrl}/challenge`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        }
      });
      if (!response.ok) {
        const errorText = await response.text().catch(() => "Unknown error");
        throw new TetherAPIError(
          `Challenge request failed: ${response.status} ${response.statusText}`,
          response.status,
          errorText
        );
      }
      const data = await response.json();
      if (!data.code) {
        throw new TetherAPIError("Invalid challenge response: missing code");
      }
      return data.code;
    } catch (error) {
      if (error instanceof TetherError) {
        throw error;
      }
      throw new TetherAPIError(
        `Failed to request challenge: ${error instanceof Error ? error.message : String(error)}`,
        void 0,
        void 0,
        error instanceof Error ? error : void 0
      );
    }
  }
  /**
   * Sign a challenge string
   */
  sign(challenge) {
    const key = this._requirePrivateKey();
    return signChallenge(key, challenge);
  }
  /**
   * Submit proof for a challenge
   */
  async submitProof(challenge, proof) {
    const credentialId = this._requireCredentialId();
    try {
      const payload = {
        challenge,
        proof,
        credentialId
      };
      const response = await fetch(`${this.baseUrl}/challenge/verify`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify(payload)
      });
      if (!response.ok) {
        const errorText = await response.text().catch(() => "Unknown error");
        throw new TetherAPIError(
          `Verification failed: ${response.status} ${response.statusText}`,
          response.status,
          errorText
        );
      }
      const data = await response.json();
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
        void 0,
        void 0,
        error instanceof Error ? error : void 0
      );
    }
  }
  /**
   * Perform complete verification in one call
   */
  async verify() {
    try {
      const challenge = await this.requestChallenge();
      const proof = this.sign(challenge);
      const result = await this.submitProof(challenge, proof);
      if (!result.verified) {
        throw new TetherVerificationError(
          result.error || "Verification failed for unknown reason"
        );
      }
      return result;
    } catch (error) {
      if (error instanceof TetherError) {
        throw error;
      }
      throw new TetherVerificationError(
        `Verification failed: ${error instanceof Error ? error.message : String(error)}`,
        error instanceof Error ? error : void 0
      );
    }
  }
  /**
   * Create a new agent
   */
  async createAgent(agentName, description = "") {
    this._requireApiKey();
    try {
      const response = await fetch(`${this.baseUrl}/credentials/issue`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...this._authHeaders()
        },
        body: JSON.stringify({ agentName, description })
      });
      if (!response.ok) {
        const errorText = await response.text().catch(() => "Unknown error");
        throw new TetherAPIError(
          `Create agent failed: ${response.status} ${response.statusText}`,
          response.status,
          errorText
        );
      }
      const data = await response.json();
      return data;
    } catch (error) {
      if (error instanceof TetherError) {
        throw error;
      }
      throw new TetherAPIError(
        `Failed to create agent: ${error instanceof Error ? error.message : String(error)}`,
        void 0,
        void 0,
        error instanceof Error ? error : void 0
      );
    }
  }
  /**
   * List all agents
   */
  async listAgents() {
    this._requireApiKey();
    try {
      const response = await fetch(`${this.baseUrl}/credentials`, {
        method: "GET",
        headers: {
          ...this._authHeaders()
        }
      });
      if (!response.ok) {
        const errorText = await response.text().catch(() => "Unknown error");
        throw new TetherAPIError(
          `List agents failed: ${response.status} ${response.statusText}`,
          response.status,
          errorText
        );
      }
      const data = await response.json();
      return data;
    } catch (error) {
      if (error instanceof TetherError) {
        throw error;
      }
      throw new TetherAPIError(
        `Failed to list agents: ${error instanceof Error ? error.message : String(error)}`,
        void 0,
        void 0,
        error instanceof Error ? error : void 0
      );
    }
  }
  /**
   * Delete an agent by ID
   */
  async deleteAgent(agentId) {
    this._requireApiKey();
    try {
      const response = await fetch(`${this.baseUrl}/credentials/${agentId}`, {
        method: "DELETE",
        headers: {
          ...this._authHeaders()
        }
      });
      if (!response.ok) {
        const errorText = await response.text().catch(() => "Unknown error");
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
        void 0,
        void 0,
        error instanceof Error ? error : void 0
      );
    }
  }
};
export {
  TetherAPIError,
  TetherClient,
  TetherError,
  TetherVerificationError,
  detectKeyFormat,
  loadPrivateKey,
  signChallenge
};
//# sourceMappingURL=index.mjs.map