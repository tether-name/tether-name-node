"use strict";
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/index.ts
var index_exports = {};
__export(index_exports, {
  TetherAPIError: () => TetherAPIError,
  TetherClient: () => TetherClient,
  TetherError: () => TetherError,
  TetherVerificationError: () => TetherVerificationError,
  detectKeyFormat: () => detectKeyFormat,
  loadPrivateKey: () => loadPrivateKey,
  signChallenge: () => signChallenge
});
module.exports = __toCommonJS(index_exports);

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
var import_crypto = require("crypto");
var import_fs = require("fs");
function loadPrivateKey(options) {
  const { keyPath, keyPem, keyBuffer } = options;
  try {
    if (keyPem) {
      return (0, import_crypto.createPrivateKey)(keyPem);
    }
    if (keyBuffer) {
      return (0, import_crypto.createPrivateKey)({
        key: keyBuffer,
        format: "der",
        type: "pkcs1"
      });
    }
    if (keyPath) {
      const keyData = (0, import_fs.readFileSync)(keyPath);
      if (keyPath.endsWith(".pem") || keyData.toString().includes("-----BEGIN")) {
        return (0, import_crypto.createPrivateKey)(keyData);
      } else {
        return (0, import_crypto.createPrivateKey)({
          key: keyData,
          format: "der",
          type: "pkcs1"
        });
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
    const sign = (0, import_crypto.createSign)("SHA256");
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
    const keyData = (0, import_fs.readFileSync)(keyPath, { encoding: "utf8", flag: "r" });
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
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  TetherAPIError,
  TetherClient,
  TetherError,
  TetherVerificationError,
  detectKeyFormat,
  loadPrivateKey,
  signChallenge
});
//# sourceMappingURL=index.js.map