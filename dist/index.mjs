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
function loadPrivateKey(options) {
  const { keyPath, keyPem, keyBuffer } = options;
  try {
    if (keyPem) {
      return createPrivateKey(keyPem);
    }
    if (keyBuffer) {
      return createPrivateKey({
        key: keyBuffer,
        format: "der",
        type: "pkcs1"
      });
    }
    if (keyPath) {
      const keyData = readFileSync(keyPath);
      if (keyPath.endsWith(".pem") || keyData.toString().includes("-----BEGIN")) {
        return createPrivateKey(keyData);
      } else {
        return createPrivateKey({
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
  constructor(config) {
    this.credentialId = config.credentialId || process.env.TETHER_CREDENTIAL_ID || "";
    if (!this.credentialId) {
      throw new TetherError("Credential ID is required. Provide it in config or set TETHER_CREDENTIAL_ID environment variable.");
    }
    const keyPath = config.privateKeyPath || process.env.TETHER_PRIVATE_KEY_PATH;
    this.privateKey = loadPrivateKey({
      keyPath,
      keyPem: config.privateKeyPem,
      keyBuffer: config.privateKeyBuffer
    });
    this.baseUrl = config.baseUrl || "https://api.tether.name";
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
    return signChallenge(this.privateKey, challenge);
  }
  /**
   * Submit proof for a challenge
   */
  async submitProof(challenge, proof) {
    try {
      const payload = {
        challenge,
        proof,
        credentialId: this.credentialId
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