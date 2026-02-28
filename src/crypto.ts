import { createSign, createPrivateKey, KeyObject } from 'crypto';
import { readFileSync } from 'fs';
import { TetherError } from './errors.js';
import type { KeyFormat } from './types.js';

/**
 * Imports a DER-encoded private key, trying PKCS#8 first then PKCS#1.
 */
function importDerKey(derData: Buffer): KeyObject {
  try {
    return createPrivateKey({ key: derData, format: 'der', type: 'pkcs8' });
  } catch {
    // PKCS#8 failed — try PKCS#1
  }
  try {
    return createPrivateKey({ key: derData, format: 'der', type: 'pkcs1' });
  } catch {
    // PKCS#1 also failed
  }
  throw new TetherError(
    'Failed to load DER private key: data is not valid PKCS#8 or PKCS#1. ' +
    'Ensure the file is an RSA private key in DER format.'
  );
}

/**
 * Loads a private key from various sources
 */
export function loadPrivateKey(options: {
  keyPath?: string;
  keyPem?: string;
  keyBuffer?: Buffer;
}): KeyObject {
  const { keyPath, keyPem, keyBuffer } = options;

  try {
    if (keyPem) {
      // PEM string provided directly
      return createPrivateKey(keyPem);
    }

    if (keyBuffer) {
      // DER buffer provided directly
      return importDerKey(keyBuffer);
    }

    if (keyPath) {
      // Read from file - detect format by extension or content
      const keyData = readFileSync(keyPath);

      // Try to detect format
      if (keyPath.endsWith('.pem') || keyData.toString().includes('-----BEGIN')) {
        // PEM format
        return createPrivateKey(keyData);
      } else {
        // Assume DER format
        return importDerKey(keyData);
      }
    }

    throw new TetherError('No private key provided');
  } catch (error) {
    if (error instanceof TetherError) {
      throw error;
    }
    throw new TetherError(
      `Failed to load private key: ${error instanceof Error ? error.message : String(error)}`,
      error instanceof Error ? error : undefined
    );
  }
}

/**
 * Signs a challenge string using RSA-SHA256
 * Returns URL-safe base64 encoded signature (no padding)
 */
export function signChallenge(privateKey: KeyObject, challenge: string): string {
  try {
    const sign = createSign('SHA256');
    sign.update(challenge);
    sign.end();
    
    const signature = sign.sign(privateKey);
    
    // Convert to URL-safe base64 without padding
    return signature
      .toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  } catch (error) {
    throw new TetherError(
      `Failed to sign challenge: ${error instanceof Error ? error.message : String(error)}`,
      error instanceof Error ? error : undefined
    );
  }
}

/**
 * Utility function to detect key format from file extension or content
 */
export function detectKeyFormat(keyPath: string): KeyFormat {
  if (keyPath.endsWith('.pem')) {
    return 'pem';
  }
  if (keyPath.endsWith('.der')) {
    return 'der';
  }
  
  // Try to read a small portion to detect format
  try {
    const keyData = readFileSync(keyPath, { encoding: 'utf8', flag: 'r' });
    if (keyData.includes('-----BEGIN')) {
      return 'pem';
    }
  } catch {
    // If we can't read as text, it's probably DER
  }
  
  return 'der';
}