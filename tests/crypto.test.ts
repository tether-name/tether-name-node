import { describe, it, expect } from 'vitest';
import { generateKeyPairSync, createVerify, createPrivateKey, createPublicKey } from 'crypto';
import { signChallenge, loadPrivateKey, detectKeyFormat } from '../src/crypto.js';
import { TetherError } from '../src/errors.js';

describe('Crypto Module', () => {
  // Generate a test RSA keypair for testing
  const testKeyPair = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem'
    },
    privateKeyEncoding: {
      type: 'pkcs1',
      format: 'pem'
    }
  });

  describe('signChallenge', () => {
    it('should sign a challenge and return URL-safe base64', () => {
      const privateKey = createPrivateKey(testKeyPair.privateKey);
      const challenge = 'test-challenge-12345';
      
      const signature = signChallenge(privateKey, challenge);
      
      // Should be a string
      expect(typeof signature).toBe('string');
      
      // Should not contain standard base64 characters that need URL encoding
      expect(signature).not.toMatch(/[+/=]/);
      
      // Should be longer than 0
      expect(signature.length).toBeGreaterThan(0);
    });

    it('should create verifiable signatures', () => {
      const privateKey = createPrivateKey(testKeyPair.privateKey);
      const publicKey = createPublicKey(testKeyPair.publicKey);
      const challenge = 'test-challenge-verify';
      
      const signature = signChallenge(privateKey, challenge);
      
      // Convert URL-safe base64 back to regular base64
      const regularBase64 = signature
        .replace(/-/g, '+')
        .replace(/_/g, '/');
      
      // Add padding if needed
      const padding = '='.repeat((4 - (regularBase64.length % 4)) % 4);
      const paddedSignature = regularBase64 + padding;
      
      // Verify the signature
      const verify = createVerify('SHA256');
      verify.update(challenge);
      verify.end();
      
      const isValid = verify.verify(publicKey, paddedSignature, 'base64');
      expect(isValid).toBe(true);
    });

    it('should create different signatures for different challenges', () => {
      const privateKey = createPrivateKey(testKeyPair.privateKey);
      
      const sig1 = signChallenge(privateKey, 'challenge-1');
      const sig2 = signChallenge(privateKey, 'challenge-2');
      
      expect(sig1).not.toBe(sig2);
    });

    it('should throw TetherError for invalid private key', () => {
      // Create an invalid key object
      const invalidKey = {} as any;
      
      expect(() => signChallenge(invalidKey, 'test')).toThrow(TetherError);
    });
  });

  describe('loadPrivateKey', () => {
    it('should load PEM key from string', () => {
      const key = loadPrivateKey({ keyPem: testKeyPair.privateKey });
      
      expect(key).toBeDefined();
      expect(key.asymmetricKeyType).toBe('rsa');
    });

    it('should load DER key from buffer', () => {
      const privateKey = createPrivateKey(testKeyPair.privateKey);
      const derBuffer = privateKey.export({ format: 'der', type: 'pkcs1' });
      
      const key = loadPrivateKey({ keyBuffer: derBuffer });
      
      expect(key).toBeDefined();
      expect(key.asymmetricKeyType).toBe('rsa');
    });

    it('should throw error when no key is provided', () => {
      expect(() => loadPrivateKey({})).toThrow(TetherError);
      expect(() => loadPrivateKey({})).toThrow('No private key provided');
    });

    it('should throw TetherError for invalid PEM', () => {
      expect(() => loadPrivateKey({ keyPem: 'invalid-pem' })).toThrow(TetherError);
    });
  });

  describe('detectKeyFormat', () => {
    it('should detect PEM format from extension', () => {
      expect(detectKeyFormat('/path/to/key.pem')).toBe('pem');
    });

    it('should detect DER format from extension', () => {
      expect(detectKeyFormat('/path/to/key.der')).toBe('der');
    });

    it('should default to DER for unknown extension', () => {
      expect(detectKeyFormat('/path/to/key.unknown')).toBe('der');
    });
  });

  describe('Integration test', () => {
    it('should complete full sign/verify cycle', () => {
      const privateKey = createPrivateKey(testKeyPair.privateKey);
      const publicKey = createPublicKey(testKeyPair.publicKey);
      const challenge = 'full-integration-test-challenge-12345';
      
      // Sign the challenge
      const signature = signChallenge(privateKey, challenge);
      
      // Verify it manually (simulating what the server would do)
      const regularBase64 = signature
        .replace(/-/g, '+')
        .replace(/_/g, '/');
      const padding = '='.repeat((4 - (regularBase64.length % 4)) % 4);
      const paddedSignature = regularBase64 + padding;
      
      const verify = createVerify('SHA256');
      verify.update(challenge);
      verify.end();
      
      const isValid = verify.verify(publicKey, paddedSignature, 'base64');
      expect(isValid).toBe(true);
    });
  });
});