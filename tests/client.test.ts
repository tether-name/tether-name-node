import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { TetherClient } from '../src/client.js';
import { TetherAPIError, TetherVerificationError } from '../src/errors.js';
import { generateKeyPairSync } from 'crypto';

// Generate a test RSA key pair
const { privateKey } = generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});

const BASE_URL = 'https://api.tether.name';

function makeClient(overrides?: { apiKey?: string; noKey?: boolean }) {
  return new TetherClient({
    credentialId: 'test-credential-id',
    privateKeyPem: overrides?.noKey ? undefined : privateKey,
    apiKey: overrides?.apiKey,
  });
}

function mockFetch(response: object, status = 200) {
  return vi.fn().mockResolvedValue({
    ok: status >= 200 && status < 300,
    status,
    statusText: status === 200 ? 'OK' : 'Error',
    json: () => Promise.resolve(response),
    text: () => Promise.resolve(JSON.stringify(response)),
  });
}

describe('TetherClient - HTTP interactions', () => {
  const originalFetch = globalThis.fetch;

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  describe('requestChallenge', () => {
    it('should POST to /challenge and return the code', async () => {
      const mock = mockFetch({ code: 'test-uuid-challenge' });
      globalThis.fetch = mock;

      const client = makeClient();
      const code = await client.requestChallenge();

      expect(code).toBe('test-uuid-challenge');
      expect(mock).toHaveBeenCalledOnce();
      const [url, opts] = mock.mock.calls[0];
      expect(url).toBe(`${BASE_URL}/challenge`);
      expect(opts.method).toBe('POST');
    });

    it('should throw TetherAPIError on non-200 response', async () => {
      globalThis.fetch = mockFetch({ error: 'rate limited' }, 429);

      const client = makeClient();
      await expect(client.requestChallenge()).rejects.toThrow(TetherAPIError);
    });

    it('should throw TetherAPIError when response has no code', async () => {
      globalThis.fetch = mockFetch({});

      const client = makeClient();
      await expect(client.requestChallenge()).rejects.toThrow('missing code');
    });
  });

  describe('submitProof', () => {
    it('should POST proof to /challenge/verify with credentialId', async () => {
      const mock = mockFetch({
        valid: true,
        agentName: 'Test Agent',
        verifyUrl: 'https://tether.name/check?challenge=abc',
      });
      globalThis.fetch = mock;

      const client = makeClient();
      const result = await client.submitProof('challenge-code', 'proof-signature');

      expect(result.verified).toBe(true);
      expect(result.agentName).toBe('Test Agent');
      expect(result.verifyUrl).toBe('https://tether.name/check?challenge=abc');
      expect(result.challenge).toBe('challenge-code');

      const body = JSON.parse(mock.mock.calls[0][1].body);
      expect(body.challenge).toBe('challenge-code');
      expect(body.proof).toBe('proof-signature');
      expect(body.credentialId).toBe('test-credential-id');
    });

    it('should throw TetherAPIError on HTTP error', async () => {
      globalThis.fetch = mockFetch({ error: 'invalid' }, 401);

      const client = makeClient();
      await expect(client.submitProof('c', 'p')).rejects.toThrow(TetherAPIError);
    });
  });

  describe('verify (end-to-end)', () => {
    it('should request challenge, sign, and submit proof', async () => {
      let callCount = 0;
      globalThis.fetch = vi.fn().mockImplementation(async (url: string) => {
        callCount++;
        if (callCount === 1) {
          // requestChallenge
          expect(url).toContain('/challenge');
          return {
            ok: true, status: 200, statusText: 'OK',
            json: () => Promise.resolve({ code: 'verify-challenge' }),
            text: () => Promise.resolve(''),
          };
        } else {
          // submitProof
          expect(url).toContain('/challenge/verify');
          return {
            ok: true, status: 200, statusText: 'OK',
            json: () => Promise.resolve({
              valid: true,
              agentName: 'My Agent',
              verifyUrl: 'https://tether.name/check?challenge=verify-challenge',
            }),
            text: () => Promise.resolve(''),
          };
        }
      });

      const client = makeClient();
      const result = await client.verify();

      expect(result.verified).toBe(true);
      expect(result.agentName).toBe('My Agent');
      expect(callCount).toBe(2);
    });

    it('should throw TetherVerificationError when verification returns invalid', async () => {
      let callCount = 0;
      globalThis.fetch = vi.fn().mockImplementation(async () => {
        callCount++;
        if (callCount === 1) {
          return {
            ok: true, status: 200, statusText: 'OK',
            json: () => Promise.resolve({ code: 'fail-challenge' }),
            text: () => Promise.resolve(''),
          };
        } else {
          return {
            ok: true, status: 200, statusText: 'OK',
            json: () => Promise.resolve({ valid: false, error: 'Invalid signature' }),
            text: () => Promise.resolve(''),
          };
        }
      });

      const client = makeClient();
      await expect(client.verify()).rejects.toThrow(TetherVerificationError);
    });
  });

  describe('createAgent', () => {
    it('should POST to /credentials/issue with auth header', async () => {
      const mock = mockFetch({
        id: 'agent-123',
        agentName: 'New Bot',
        description: 'A test bot',
        createdAt: 1700000000000,
        registrationToken: 'reg-token-xyz',
      });
      globalThis.fetch = mock;

      const client = makeClient({ apiKey: 'test-api-key' });
      const agent = await client.createAgent('New Bot', 'A test bot');

      expect(agent.id).toBe('agent-123');
      expect(agent.agentName).toBe('New Bot');
      expect(agent.registrationToken).toBe('reg-token-xyz');

      const [url, opts] = mock.mock.calls[0];
      expect(url).toBe(`${BASE_URL}/credentials/issue`);
      expect(opts.method).toBe('POST');
      expect(opts.headers['Authorization']).toBe('Bearer test-api-key');

      const body = JSON.parse(opts.body);
      expect(body.agentName).toBe('New Bot');
      expect(body.description).toBe('A test bot');
    });

    it('should throw when no API key is configured', async () => {
      const client = makeClient();
      await expect(client.createAgent('bot')).rejects.toThrow();
    });

    it('should throw TetherAPIError on server error', async () => {
      globalThis.fetch = mockFetch({ error: 'Unauthorized' }, 401);

      const client = makeClient({ apiKey: 'bad-key' });
      await expect(client.createAgent('bot')).rejects.toThrow(TetherAPIError);
    });
  });

  describe('listAgents', () => {
    it('should GET /credentials with auth header', async () => {
      const agents = [
        { id: 'a1', agentName: 'Bot 1', description: '', createdAt: 1700000000000 },
        { id: 'a2', agentName: 'Bot 2', description: 'helper', createdAt: 1700000001000 },
      ];
      const mock = mockFetch(agents);
      globalThis.fetch = mock;

      const client = makeClient({ apiKey: 'test-api-key' });
      const result = await client.listAgents();

      expect(result).toHaveLength(2);
      expect(result[0].agentName).toBe('Bot 1');
      expect(result[1].agentName).toBe('Bot 2');

      const [url, opts] = mock.mock.calls[0];
      expect(url).toBe(`${BASE_URL}/credentials`);
      expect(opts.method).toBe('GET');
      expect(opts.headers['Authorization']).toBe('Bearer test-api-key');
    });

    it('should throw when no API key is configured', async () => {
      const client = makeClient();
      await expect(client.listAgents()).rejects.toThrow();
    });
  });

  describe('deleteAgent', () => {
    it('should DELETE /credentials/:id with auth header', async () => {
      const mock = mockFetch({});
      globalThis.fetch = mock;

      const client = makeClient({ apiKey: 'test-api-key' });
      const result = await client.deleteAgent('agent-to-delete');

      expect(result).toBe(true);

      const [url, opts] = mock.mock.calls[0];
      expect(url).toBe(`${BASE_URL}/credentials/agent-to-delete`);
      expect(opts.method).toBe('DELETE');
      expect(opts.headers['Authorization']).toBe('Bearer test-api-key');
    });

    it('should throw TetherAPIError on 404', async () => {
      globalThis.fetch = mockFetch({ error: 'Not found' }, 404);

      const client = makeClient({ apiKey: 'test-api-key' });
      await expect(client.deleteAgent('nonexistent')).rejects.toThrow(TetherAPIError);
    });

    it('should throw when no API key is configured', async () => {
      const client = makeClient();
      await expect(client.deleteAgent('any-id')).rejects.toThrow();
    });
  });

  describe('error handling', () => {
    it('should wrap network errors in TetherAPIError', async () => {
      globalThis.fetch = vi.fn().mockRejectedValue(new Error('Network failure'));

      const client = makeClient();
      await expect(client.requestChallenge()).rejects.toThrow(TetherAPIError);
    });
  });
});
