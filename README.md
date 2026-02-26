# tether-name

Official Node.js SDK for [tether.name](https://tether.name) — cryptographic identity verification for AI agents. Tether lets AI agents prove their identity using RSA-2048 signatures, enabling trusted agent-to-agent communication.

## Installation

```bash
npm install tether-name
```

Requires Node.js 18+ (uses native `fetch` and `crypto` modules).

## Quick Start

```typescript
import { TetherClient } from 'tether-name';

const client = new TetherClient({
  credentialId: 'your-credential-id',
  privateKeyPath: '/path/to/your/private-key.der'
});

// One-call verification
const result = await client.verify();
console.log(result.verified);    // true
console.log(result.agentName);   // "Jawnnybot"
console.log(result.verifyUrl);   // "https://tether.name/check?challenge=..."
```

## Step-by-Step Usage

For more control over the verification process:

```typescript
import { TetherClient } from 'tether-name';

const client = new TetherClient({
  credentialId: 'your-credential-id',
  privateKeyPem: `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA...
-----END RSA PRIVATE KEY-----`
});

try {
  // 1. Request a challenge from Tether
  const challenge = await client.requestChallenge();
  
  // 2. Sign the challenge with your private key
  const proof = client.sign(challenge);
  
  // 3. Submit the proof for verification
  const result = await client.submitProof(challenge, proof);
  
  if (result.verified) {
    console.log(`✅ Verified as ${result.agentName}`);
    console.log(`📝 Public verification: ${result.verifyUrl}`);
  } else {
    console.log(`❌ Verification failed: ${result.error}`);
  }
} catch (error) {
  console.error('Verification error:', error.message);
}
```

## Configuration Options

### Constructor Options

```typescript
interface TetherClientConfig {
  // Credential ID (required)
  credentialId?: string;           // Or use TETHER_CREDENTIAL_ID env var
  
  // Private key (choose one)
  privateKeyPath?: string;         // Path to DER or PEM file
  privateKeyPem?: string;          // PEM string directly
  privateKeyBuffer?: Buffer;       // DER buffer directly
  
  // Optional
  baseUrl?: string;               // API base URL (defaults to https://api.tether.name)
}
```

### Key Format Support

The SDK supports both DER and PEM private key formats:

```typescript
// From file path (auto-detects format)
const client1 = new TetherClient({
  credentialId: 'your-id',
  privateKeyPath: '/path/to/key.der'    // or .pem
});

// From PEM string
const client2 = new TetherClient({
  credentialId: 'your-id',
  privateKeyPem: '-----BEGIN RSA PRIVATE KEY-----\n...'
});

// From DER buffer
const derBuffer = fs.readFileSync('/path/to/key.der');
const client3 = new TetherClient({
  credentialId: 'your-id',
  privateKeyBuffer: derBuffer
});
```

## Environment Variables

Set these environment variables to avoid hardcoding credentials:

```bash
export TETHER_CREDENTIAL_ID="your-credential-id"
export TETHER_PRIVATE_KEY_PATH="/path/to/your/private-key.der"
```

Then initialize without parameters:

```typescript
const client = new TetherClient({});  // Uses env vars
```

## API Reference

### `TetherClient`

#### `constructor(config: TetherClientConfig)`

Creates a new Tether client instance.

#### `async verify(): Promise<VerificationResult>`

Performs complete verification in one call. Requests challenge, signs it, and submits proof.

**Throws:** `TetherVerificationError` if verification fails.

#### `async requestChallenge(): Promise<string>`

Requests a new challenge from the Tether API.

**Returns:** Challenge string to be signed.

#### `sign(challenge: string): string`

Signs a challenge using the configured private key.

**Returns:** URL-safe base64 signature (no padding).

#### `async submitProof(challenge: string, proof: string): Promise<VerificationResult>`

Submits signed proof to verify the challenge.

### Types

```typescript
interface VerificationResult {
  verified: boolean;           // Whether verification succeeded
  agentName?: string;          // Registered agent name
  verifyUrl?: string;          // Public verification URL
  email?: string;              // Registered email
  registeredSince?: string;    // ISO date of registration
  error?: string;              // Error message if failed
  challenge?: string;          // The verified challenge
}
```

### Errors

- `TetherError` - Base error class
- `TetherVerificationError` - Verification failed
- `TetherAPIError` - API request failed

## Getting Your Credentials

1. Visit [tether.name](https://tether.name)
2. Register your agent and get a credential ID
3. Generate an RSA-2048 private key:

```bash
# Generate private key
openssl genrsa -out private-key.pem 2048

# Convert to DER format (optional)
openssl rsa -in private-key.pem -outform DER -out private-key.der
```

## Requirements

- Node.js 18+ (uses native `fetch`)
- RSA-2048 private key
- Zero runtime dependencies (uses only Node.js built-ins)

## Security Notes

- Keep your private key secure and never commit it to version control
- Use environment variables or secure key management
- The SDK uses SHA256withRSA signatures with URL-safe base64 encoding
- All verification happens server-side at tether.name

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Links

- 🌐 [Tether Website](https://tether.name)
- 📘 [Documentation](https://docs.tether.name)
- 🐛 [Issues](https://github.com/tether-name/tether-name-node/issues)
- 📦 [npm Package](https://www.npmjs.com/package/tether-name)