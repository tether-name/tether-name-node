/**
 * Base error class for all Tether-related errors
 */
export class TetherError extends Error {
  constructor(message: string, public readonly cause?: Error) {
    super(message);
    this.name = 'TetherError';
    
    // Maintain proper stack trace for where our error was thrown (only available on V8)
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, TetherError);
    }
  }
}

/**
 * Error thrown when verification fails
 */
export class TetherVerificationError extends TetherError {
  constructor(message: string, cause?: Error) {
    super(message, cause);
    this.name = 'TetherVerificationError';
  }
}

/**
 * Error thrown when API requests fail
 */
export class TetherAPIError extends TetherError {
  constructor(
    message: string,
    public readonly status?: number,
    public readonly response?: string,
    cause?: Error
  ) {
    super(message, cause);
    this.name = 'TetherAPIError';
  }
}