/**
 * Strict input validation utilities.
 * Every user-facing value MUST pass through a validator before use.
 */

export class ValidationError extends Error {
  constructor(
    public readonly field: string,
    public readonly reason: string
  ) {
    super(`Validation failed for "${field}": ${reason}`);
    this.name = 'ValidationError';
  }
}

/** Ensure a value is a non-empty string within a maximum length. */
export function validateString(
  field: string,
  value: unknown,
  maxLength = 10_000
): string {
  if (typeof value !== 'string') {
    throw new ValidationError(field, 'expected a string');
  }
  if (value.length === 0) {
    throw new ValidationError(field, 'must not be empty');
  }
  if (value.length > maxLength) {
    throw new ValidationError(
      field,
      `exceeds maximum length of ${maxLength}`
    );
  }
  return value;
}

/** Ensure a value is a positive integer within bounds. */
export function validateInt(
  field: string,
  value: unknown,
  min = 0,
  max = Number.MAX_SAFE_INTEGER
): number {
  const n = typeof value === 'string' ? Number(value) : value;
  if (typeof n !== 'number' || !Number.isInteger(n)) {
    throw new ValidationError(field, 'expected an integer');
  }
  if (n < min || n > max) {
    throw new ValidationError(field, `must be between ${min} and ${max}`);
  }
  return n;
}

/** Ensure a value matches a fixed set of allowed strings. */
export function validateEnum<T extends string>(
  field: string,
  value: unknown,
  allowed: readonly T[]
): T {
  const s = validateString(field, value);
  if (!allowed.includes(s as T)) {
    throw new ValidationError(
      field,
      `must be one of: ${allowed.join(', ')}`
    );
  }
  return s as T;
}

/** Sanitise a string by removing characters outside a safe set. */
export function sanitise(input: string): string {
  return input.replace(/[^\w\s@.,:/-]/g, '');
}

/** Validate that a hostname looks reasonable (no injection payloads). */
export function validateHostname(field: string, value: unknown): string {
  const s = validateString(field, value, 253);
  if (!/^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$/.test(s)) {
    throw new ValidationError(field, 'invalid hostname');
  }
  return s;
}
