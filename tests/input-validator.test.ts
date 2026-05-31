import {
  validateString,
  validateInt,
  validateEnum,
  validateHostname,
  sanitise,
  ValidationError,
} from '../src/utils/input-validator';

describe('Input Validator', () => {
  describe('validateString', () => {
    it('accepts valid strings', () => {
      expect(validateString('name', 'hello')).toBe('hello');
    });

    it('rejects non-strings', () => {
      expect(() => validateString('name', 42)).toThrow(ValidationError);
      expect(() => validateString('name', null)).toThrow(ValidationError);
    });

    it('rejects empty strings', () => {
      expect(() => validateString('name', '')).toThrow(ValidationError);
    });

    it('rejects strings exceeding max length', () => {
      const long = 'a'.repeat(101);
      expect(() => validateString('name', long, 100)).toThrow(ValidationError);
    });
  });

  describe('validateInt', () => {
    it('accepts valid integers', () => {
      expect(validateInt('port', 8080)).toBe(8080);
    });

    it('parses string integers', () => {
      expect(validateInt('port', '8080')).toBe(8080);
    });

    it('rejects non-integers', () => {
      expect(() => validateInt('port', 'abc')).toThrow(ValidationError);
      expect(() => validateInt('port', 3.14)).toThrow(ValidationError);
    });

    it('enforces min/max bounds', () => {
      expect(() => validateInt('port', -1, 0, 65535)).toThrow(ValidationError);
      expect(() => validateInt('port', 70000, 0, 65535)).toThrow(ValidationError);
    });
  });

  describe('validateEnum', () => {
    it('accepts allowed values', () => {
      expect(validateEnum('level', 'info', ['debug', 'info', 'warn'] as const)).toBe('info');
    });

    it('rejects disallowed values', () => {
      expect(() => validateEnum('level', 'trace', ['debug', 'info'] as const)).toThrow(ValidationError);
    });
  });

  describe('validateHostname', () => {
    it('accepts valid hostnames', () => {
      expect(validateHostname('host', 'api.example.com')).toBe('api.example.com');
      expect(validateHostname('host', 'localhost')).toBe('localhost');
    });

    it('rejects invalid hostnames', () => {
      expect(() => validateHostname('host', 'evil;rm -rf /')).toThrow(ValidationError);
      expect(() => validateHostname('host', '../../../etc/passwd')).toThrow(ValidationError);
    });
  });

  describe('sanitise', () => {
    it('strips dangerous characters', () => {
      expect(sanitise('hello<script>alert(1)</script>')).toBe('helloscriptalert1/script');
    });

    it('preserves safe characters', () => {
      expect(sanitise('user@example.com')).toBe('user@example.com');
      expect(sanitise('hello world')).toBe('hello world');
    });
  });
});
