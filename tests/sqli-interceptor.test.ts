import { detectSqlInjection, detectSqlInjectionInValue } from '../src/interceptors/sqli-interceptor';

describe('SQL Injection Interceptor', () => {
  describe('detectSqlInjection', () => {
    it('allows legitimate SELECT queries', () => {
      const result = detectSqlInjection("SELECT id, name FROM users WHERE id = 42");
      expect(result.isMalicious).toBe(false);
      expect(result.reasons).toHaveLength(0);
    });

    it('allows legitimate INSERT queries', () => {
      const result = detectSqlInjection(
        "INSERT INTO logs (action, user_id) VALUES ('login', 5)"
      );
      expect(result.isMalicious).toBe(false);
    });

    it('detects UNION SELECT injection', () => {
      const result = detectSqlInjection(
        "SELECT name FROM users WHERE id = 1 UNION SELECT password FROM admins"
      );
      expect(result.isMalicious).toBe(true);
      expect(result.reasons).toEqual(
        expect.arrayContaining([expect.stringContaining('UNION SELECT')])
      );
    });

    it('detects stacked queries', () => {
      const result = detectSqlInjection(
        "SELECT 1; DROP TABLE users"
      );
      expect(result.isMalicious).toBe(true);
      expect(result.reasons).toEqual(
        expect.arrayContaining([expect.stringContaining('Stacked queries')])
      );
    });

    it('detects tautology (OR 1=1)', () => {
      const result = detectSqlInjection(
        "SELECT * FROM users WHERE name = '' OR 1 = 1"
      );
      expect(result.isMalicious).toBe(true);
    });

    it('detects DROP TABLE', () => {
      const result = detectSqlInjection(
        "SELECT 1; DROP TABLE users"
      );
      expect(result.isMalicious).toBe(true);
      expect(result.reasons).toEqual(
        expect.arrayContaining([expect.stringContaining('DROP')])
      );
    });

    it('detects comment-based truncation', () => {
      const result = detectSqlInjection(
        "SELECT * FROM users WHERE name = 'admin' -- AND password = 'x'"
      );
      expect(result.isMalicious).toBe(true);
      expect(result.reasons).toEqual(
        expect.arrayContaining([expect.stringContaining('comment')])
      );
    });

    it('detects SLEEP-based blind injection', () => {
      const result = detectSqlInjection(
        "SELECT * FROM users WHERE id = 1 AND SLEEP(5)"
      );
      expect(result.isMalicious).toBe(true);
      expect(result.reasons).toEqual(
        expect.arrayContaining([expect.stringContaining('SLEEP')])
      );
    });

    it('detects INFORMATION_SCHEMA access', () => {
      const result = detectSqlInjection(
        "SELECT * FROM INFORMATION_SCHEMA.tables"
      );
      expect(result.isMalicious).toBe(true);
    });

    it('detects BENCHMARK injection', () => {
      const result = detectSqlInjection(
        "SELECT BENCHMARK(5000000, SHA1('test'))"
      );
      expect(result.isMalicious).toBe(true);
    });
  });

  describe('detectSqlInjectionInValue', () => {
    it('allows normal string values', () => {
      const result = detectSqlInjectionInValue('John Doe');
      expect(result.isMalicious).toBe(false);
    });

    it('detects injection payload in a value', () => {
      const result = detectSqlInjectionInValue("1 OR 1=1 --");
      expect(result.isMalicious).toBe(true);
      expect(result.reasons.length).toBeGreaterThan(0);
    });
  });
});
