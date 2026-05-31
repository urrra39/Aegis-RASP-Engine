import { loadConfig } from '../src/config';

describe('Config', () => {
  const originalEnv = process.env;

  beforeEach(() => {
    process.env = { ...originalEnv };
    process.env.AEGIS_ADMIN_TOKEN = 'test-token';
  });

  afterAll(() => {
    process.env = originalEnv;
  });

  it('loads required AEGIS_ADMIN_TOKEN', () => {
    const config = loadConfig();
    expect(config.adminToken).toBe('test-token');
  });

  it('throws when AEGIS_ADMIN_TOKEN is missing', () => {
    delete process.env.AEGIS_ADMIN_TOKEN;
    expect(() => loadConfig()).toThrow('Missing required environment variable: AEGIS_ADMIN_TOKEN');
  });

  it('uses default log level', () => {
    const config = loadConfig();
    expect(config.logLevel).toBe('info');
  });

  it('reads custom log level', () => {
    process.env.AEGIS_LOG_LEVEL = 'debug';
    const config = loadConfig();
    expect(config.logLevel).toBe('debug');
  });

  it('parses CSV lists', () => {
    process.env.AEGIS_ALLOWED_EGRESS_HOSTS = 'a.com, b.com, c.com';
    const config = loadConfig();
    expect(config.allowedEgressHosts).toEqual(['a.com', 'b.com', 'c.com']);
  });

  it('parses boolean flags', () => {
    process.env.AEGIS_ENABLE_SQLI_PROTECTION = 'false';
    const config = loadConfig();
    expect(config.enableSqliProtection).toBe(false);
  });

  it('defaults feature flags to true', () => {
    const config = loadConfig();
    expect(config.enableSqliProtection).toBe(true);
    expect(config.enableRceProtection).toBe(true);
    expect(config.enableEgressFirewall).toBe(true);
  });
});
