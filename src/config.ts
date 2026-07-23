/**
 * Centralised, environment-driven configuration.
 * Every tuneable is loaded from process.env — nothing is hardcoded.
 */

export interface AegisConfig {
  /** Token required for admin/dashboard endpoints */
  adminToken: string;
  /** Logging verbosity */
  logLevel: 'debug' | 'info' | 'warn' | 'error';
  /** Hosts the egress firewall allows outbound connections to */
  allowedEgressHosts: string[];
  /** Origins permitted by CORS (empty = deny all cross-origin) */
  corsAllowedOrigins: string[];
  /** Feature flags */
  enableSqliProtection: boolean;
  enableRceProtection: boolean;
  enableEgressFirewall: boolean;
}

function requiredEnv(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(
      `Missing required environment variable: ${name}. ` +
      `See .env.example for reference.`
    );
  }
  return value;
}

function optionalEnv(name: string, fallback: string): string {
  return process.env[name] ?? fallback;
}

function csvList(name: string, fallback: string): string[] {
  const raw = optionalEnv(name, fallback);
  return raw
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

function bool(name: string, fallback: boolean): boolean {
  const raw = process.env[name];
  if (raw === undefined) return fallback;
  return raw.toLowerCase() === 'true' || raw === '1';
}

export function loadConfig(): AegisConfig {
  return {
    adminToken: requiredEnv('AEGIS_ADMIN_TOKEN'),
    logLevel: optionalEnv('AEGIS_LOG_LEVEL', 'info') as AegisConfig['logLevel'],
    allowedEgressHosts: csvList('AEGIS_ALLOWED_EGRESS_HOSTS', ''),
    corsAllowedOrigins: csvList('AEGIS_CORS_ALLOWED_ORIGINS', ''),
    enableSqliProtection: bool('AEGIS_ENABLE_SQLI_PROTECTION', true),
    enableRceProtection: bool('AEGIS_ENABLE_RCE_PROTECTION', true),
    enableEgressFirewall: bool('AEGIS_ENABLE_EGRESS_FIREWALL', true),
  };
}
