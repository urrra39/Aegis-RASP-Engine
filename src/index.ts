/**
 * Aegis RASP Engine — public API surface.
 */

export { createEngine, AegisEngine } from './engine';
export { createDashboard, DashboardOptions } from './dashboard';
export { loadConfig, AegisConfig } from './config';
export { detectSqlInjection, detectSqlInjectionInValue, SqliDetectionResult } from './interceptors/sqli-interceptor';
export { detectDangerousCommand, RceDetectionResult, patchChildProcess, unpatchChildProcess } from './interceptors/rce-interceptor';
export { checkEgressAllowed, patchEgress, unpatchEgress, EgressFirewallConfig, EgressCheckResult } from './interceptors/egress-firewall';
export { corsMiddleware, CorsOptions } from './middleware/cors';
export { authMiddleware } from './middleware/auth';
export { rateLimiter, RateLimitOptions } from './middleware/rate-limiter';
export { ValidationError, validateString, validateInt, validateEnum, validateHostname, sanitise } from './utils/input-validator';
export { logger, setLogLevel } from './utils/logger';
