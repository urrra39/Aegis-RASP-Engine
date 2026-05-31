/**
 * Aegis RASP Engine — core orchestrator.
 *
 * Initialises all protection modules based on config and exposes
 * a unified API for starting/stopping the RASP agent.
 */

import { AegisConfig, loadConfig } from './config';
import { logger, setLogLevel } from './utils/logger';
import { patchChildProcess, unpatchChildProcess } from './interceptors/rce-interceptor';
import { patchEgress, unpatchEgress, EgressFirewallConfig } from './interceptors/egress-firewall';
import { detectSqlInjection, detectSqlInjectionInValue, SqliDetectionResult } from './interceptors/sqli-interceptor';

export interface AegisEngine {
  config: AegisConfig;
  /** Check a SQL query for injection attempts */
  checkSql(query: string): SqliDetectionResult;
  /** Check a user-supplied value for injection payloads */
  checkSqlValue(value: string): SqliDetectionResult;
  /** Shut down all protections and restore originals */
  shutdown(): void;
}

export function createEngine(overrides?: Partial<AegisConfig>): AegisEngine {
  const config = { ...loadConfig(), ...overrides };
  setLogLevel(config.logLevel);

  logger.info('Aegis RASP Engine starting', {
    sqli: config.enableSqliProtection,
    rce: config.enableRceProtection,
    egress: config.enableEgressFirewall,
  });

  // Activate RCE protection
  if (config.enableRceProtection) {
    patchChildProcess();
  }

  // Activate egress firewall
  if (config.enableEgressFirewall) {
    const egressConfig: EgressFirewallConfig = {
      allowedHosts: config.allowedEgressHosts,
      blockByDefault: true,
      allowLoopback: true,
    };
    patchEgress(egressConfig);
  }

  logger.info('Aegis RASP Engine ready');

  return {
    config,

    checkSql(query: string): SqliDetectionResult {
      if (!config.enableSqliProtection) {
        return { isMalicious: false, reasons: [], tokens: [] };
      }
      return detectSqlInjection(query);
    },

    checkSqlValue(value: string): SqliDetectionResult {
      if (!config.enableSqliProtection) {
        return { isMalicious: false, reasons: [], tokens: [] };
      }
      return detectSqlInjectionInValue(value);
    },

    shutdown(): void {
      logger.info('Aegis RASP Engine shutting down');
      unpatchChildProcess();
      unpatchEgress();
    },
  };
}
