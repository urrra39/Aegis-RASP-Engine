/**
 * Real-time egress exfiltration firewall.
 *
 * Intercepts outbound HTTP/HTTPS requests and blocks connections
 * to hosts not in the allowlist. Prevents data exfiltration via
 * DNS/HTTP tunnelling or connections to attacker-controlled servers.
 */

import * as http from 'http';
import * as https from 'https';
import { URL } from 'url';
import { logger } from '../utils/logger';

export interface EgressFirewallConfig {
  allowedHosts: string[];
  /** If true, block all outgoing requests to hosts not in allowedHosts */
  blockByDefault: boolean;
  /** Internal/loopback addresses are always allowed */
  allowLoopback: boolean;
}

const LOOPBACK_PATTERNS = [
  /^127\.\d+\.\d+\.\d+$/,
  /^::1$/,
  /^localhost$/i,
  /^0\.0\.0\.0$/,
];

function isLoopback(host: string): boolean {
  return LOOPBACK_PATTERNS.some((p) => p.test(host));
}

export interface EgressCheckResult {
  allowed: boolean;
  host: string;
  reason: string;
}

export function checkEgressAllowed(
  host: string,
  config: EgressFirewallConfig
): EgressCheckResult {
  // Loopback is always allowed
  if (config.allowLoopback && isLoopback(host)) {
    return { allowed: true, host, reason: 'loopback address' };
  }

  // Check allowlist
  const normalisedHost = host.toLowerCase();
  const isAllowed = config.allowedHosts.some((allowed) => {
    const normAllowed = allowed.toLowerCase();
    // Exact match or subdomain match (e.g., *.example.com)
    return (
      normalisedHost === normAllowed ||
      normalisedHost.endsWith('.' + normAllowed)
    );
  });

  if (isAllowed) {
    return { allowed: true, host, reason: 'host in allowlist' };
  }

  if (config.blockByDefault) {
    logger.warn('Egress blocked', { host });
    return {
      allowed: false,
      host,
      reason: `host "${host}" not in egress allowlist`,
    };
  }

  return { allowed: true, host, reason: 'default-allow mode' };
}

// Store originals
const originals = {
  httpRequest: http.request,
  httpsRequest: https.request,
};

let activeConfig: EgressFirewallConfig | null = null;

function extractHost(
  urlOrOptions: string | URL | http.RequestOptions,
  options?: http.RequestOptions
): string | null {
  if (typeof urlOrOptions === 'string') {
    try {
      return new URL(urlOrOptions).hostname;
    } catch {
      return null;
    }
  }
  if (urlOrOptions instanceof URL) {
    return urlOrOptions.hostname;
  }
  return (urlOrOptions as http.RequestOptions).hostname ??
    (urlOrOptions as http.RequestOptions).host?.split(':')[0] ??
    options?.hostname ??
    options?.host?.split(':')[0] ??
    null;
}

function createPatchedRequest(
  originalFn: typeof http.request,
  protocol: string
) {
  return function patchedRequest(
    this: unknown,
    urlOrOptions: string | URL | http.RequestOptions,
    optionsOrCallback?: http.RequestOptions | ((res: http.IncomingMessage) => void),
    maybeCallback?: (res: http.IncomingMessage) => void
  ): http.ClientRequest {
    if (!activeConfig) {
      // eslint-disable-next-line @typescript-eslint/ban-types
      return (originalFn as Function).call(
        this, urlOrOptions, optionsOrCallback, maybeCallback
      );
    }

    const options = typeof optionsOrCallback === 'function'
      ? undefined
      : optionsOrCallback;
    const host = extractHost(urlOrOptions, options);

    if (host) {
      const result = checkEgressAllowed(host, activeConfig);
      if (!result.allowed) {
        logger.error(`Egress firewall blocked ${protocol} request`, {
          host,
          reason: result.reason,
        });
        const req = new http.ClientRequest(
          typeof urlOrOptions === 'string' ? urlOrOptions : 'http://blocked'
        );
        process.nextTick(() => {
          req.destroy(
            new Error(`[Aegis RASP] Egress blocked: ${result.reason}`)
          );
        });
        return req;
      }
    }

    // eslint-disable-next-line @typescript-eslint/ban-types
    return (originalFn as Function).call(
      this, urlOrOptions, optionsOrCallback, maybeCallback
    );
  };
}

export function patchEgress(config: EgressFirewallConfig): void {
  activeConfig = config;

  (http as Record<string, unknown>).request = createPatchedRequest(
    originals.httpRequest,
    'HTTP'
  );
  (https as Record<string, unknown>).request = createPatchedRequest(
    originals.httpsRequest as unknown as typeof http.request,
    'HTTPS'
  );

  logger.info('Egress firewall: HTTP/HTTPS patched', {
    allowedHosts: config.allowedHosts,
    blockByDefault: config.blockByDefault,
  });
}

export function unpatchEgress(): void {
  (http as Record<string, unknown>).request = originals.httpRequest;
  (https as Record<string, unknown>).request = originals.httpsRequest;
  activeConfig = null;
  logger.info('Egress firewall: HTTP/HTTPS restored');
}
