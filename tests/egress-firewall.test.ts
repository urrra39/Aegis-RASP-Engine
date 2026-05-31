import { checkEgressAllowed, EgressFirewallConfig } from '../src/interceptors/egress-firewall';

describe('Egress Firewall', () => {
  const config: EgressFirewallConfig = {
    allowedHosts: ['api.example.com', 'cdn.example.com'],
    blockByDefault: true,
    allowLoopback: true,
  };

  it('allows requests to hosts in the allowlist', () => {
    const result = checkEgressAllowed('api.example.com', config);
    expect(result.allowed).toBe(true);
    expect(result.reason).toBe('host in allowlist');
  });

  it('allows subdomain of allowed host', () => {
    const result = checkEgressAllowed('v2.api.example.com', config);
    expect(result.allowed).toBe(true);
  });

  it('blocks requests to unknown hosts', () => {
    const result = checkEgressAllowed('evil-server.com', config);
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain('not in egress allowlist');
  });

  it('allows loopback addresses', () => {
    expect(checkEgressAllowed('127.0.0.1', config).allowed).toBe(true);
    expect(checkEgressAllowed('localhost', config).allowed).toBe(true);
    expect(checkEgressAllowed('::1', config).allowed).toBe(true);
  });

  it('blocks loopback when allowLoopback is false', () => {
    const strictConfig: EgressFirewallConfig = {
      ...config,
      allowLoopback: false,
    };
    expect(checkEgressAllowed('127.0.0.1', strictConfig).allowed).toBe(false);
  });

  it('allows all hosts when blockByDefault is false', () => {
    const permissiveConfig: EgressFirewallConfig = {
      ...config,
      blockByDefault: false,
    };
    const result = checkEgressAllowed('anything.com', permissiveConfig);
    expect(result.allowed).toBe(true);
    expect(result.reason).toBe('default-allow mode');
  });

  it('is case-insensitive for host matching', () => {
    const result = checkEgressAllowed('API.EXAMPLE.COM', config);
    expect(result.allowed).toBe(true);
  });
});
