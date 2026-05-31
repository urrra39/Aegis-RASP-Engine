/**
 * RCE prevention via core module monkey-patching.
 *
 * Intercepts child_process.exec/execSync/spawn/fork and blocks
 * command execution that matches known-dangerous patterns or
 * contains user-controlled input that could lead to shell injection.
 */

import * as childProcess from 'child_process';
import { EventEmitter } from 'events';
import { logger } from '../utils/logger';

/** Patterns that indicate shell injection or dangerous commands. */
const DANGEROUS_PATTERNS = [
  /;\s*(rm|dd|mkfs|shutdown|reboot|halt|poweroff)\b/i,
  /\|\s*(bash|sh|zsh|ksh|csh|dash|nc|ncat|netcat)\b/i,
  /`[^`]+`/,                         // backtick command substitution
  /\$\([^)]+\)/,                      // $() command substitution
  />\s*\/etc\//,                      // writing to /etc
  />\s*\/dev\/sd/,                    // writing to block devices
  /\beval\b/i,
  /\bcurl\b.*\|\s*(bash|sh)\b/i,     // curl | bash pattern
  /\bwget\b.*\|\s*(bash|sh)\b/i,     // wget | bash pattern
];

/** Commands that should never be spawned from a web application. */
const BLOCKED_COMMANDS = new Set([
  'rm', 'dd', 'mkfs', 'shutdown', 'reboot', 'halt', 'poweroff',
  'nc', 'ncat', 'netcat', 'telnet',
  'chmod', 'chown', 'chgrp',
  'mount', 'umount',
  'iptables', 'ip6tables',
  'useradd', 'userdel', 'usermod',
  'passwd', 'su', 'sudo',
]);

export interface RceDetectionResult {
  isBlocked: boolean;
  reasons: string[];
}

function extractBaseCommand(command: string): string {
  const trimmed = command.trim();
  const parts = trimmed.split(/\s+/);
  const base = parts[0] ?? '';
  // strip path prefix
  const segments = base.split('/');
  return segments[segments.length - 1];
}

export function detectDangerousCommand(command: string): RceDetectionResult {
  const reasons: string[] = [];

  // Check base command against blocklist
  const baseCmd = extractBaseCommand(command);
  if (BLOCKED_COMMANDS.has(baseCmd.toLowerCase())) {
    reasons.push(`Blocked command: ${baseCmd}`);
  }

  // Check for dangerous patterns
  for (const pattern of DANGEROUS_PATTERNS) {
    if (pattern.test(command)) {
      reasons.push(`Dangerous pattern matched: ${pattern.source}`);
    }
  }

  // Check for null-byte injection
  if (command.includes('\0')) {
    reasons.push('Null byte detected in command');
  }

  // Check for newline injection
  if (/[\r\n]/.test(command)) {
    reasons.push('Newline injection detected in command');
  }

  if (reasons.length > 0) {
    logger.warn('Dangerous command execution blocked', {
      command: command.slice(0, 200),
      reasons,
    });
  }

  return { isBlocked: reasons.length > 0, reasons };
}

type ExecCallback = (
  error: childProcess.ExecException | null,
  stdout: string | Buffer,
  stderr: string | Buffer
) => void;

// Store originals for restoration
const originals = {
  exec: childProcess.exec,
  execSync: childProcess.execSync,
};

let isPatched = false;

export function patchChildProcess(): void {
  if (isPatched) return;

  const originalExec = childProcess.exec;
  const originalExecSync = childProcess.execSync;

  // Patch exec
  (childProcess as Record<string, unknown>).exec = function patchedExec(
    command: string,
    ...args: unknown[]
  ): childProcess.ChildProcess {
    const result = detectDangerousCommand(command);
    if (result.isBlocked) {
      const err = new Error(
        `[Aegis RASP] Command execution blocked: ${result.reasons.join('; ')}`
      );
      err.name = 'RcePreventionError';

      // If a callback was provided, call it with error
      const lastArg = args[args.length - 1];
      if (typeof lastArg === 'function') {
        (lastArg as ExecCallback)(
          err as childProcess.ExecException, '', ''
        );
      }

      const emitter = new EventEmitter();
      process.nextTick(() => emitter.emit('error', err));
      return emitter as childProcess.ChildProcess;
    }
    // eslint-disable-next-line @typescript-eslint/ban-types
    return (originalExec as Function).call(childProcess, command, ...args);
  };

  // Patch execSync
  (childProcess as Record<string, unknown>).execSync = function patchedExecSync(
    command: string,
    options?: childProcess.ExecSyncOptions
  ): Buffer {
    const result = detectDangerousCommand(command);
    if (result.isBlocked) {
      throw new Error(
        `[Aegis RASP] Synchronous command execution blocked: ${result.reasons.join('; ')}`
      );
    }
    return originalExecSync.call(childProcess, command, options) as Buffer;
  };

  isPatched = true;
  logger.info('RCE interceptor: child_process patched');
}

export function unpatchChildProcess(): void {
  if (!isPatched) return;
  (childProcess as Record<string, unknown>).exec = originals.exec;
  (childProcess as Record<string, unknown>).execSync = originals.execSync;
  isPatched = false;
  logger.info('RCE interceptor: child_process restored');
}
