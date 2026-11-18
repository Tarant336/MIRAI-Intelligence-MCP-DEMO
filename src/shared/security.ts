/**
 * Security boundary (§10 of the platform specification).
 *
 * This module is the single chokepoint through which every tool must pass.
 * It enforces:
 *   - workspace path containment
 *   - capability/risk gating
 *   - artifact size limits
 *   - refusal of offensive / attack-capable artefacts
 *
 * When a request crosses a boundary the boundary returns a *defensive
 * alternative* instead of a vague disclaimer (§10, final paragraph).
 */

import { realpathSync } from 'node:fs';
import { isAbsolute, normalize, relative, resolve, sep } from 'node:path';

import { getConfig } from '../config/index.js';
import { errors, MiraiError } from '../core/errors.js';
import type { Capability, RiskClass } from './types.js';

/** Resolve a user-supplied path and assert it stays inside the workspace. */
export function resolveWorkspacePath(inputPath: string, mustExist = false): string {
  const cfg = getConfig();
  const base = cfg.workspaceRoot;
  const absolute = isAbsolute(inputPath) ? normalize(inputPath) : resolve(base, inputPath);

  let resolved = absolute;
  if (mustExist) {
    try {
      resolved = realpathSync(absolute);
    } catch {
      throw errors.notFound(`Path "${inputPath}"`, { path: absolute });
    }
  }

  const rel = relative(base, resolved);
  const escapes = rel === '' ? false : rel.startsWith('..') || rel.includes(`..${sep}`);
  if (escapes || isAbsolute(rel)) {
    throw errors.pathOutsideWorkspace(resolved, base);
  }
  return resolved;
}

export interface PolicyDecision {
  allowed: boolean;
  risk: RiskClass;
  reason?: string;
  /** A constructive, technically useful alternative when blocked. */
  defensiveAlternative?: string;
}

/** Capabilities that are never permitted, regardless of configuration. */
const FORBIDDEN_CAPABILITY_PATTERNS: RegExp[] = [
  /\bbotnet\b.*\b(build|deploy|infect|propagat)/i,
  /\b(worm|self[-\s]?propagat)/i,
  /\b(source[-\s]?spoof|ip[-\s]?spoof)\w*/i,
  /\b(reflection|amplification)\s+(launcher|attack|flood)/i,
  /\b(ddos|flood|stress)\s+(launcher|tool|generator|attack code)/i,
  /\b(brute[-\s]?force|credential\s+stuff)/i,
  /\bcommand[-\s]?and[-\s]?control\s+(server|infrastructure|deployment)/i,
  /\b(evasion|anti[-\s]?monitor|bypass)\b.*\b(third[-\s]?party|edr|av|surveillance)\b/i,
];

/**
 * Evaluate the intent string of a request against the platform policy.
 * This is a defence-in-depth keyword gate; the real control is capability gating.
 */
export function evaluateIntent(intent: string, requestedRisk: RiskClass): PolicyDecision {
  for (const pattern of FORBIDDEN_CAPABILITY_PATTERNS) {
    if (pattern.test(intent)) {
      return {
        allowed: false,
        risk: 'prohibited',
        reason: `Request matches prohibited capability pattern (${pattern.source}).`,
        defensiveAlternative:
          'The same underlying knowledge can be obtained through defensive tooling: write a detector, ' +
          'an offline parser, a lab-restricted simulator, or a regression test instead of an operational capability.',
      };
    }
  }

  if (requestedRisk === 'prohibited') {
    return {
      allowed: false,
      risk: 'prohibited',
      reason: 'Requested risk class is prohibited by platform policy.',
      defensiveAlternative:
        'Reframe the task as analysis, detection, mitigation or offline verification.',
    };
  }

  if (requestedRisk === 'isolated_exec' && !getConfig().allowIsolatedExec) {
    return {
      allowed: false,
      risk: requestedRisk,
      reason: 'Isolated execution is disabled (MIRAI_ALLOW_ISOLATED_EXEC=false).',
      defensiveAlternative: 'Enable isolated execution or use a static-analysis-only path.',
    };
  }

  if (requestedRisk === 'external_fetch' && !getConfig().allowPublicFetch) {
    return {
      allowed: false,
      risk: requestedRisk,
      reason: 'Public fetching is disabled (MIRAI_ALLOW_PUBLIC_FETCH=false).',
      defensiveAlternative: 'Provide the artefact locally or enable public fetch explicitly.',
    };
  }

  return { allowed: true, risk: requestedRisk };
}

/** Assert that a set of capabilities is grantable. */
export function assertCapabilities(capabilities: Capability[]): void {
  const cfg = getConfig();
  if (capabilities.includes('network_public_fetch') && !cfg.allowPublicFetch) {
    throw new MiraiError(
      'EXTERNAL_FETCH_DISABLED',
      'This tool requires public network access which is disabled.',
      'Set MIRAI_ALLOW_PUBLIC_FETCH=true, or supply the resource locally.',
    );
  }
  if (capabilities.includes('run_isolated') && !cfg.allowIsolatedExec) {
    throw errors.policyBlocked(
      'This tool requires isolated execution which is disabled.',
      'Set MIRAI_ALLOW_ISOLATED_EXEC=true to permit sandboxed build/test/emulation.',
    );
  }
}

/** Enforce the configured maximum artifact size. */
export function assertArtifactSize(bytes: number): void {
  const limit = getConfig().maxArtifactBytes;
  if (bytes > limit) throw errors.artifactTooLarge(bytes, limit);
}

/**
 * Active/lab testing requires an explicit authorization token (§4.4).
 * This gate is intentionally strict: no token, no active test.
 */
export function requireLabAuthorization(token: string | undefined): void {
  const expected = getConfig().labAuthorizationToken;
  if (!expected) {
    throw errors.policyBlocked(
      'Active/lab testing requires an authorization token but none is configured.',
      'Set MIRAI_LAB_TOKEN to an operator-controlled secret and pass it as "labToken".',
    );
  }
  if (!token || token !== expected) {
    throw errors.policyBlocked(
      'Active/lab testing authorization token is missing or invalid.',
      'Pass the exact value of MIRAI_LAB_TOKEN as the "labToken" argument.',
    );
  }
}

/** Convenience: require that a boolean guard holds, else raise POLICY_BLOCKED. */
export function requirePolicy(condition: boolean, reason: string, hint: string): void {
  if (!condition) throw errors.policyBlocked(reason, hint);
}
