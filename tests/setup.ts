/**
 * Vitest global setup.
 *
 * Test runs must never write into the operator's real knowledge store
 * (§P2.2 requirement 6: keep test fixtures out of the production knowledge
 * base). The persistent store lives under the configured data directory, so we
 * point `MIRAI_DATA_DIR` at a throw-away temp directory for the whole run and
 * clean it up on exit. Child processes spawned by the tests (e.g. the stdio
 * server) inherit this environment variable.
 */
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const isolatedDataDir = mkdtempSync(join(tmpdir(), 'mirai-mcp-test-kb-'));
process.env.MIRAI_DATA_DIR = isolatedDataDir;

process.on('exit', () => {
  try {
    rmSync(isolatedDataDir, { recursive: true, force: true });
  } catch {
    /* best-effort cleanup — a leftover temp dir must not fail the suite */
  }
});
