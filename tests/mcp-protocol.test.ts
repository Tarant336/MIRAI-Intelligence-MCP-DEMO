/**
 * MCP protocol-level tests: connect a real SDK Client to the server over an
 * in-memory transport and exercise initialize / tools/list / tools/call / prompts.
 */

import { describe, expect, it, beforeAll, afterAll } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';

import { buildRegistry, VERSION } from '../src/index.js';
import { createServer } from '../src/core/server.js';

let client: Client;

beforeAll(async () => {
  const registry = buildRegistry();
  const server = createServer({ registry, version: VERSION });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  client = new Client({ name: 'mirai-test-client', version: '0.0.1' });
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
});

afterAll(async () => {
  await client?.close();
});

describe('MCP protocol', () => {
  it('lists all registered tools with schemas', async () => {
    const { tools } = await client.listTools();
    expect(tools.length).toBeGreaterThan(50);
    const health = tools.find((t) => t.name === 'health_check');
    expect(health).toBeTruthy();
    expect(health?.inputSchema).toBeTruthy();
  });

  it('exposes prompts', async () => {
    const { prompts } = await client.listPrompts();
    const names = prompts.map((p) => p.name);
    expect(names).toContain('autonomous_task');
    expect(names).toContain('malware_research_workflow');
    expect(names).toContain('anti_ddos_defense_workflow');
  });

  it('calls health_check over the protocol', async () => {
    const res = await client.callTool({ name: 'health_check', arguments: {} });
    expect(res.isError).toBeFalsy();
    expect(res.content).toBeTruthy();
    expect(res.structuredContent).toBeTruthy();
    const sc = res.structuredContent as { ok: boolean; data: { status: string } };
    expect(sc.ok).toBe(true);
    expect(sc.data.status).toBe('ok');
  });

  it('blocks a tool when public fetch is disabled', async () => {
    const prev = process.env.MIRAI_ALLOW_PUBLIC_FETCH;
    process.env.MIRAI_ALLOW_PUBLIC_FETCH = 'false';
    const { resetConfig } = await import('../src/config/index.js');
    resetConfig();
    try {
      const res = await client.callTool({
        name: 'cve_search',
        arguments: { cveId: 'CVE-2017-17215', offline: false },
      });
      const sc = res.structuredContent as { ok: boolean; blocked?: boolean };
      expect(sc.ok).toBe(false);
      expect(sc.blocked).toBe(true);
    } finally {
      if (prev === undefined) delete process.env.MIRAI_ALLOW_PUBLIC_FETCH;
      else process.env.MIRAI_ALLOW_PUBLIC_FETCH = prev;
      resetConfig();
    }
  });

  it('serves the knowledge stats resource', async () => {
    const { resources } = await client.listResources();
    expect(resources.some((r) => r.uri === 'mirai://knowledge/stats')).toBe(true);
    const read = await client.readResource({ uri: 'mirai://knowledge/stats' });
    expect(read.contents[0]?.text).toContain('records');
  });
});
