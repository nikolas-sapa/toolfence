// Connection layer: establishes an MCP client over HTTP or stdio and
// gathers transport-level facts the security checks rely on.

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { SSEClientTransport } from "@modelcontextprotocol/sdk/client/sse.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import type { ConnectionContext, ToolInfo } from "./types.js";

export interface ConnectResult {
  client: Client;
  connection: ConnectionContext;
  tools: ToolInfo[];
  close: () => Promise<void>;
}

export interface ConnectOptions {
  // For HTTP targets: a bearer token to attach (tests authenticated servers).
  bearer?: string;
  // Treat the target as a stdio command instead of a URL.
  stdio?: boolean;
}

const CLIENT_INFO = { name: "mcpguard", version: "0.1.0" };

function isUrl(target: string): boolean {
  return /^https?:\/\//i.test(target);
}

// Lightweight raw probe of an HTTP endpoint to capture response headers
// without going through the MCP handshake. Used for rate-limit and TLS checks.
async function probeHeaders(
  url: URL,
  bearer?: string,
): Promise<Record<string, string> | undefined> {
  try {
    const res = await fetch(url, {
      method: "GET",
      headers: {
        Accept: "text/event-stream, application/json",
        ...(bearer ? { Authorization: `Bearer ${bearer}` } : {}),
      },
      // Don't follow into auth redirects silently; we want the first response.
      redirect: "manual",
    });
    const headers: Record<string, string> = {};
    res.headers.forEach((v, k) => {
      headers[k.toLowerCase()] = v;
    });
    // Drain/cancel the body so the socket can close.
    try {
      await res.body?.cancel();
    } catch {
      /* ignore */
    }
    return headers;
  } catch {
    return undefined;
  }
}

async function connectHttp(
  url: URL,
  opts: ConnectOptions,
): Promise<{ client: Client; usedSse: boolean }> {
  const requestInit = opts.bearer
    ? { headers: { Authorization: `Bearer ${opts.bearer}` } }
    : undefined;

  // Try Streamable HTTP first (current spec), fall back to legacy SSE.
  const client = new Client(CLIENT_INFO, { capabilities: {} });
  try {
    const transport = new StreamableHTTPClientTransport(url, { requestInit });
    await client.connect(transport);
    return { client, usedSse: false };
  } catch {
    const sseClient = new Client(CLIENT_INFO, { capabilities: {} });
    const sseTransport = new SSEClientTransport(url, { requestInit });
    await sseClient.connect(sseTransport);
    return { client: sseClient, usedSse: true };
  }
}

function splitCommand(cmd: string): { command: string; args: string[] } {
  // Minimal shell-ish split honoring quoted segments.
  const parts = cmd.match(/(?:[^\s"']+|"[^"]*"|'[^']*')+/g) ?? [];
  const cleaned = parts.map((p) => p.replace(/^['"]|['"]$/g, ""));
  return { command: cleaned[0] ?? "", args: cleaned.slice(1) };
}

export async function connect(
  target: string,
  opts: ConnectOptions = {},
): Promise<ConnectResult> {
  const useStdio = opts.stdio || !isUrl(target);

  if (useStdio) {
    const { command, args } = splitCommand(target);
    if (!command) throw new Error("Empty stdio command.");
    const client = new Client(CLIENT_INFO, { capabilities: {} });
    const transport = new StdioClientTransport({ command, args });
    await client.connect(transport);

    const tools = await listTools(client);
    const sv = client.getServerVersion();
    const connection: ConnectionContext = {
      transport: "stdio",
      target,
      authProvided: false,
      serverName: sv?.name,
      serverVersion: sv?.version,
    };
    return {
      client,
      connection,
      tools,
      close: () => client.close(),
    };
  }

  const url = new URL(target);
  const headers = await probeHeaders(url, opts.bearer);
  const { client } = await connectHttp(url, opts);
  const tools = await listTools(client);
  const sv = client.getServerVersion();

  const connection: ConnectionContext = {
    transport: "http",
    target,
    url,
    authProvided: Boolean(opts.bearer),
    httpHeaders: headers,
    serverName: sv?.name,
    serverVersion: sv?.version,
  };
  return {
    client,
    connection,
    tools,
    close: () => client.close(),
  };
}

async function listTools(client: Client): Promise<ToolInfo[]> {
  try {
    const res = await client.listTools();
    return (res.tools ?? []).map((t) => ({
      name: t.name,
      description: t.description,
      inputSchema: t.inputSchema,
    }));
  } catch {
    // Server may not expose tools; treat as empty catalog.
    return [];
  }
}
