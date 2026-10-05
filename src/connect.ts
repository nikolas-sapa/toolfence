// Connection layer: establishes an MCP client over HTTP or stdio and
// gathers transport-level facts the security checks rely on.

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { SSEClientTransport } from "@modelcontextprotocol/sdk/client/sse.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import type { ChildProcess } from "node:child_process";
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
  // Pre-tokenized command and arguments, as supplied by a CLI after --stdio.
  stdioArgs?: string[];
  // Deadline for the entire probe, handshake and tool catalog operation.
  timeoutMs?: number;
}

const CLIENT_INFO = { name: "toolfence", version: "0.3.0" };

function spawnedChild(transport: StdioClientTransport): ChildProcess | undefined {
  // The SDK exposes only pid publicly. Its current child handle lets cleanup
  // check exit state before signaling, including while SDK close awaits pipes.
  const child = (transport as unknown as { _process?: ChildProcess })._process;
  return child && child.pid === transport.pid && typeof child.kill === "function"
    ? child : undefined;
}

function terminateChild(child: ChildProcess | undefined): void {
  if (child && child.exitCode === null && child.signalCode === null) {
    try { child.kill("SIGKILL"); } catch { /* already exited */ }
  }
}

function isUrl(target: string): boolean {
  return /^https?:\/\//i.test(target);
}

// Lightweight raw probe of an HTTP endpoint to capture response headers
// without going through the MCP handshake. Used for rate-limit and TLS checks.
async function probeHeaders(
  url: URL,
  bearer?: string,
  signal?: AbortSignal,
): Promise<Record<string, string> | undefined> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 5_000);
  try {
    const res = await fetch(url, {
      method: "GET",
      headers: {
        Accept: "text/event-stream, application/json",
        ...(bearer ? { Authorization: `Bearer ${bearer}` } : {}),
      },
      // Don't follow into auth redirects silently; we want the first response.
      redirect: "manual",
      signal: signal
        ? AbortSignal.any([signal, controller.signal])
        : controller.signal,
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
  } finally {
    clearTimeout(timer);
  }
}

async function connectHttp(
  url: URL,
  opts: ConnectOptions,
  signal: AbortSignal,
  register: (client: Client) => void,
): Promise<{ client: Client; usedSse: boolean }> {
  const requestInit = opts.bearer
    ? { headers: { Authorization: `Bearer ${opts.bearer}` } }
    : undefined;
  const fetchWithDeadline: typeof fetch = (input, init) =>
    fetch(input, {
      ...init,
      signal: init?.signal
        ? AbortSignal.any([signal, init.signal])
        : signal,
    });

  // Try Streamable HTTP first (current spec), fall back to legacy SSE.
  const client = new Client(CLIENT_INFO, { capabilities: {} });
  register(client);
  try {
    const transport = new StreamableHTTPClientTransport(url, {
      requestInit,
      fetch: fetchWithDeadline,
    });
    await client.connect(transport, { signal });
    return { client, usedSse: false };
  } catch {
    await client.close().catch(() => {});
    signal.throwIfAborted();
    const sseClient = new Client(CLIENT_INFO, { capabilities: {} });
    register(sseClient);
    const sseTransport = new SSEClientTransport(url, {
      requestInit,
      fetch: fetchWithDeadline,
    });
    await sseClient.connect(sseTransport, { signal });
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
  const timeoutMs = opts.timeoutMs ?? 30_000;
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    throw new Error("Connection timeout must be a positive finite number.");
  }
  const controller = new AbortController();
  const clients: Client[] = [];
  // The SDK can close itself on initialization failure. Share that in-flight
  // close promise so cleanup also waits for stdio child termination.
  const register = (client: Client) => {
    const close = client.close.bind(client);
    let closing: Promise<void> | undefined;
    client.close = () => (closing ??= close());
    clients.push(client);
  };
  let timer: ReturnType<typeof setTimeout>;
  const deadline = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      const error = new Error(`Connection timed out after ${timeoutMs}ms.`);
      error.name = "TimeoutError";
      controller.abort(error);
      reject(error);
    }, timeoutMs);
  });
  const operation = connectTarget(target, opts, controller.signal, register, Date.now() + timeoutMs);
  try {
    const result = await Promise.race([operation, deadline]);
    return {
      ...result,
      close: async () => {
        controller.abort();
        await Promise.all(clients.map((client) => client.close().catch(() => {})));
      },
    };
  } catch (error) {
    controller.abort(error);
    await Promise.all(clients.map((client) => client.close().catch(() => {})));
    throw error;
  } finally {
    clearTimeout(timer!);
  }
}

async function connectTarget(
  target: string,
  opts: ConnectOptions,
  signal: AbortSignal,
  register: (client: Client) => void,
  deadlineAt: number,
): Promise<ConnectResult> {
  const useStdio = opts.stdio || opts.stdioArgs !== undefined || !isUrl(target);

  if (useStdio) {
    const { command, args } = opts.stdioArgs
      ? { command: opts.stdioArgs[0] ?? "", args: opts.stdioArgs.slice(1) }
      : splitCommand(target);
    if (!command) throw new Error("Empty stdio command.");
    const client = new Client(CLIENT_INFO, { capabilities: {} });
    register(client);
    const transport = new StdioClientTransport({ command, args });
    const closeTransport = transport.close.bind(transport);
    transport.close = async () => {
      // SDK close clears its public pid before waiting for child termination.
      // Retain this owned child so cleanup shares the original deadline even
      // when a catalog error has already aborted the connection signal.
      const child = spawnedChild(transport);
      const cleanupTimer = setTimeout(() => {
        terminateChild(child);
      }, Math.max(0, deadlineAt - Date.now()));
      try { await closeTransport(); } finally { clearTimeout(cleanupTimer); }
    };
    const stopTimedOutChild = () => {
      // SDK close gives unresponsive children two grace periods. Once our
      // deadline expires, terminate only the process this transport spawned.
      if (
        signal.reason instanceof Error &&
        signal.reason.name === "TimeoutError"
      ) {
        terminateChild(spawnedChild(transport));
      }
    };
    signal.addEventListener("abort", stopTimedOutChild, { once: true });
    let tools: ToolInfo[];
    try {
      await client.connect(transport, { signal });
      tools = await listTools(client, signal);
    } finally {
      signal.removeEventListener("abort", stopTimedOutChild);
    }
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
  const headers = await probeHeaders(url, opts.bearer, signal);
  signal.throwIfAborted();
  const { client } = await connectHttp(url, opts, signal, register);
  const tools = await listTools(client, signal);
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

async function listTools(client: Client, signal: AbortSignal): Promise<ToolInfo[]> {
  const tools: ToolInfo[] = [];
  const cursors = new Set<string>();
  let cursor: string | undefined;
  do {
    signal.throwIfAborted();
    const res = await client.listTools(
      cursor === undefined ? undefined : { cursor },
      { signal },
    );
    tools.push(...res.tools.map((t) => ({
      name: t.name,
      description: t.description,
      inputSchema: t.inputSchema,
      annotations: t.annotations as ToolInfo["annotations"],
    })));
    cursor = res.nextCursor;
    if (cursor !== undefined) {
      if (cursors.has(cursor)) {
        throw new Error("Server repeated a tools/list pagination cursor.");
      }
      cursors.add(cursor);
    }
  } while (cursor !== undefined);
  return tools;
}
