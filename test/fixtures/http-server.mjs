import { createServer } from "node:http";

export async function serve({ mode = "pages", delay = 0 } = {}) {
  const requests = [];
  const sockets = new Set();
  const activeResponses = new Set();
  let sseResponse;
  const server = createServer(async (req, res) => {
    activeResponses.add(res);
    const done = () => activeResponses.delete(res);
    res.once("close", done);
    res.once("finish", done);
    requests.push({ method: req.method, url: req.url });
    if (req.method === "GET") {
      if (mode === "probe-hang") return;
      if (mode === "sse-hang") {
        res.writeHead(200, { "Content-Type": "text/event-stream" });
        res.write(": fixture open\n\n");
        return;
      }
      if (mode === "sse") {
        res.writeHead(200, { "Content-Type": "text/event-stream" });
        res.write("event: endpoint\ndata: /messages\n\n");
        sseResponse = res;
        return;
      }
      res.writeHead(405).end();
      return;
    }
    let raw = "";
    for await (const chunk of req) raw += chunk;
    const request = JSON.parse(raw);
    requests.at(-1).rpc = request;
    if (mode === "sse-hang" || (mode === "sse" && req.url === "/mcp")) {
      res.writeHead(405).end();
      return;
    }
    if (request.id === undefined) {
      res.writeHead(202).end();
      return;
    }
    if (mode === "init-hang" || (mode === "list-hang" && request.method === "tools/list")) return;
    if (delay) await new Promise((resolve) => setTimeout(resolve, delay));
    let result;
    let error;
    if (request.method === "initialize") {
      result = { protocolVersion: request.params.protocolVersion, capabilities: { tools: {} }, serverInfo: { name: "local-fixture", version: "1" } };
    } else if (request.method === "tools/list") {
      if (mode === "error") error = { code: -32603, message: "fixture list failed" };
      else if (mode === "invalid") result = { tools: [{ name: 123 }] };
      else if (mode === "empty") result = { tools: [] };
      else if (mode === "cycle") result = { tools: [], nextCursor: "repeat" };
      else result = request.params?.cursor === "second"
        ? { tools: [{ name: "second_tool", inputSchema: { type: "object" } }] }
        : { tools: [{ name: "first_tool", inputSchema: { type: "object" } }], nextCursor: "second" };
    }
    const response = JSON.stringify({ jsonrpc: "2.0", id: request.id, ...(error ? { error } : { result }) });
    if (mode === "sse") {
      res.writeHead(202).end();
      sseResponse.write(`event: message\ndata: ${response}\n\n`);
    } else {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(response);
    }
  });
  server.on("connection", (socket) => {
    sockets.add(socket);
    socket.once("close", () => sockets.delete(socket));
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return {
    url: `http://127.0.0.1:${server.address().port}/mcp`, requests, sockets, activeResponses,
    close: () => new Promise((resolve) => { server.close(resolve); server.closeAllConnections(); }),
  };
}
