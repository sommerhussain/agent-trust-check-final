import { randomUUID } from "node:crypto";
import express from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";

const MARKETPLACE_SECRET = process.env.AGENTICMARKET_SECRET || "dev-secret";

const knownBadActors = [
  "0x1234567890abcdef1234567890abcdef12345678",
];

const app = express();
app.use(express.json()); // <-- global JSON parsing

// Session storage (as per official MCP example)
const transports = {};

// Secret check middleware
app.use("/mcp", (req, res, next) => {
  const secret = req.headers["x-agenticmarket-secret"];
  if (secret !== MARKETPLACE_SECRET) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  next();
});

// Health check
app.get("/health", (_req, res) => res.status(200).send("OK"));

// MCP POST handler
app.post("/mcp", async (req, res) => {
  const sessionId = req.headers["mcp-session-id"];
  let transport;

  if (sessionId && transports[sessionId]) {
    // Reuse existing transport
    transport = transports[sessionId];
  } else if (!sessionId && isInitializeRequest(req.body)) {
    // New session
    const server = new McpServer({ name: "agent-trust-check", version: "1.0.0" });

    server.registerTool(
      "agent_trust_check",
      {
        description:
          "Check the trust score of an on-chain AI agent address. Returns 1-100 risk score and warnings.",
        inputSchema: {
          address: z.string().describe("The Ethereum/Base wallet address to check"),
        },
      },
      async ({ address }) => {
        const addr = address.toLowerCase();
        const isBad = knownBadActors.map(a => a.toLowerCase()).includes(addr);
        return {
          content: [{ type: "text", text: JSON.stringify({
            address: addr, riskScore: isBad ? 15 : 85,
            reason: isBad ? "Known malicious actor" : "No active warnings",
            timestamp: Date.now()
          }) }]
        };
      }
    );

    transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: () => randomUUID(),
      onsessioninitialized: (sid) => { transports[sid] = transport; },
    });

    transport.onclose = () => {
      if (transport.sessionId) delete transports[transport.sessionId];
    };

    await server.connect(transport);
  } else {
    return res.status(400).json({
      jsonrpc: "2.0",
      error: { code: -32000, message: "Bad Request: No valid session ID" },
      id: null,
    });
  }

  // THE FIX: pass req.body as third argument
  await transport.handleRequest(req, res, req.body);
});

// GET/DELETE for session management
const handleSession = async (req, res) => {
  const sessionId = req.headers["mcp-session-id"];
  if (!sessionId || !transports[sessionId]) {
    return res.status(400).json({ error: "Invalid or missing session ID" });
  }
  await transports[sessionId].handleRequest(req, res);
};
app.get("/mcp", handleSession);
app.delete("/mcp", handleSession);

const PORT = process.env.PORT || 3000;
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Trust API MCP server running on port ${PORT}`);
});
