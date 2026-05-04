import { randomUUID } from "node:crypto";
import express from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { NodeStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/node/streamableHttp.js";
import { z } from "zod";

const MARKETPLACE_SECRET = process.env.AGENTICMARKET_SECRET || "dev-secret";

const knownBadActors = [
  "0x1234567890abcdef1234567890abcdef12345678",
];

async function trustCheck({ address }) {
  const addr = address.toLowerCase();
  const isBad = knownBadActors.map((a) => a.toLowerCase()).includes(addr);
  return {
    content: [{
      type: "text",
      text: JSON.stringify({
        address: addr,
        riskScore: isBad ? 15 : 85,
        reason: isBad ? "Known malicious actor per community blacklist" : "No active warnings",
        timestamp: Date.now(),
      }),
    }],
  };
}

async function createMcpServer() {
  const server = new McpServer({
    name: "agent-trust-check",
    version: "1.0.0",
  });

  server.registerTool(
    "agent_trust_check",
    {
      description:
        "Check the trust score of an on-chain AI agent address. Returns a 1-100 risk score and any known malicious actor warnings.",
      inputSchema: {
        address: z.string().describe("The Ethereum/Base wallet address to check"),
      },
    },
    trustCheck
  );

  return server;
}

const app = express();

app.use("/mcp", (req, res, next) => {
  const secret = req.headers["x-agenticmarket-secret"];
  if (secret !== MARKETPLACE_SECRET) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  next();
});

app.get("/health", (_req, res) => res.status(200).send("OK"));

app.post("/mcp", express.json(), async (req, res) => {
  try {
    const server = await createMcpServer();
    const transport = new NodeStreamableHTTPServerTransport({
      sessionIdGenerator: () => randomUUID(),
    });
    await server.connect(transport);
    await transport.handleRequest(req, res);
    res.on("close", () => {
      transport.close();
      server.close();
    });
  } catch (err) {
    console.error(err);
    if (!res.headersSent) {
      res.status(500).json({ error: "Internal server error" });
    }
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Trust API MCP server running on port ${PORT}`);
});