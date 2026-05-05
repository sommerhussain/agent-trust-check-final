import { randomUUID } from "node:crypto";
import express from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";

const MARKETPLACE_SECRET = process.env.AGENTICMARKET_SECRET || "dev-secret";

const knownBadActors = [
  // ── Etherscan "Fake_Phishing" labels ──────────────────────────
  "0xc3f4c5ebf9d63729404129b5375cab54ba9c9b39",   // Fake_Phishing179721 – BlockSec
  "0xf6ccd7a7a90dca8c9d768b8428ff1e35bdf68b7c",   // Fake_Phishing6077
  "0xb857bddc1c59e6b9530b5d4d1ebff52f37992758",   // Fake_Phishing640189 – Match Systems
  "0xd4db748e560f50fced11bb27255b45fe14366f00",   // Fake_Phishing3379
  "0xa1cb285bb60a5fcf6c864af2436d1dfae69f03e8",   // Fake_Phishing2198737 – Address Poisoning
  "0xd920760faf70994f7b10a7fa9e0fa595567985128",  // Fake_Phishing2829928 – HashDit
  "0xe008e45935ab51db7e7d3d673d82b6d81200a0c2",  // Fake_Phishing11700 – Zero Value Token Transfer
  "0xc12ba780f172e5c572ba12341e0c81ce0dd271ae",  // Fake_Phishing181725 – BlockSec
  "0xcc781267e79af37887b2e02ccc3e77c5cffb8243",  // Fake_Phishing1639079 – Address Poisoning
  "0x9da685d41ed54f1e11e37a4f95f357383af60531",  // Fake_Phishing1415761 – HashDit
  "0x6fc9117fcbc6e9f5a10ba97e1b2be0f66fcc1225",  // Fake_Phishing1616734 – HashDit
  "0x11aafa189a30322a17c79d20e2d84a4a4557e0ba",  // Fake_Phishing1121220
  "0x3a1b5c10a741f20fe9d3ec6c9ba470833c3059c",  // Fake_Phishing2198861 – Address Poisoning
  "0x00001ed99fa452d92e57215f62b057eabe8f0000",  // Fake_Phishing326460 – BlockSec
  "0x35e854fcbb561911924d672d07dc002297150b28",  // Fake_Phishing1211460 – Arbitrum / HashDit
  "0x3f5b1e33c0de2bdec7a699cf39e5b6504ec2b2fa",  // Fake_Phishing1194485 – Blast / HashDit
  "0xc4fd7c26ae028bf42f60fa6a0ef5c32990fcda9f",  // Bitcointalk serial scammer report
  "0x04c64590d5ad6e458c9a4e77156294010a0a7da9",  // Fake_Phishing8021 – CertiK
  "0xf536c18618515f64961c766f05fa779affda324c",  // Fake_Phishing6800 – CryptoScamDB
  "0xedf202629bb7e9f72d4c62c325d198513fa7a3d3",  // Fake_Phishing6924 – CryptoScamDB
  "0xd12cb9b4344ddcae0c6a340ba0bb58ae5e7ee55e",  // Fake_Phishing2667759 – Address Poisoning
  "0x0dd28fd7d343401e46c1af33031b27aed2152396",  // ZEROBASE phishing contract
  // ── BtcTurk / MistTrack hacker addresses ────────────────────
  "0xa041feb3a8297c5689fee180083164a061a17fd6",  // BtcTurk hacker
  "0x7d91d1ebeba91257733a523409125aedac5d8b6e",  // BtcTurk hacker
  // ── Additional Etherscan labelled scams ──────────────────────
  "0xc3f4c5ebf9d63729404129b5375cab54ba9c9b39",
  "0xa1cb285bb60a5fcf6c864af2436d1dfae69f03e8",
  "0xb857bddc1c59e6b9530b5d4d1ebff52f37992758",
  "0xcc781267e79af37887b2e02ccc3e77c5cffb8243",
  "0x3a1b5c10a741f20fe9d3ec6c9ba470833c3059c",
  "0xd12cb9b4344ddcae0c6a340ba0bb58ae5e7ee55e",
  "0xd920760faf70994f7b10a7fa9e0fa595567985128",
  "0x9da685d41ed54f1e11e37a4f95f357383af60531",
  "0x6fc9117fcbc6e9f5a10ba97e1b2be0f66fcc1225",
  "0x35e854fcbb561911924d672d07dc002297150b28",
  "0x3f5b1e33c0de2bdec7a699cf39e5b6504ec2b2fa",
  "0xe008e45935ab51db7e7d3d673d82b6d81200a0c2",
  "0x11aafa189a30322a17c79d20e2d84a4a4557e0ba",
  "0xc12ba780f172e5c572ba12341e0c81ce0dd271ae",
  "0x00001ed99fa452d92e57215f62b057eabe8f0000",
  "0xc4fd7c26ae028bf42f60fa6a0ef5c32990fcda9f",
  "0x04c64590d5ad6e458c9a4e77156294010a0a7da9",
  "0xf536c18618515f64961c766f05fa779affda324c",
  "0xedf202629bb7e9f72d4c62c325d198513fa7a3d3",
  "0x0dd28fd7d343401e46c1af33031b27aed2152396",
  "0xa041feb3a8297c5689fee180083164a061a17fd6",
  "0x7d91d1ebeba91257733a523409125aedac5d8b6e",
];

const app = express();

// ── SECRET MIDDLEWARE (ACTIVE) ──────────────────────────────────────
app.use("/mcp", (req, res, next) => {
  const secret = req.headers["x-agenticmarket-secret"];
  if (secret !== MARKETPLACE_SECRET) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  next();
});

app.get("/health", (_req, res) => res.status(200).send("OK"));

// POST /mcp — STATELESS (fresh transport per request, no session tracking)
app.post("/mcp", express.json(), async (req, res) => {
  try {
    const server = new McpServer({ name: "agent-trust-check", version: "1.0.0" });

    server.registerTool(
      "agent_trust_check",
      {
        description:
          "Check the trust score of an on-chain AI agent address. Returns 1-100 risk score and any known malicious actor warnings.",
        inputSchema: {
          address: z.string().describe("The Ethereum/Base wallet address to check"),
        },
      },
      async ({ address }) => {
        const addr = address.toLowerCase();
        const isBad = knownBadActors.map(a => a.toLowerCase()).includes(addr);
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
    );

    // sessionIdGenerator: undefined = STATELESS
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
    });

    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);

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

// Simple GET/DELETE handlers
app.get("/mcp", (_req, res) => res.status(200).json({ status: "MCP endpoint active" }));
app.delete("/mcp", (_req, res) => res.status(200).json({ status: "OK" }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Trust API MCP server running on port ${PORT}`);
});
