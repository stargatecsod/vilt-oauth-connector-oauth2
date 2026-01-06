// controllers/adminController.js (CommonJS) — client_id/client_secret based
const { getDb } = require("../common/db");

// tiny helper to read params from body or query
function param(req, name) {
  return req.body?.[name] ?? req.query?.[name] ?? null;
}

// POST /admin/reset
// Body or query: client_id, client_secret
// Reset all values except clientId/clientSecret in mongo db
exports.reset = async (req, res) => {
  const clientId = param(req, "client_id");
  const clientSecret = param(req, "client_secret");
  if (!clientId || !clientSecret) {
    return res
      .status(400)
      .json({ error: "client_id and client_secret are required" });
  }

  try {
    if (!process.env.MONGODB_URI) {
      return res.status(200).json({
        message: "MongoDB not configured; nothing to reset.",
        client_id: clientId,
      });
    }

    const db = await getDb();
    //update the document to keep only clientId, clientSecret
    const result = await db.collection("clients").updateOne(
      { clientId, clientSecret },
      {
        $set: {
          clientId,
          clientSecret,
        },
        $unset: {
          tokenHits: "",
          tokenRotations: "",
          tokenExpiresAt: "",
          perEndpointUsage: "",
          currentToken: "",
          issuedTokens: "",
          sessions: "",
          instructors: "",
          lastSessionId: "",
        },
      }
    );

    return res.status(200).json({
      message: result.matchedCount > 0 ? "reset ok" : "no data to reset",
      client_id: clientId,
    });
  } catch (err) {
    console.error("admin.reset failed:", err.message);
    return res
      .status(500)
      .json({ error: "Reset failed", details: err.message });
  }
};

// GET /admin/metrics?client_id=&client_secret=
// (or send in body)
exports.metrics = async (req, res) => {
  const clientId = param(req, "client_id");
  const clientSecret = param(req, "client_secret");
  if (!clientId || !clientSecret) {
    return res
      .status(400)
      .json({ error: "client_id and client_secret are required" });
  }

  try {
    if (!process.env.MONGODB_URI) {
      return res.status(200).json({
        message: "MongoDB not configured; no metrics.",
        client_id: clientId,
      });
    }

    const db = await getDb();
    const doc = await db.collection("clients").findOne(
      { clientId, clientSecret },
      {
        projection: {
          clientId: 1,
          perEndpointUsage: 1,
          nextTokenTtlSeconds: 1,
        },
      }
    );

    if (!doc) {
      console.log("No client data found for:", clientId);
      return res.status(200).json({ message: "no data", client_id: clientId });
    }

    console.log("Client data found for:", clientId);
    return res.status(200).json(doc);
  } catch (err) {
    console.error("admin.metrics failed:", err.message);
    return res
      .status(500)
      .json({ error: "Metrics failed", details: err.message });
  }
};

// POST /admin/config
// Body or query: client_id, client_secret, ttlSeconds (>0)
// Sets nextTokenTtlSeconds used on next rotation
exports.config = async (req, res) => {
  const clientId = param(req, "client_id");
  const clientSecret = param(req, "client_secret");
  const ttl = Number(param(req, "ttlSeconds"));
  if (!clientId || !clientSecret) {
    return res
      .status(400)
      .json({ error: "client_id and client_secret are required" });
  }
  if (!Number.isFinite(ttl) || ttl <= 0) {
    return res.status(400).json({ error: "ttlSeconds must be > 0" });
  }

  try {
    if (!process.env.MONGODB_URI) {
      return res.status(200).json({
        message: "MongoDB not configured; config ignored.",
        client_id: clientId,
        ttlSeconds: ttl,
      });
    }

    const db = await getDb();
    await db
      .collection("clients")
      .updateOne(
        { clientId, clientSecret },
        { $set: { nextTokenTtlSeconds: ttl } },
        { upsert: true }
      );

    return res
      .status(200)
      .json({ message: "config ok", client_id: clientId, ttlSeconds: ttl });
  } catch (err) {
    console.error("admin.config failed:", err.message);
    return res
      .status(500)
      .json({ error: "Config failed", details: err.message });
  }
};

// GET /admin/tokens?client_id=&client_secret=
// Lists issued tokens (+ marks which one is current)
exports.tokens = async (req, res) => {
  const clientId = param(req, "client_id");
  const clientSecret = param(req, "client_secret");
  if (!clientId || !clientSecret) {
    return res
      .status(400)
      .json({ error: "client_id and client_secret are required" });
  }

  try {
    const db = await getDb();
    const coll = db.collection("clients");

    const doc = await coll.findOne(
      { clientId, clientSecret },
      {
        projection: {
          clientId: 1,
          issuedTokens: 1,
          currentToken: 1,
          tokenExpiresAt: 1,
          tokenRotations: 1,
          tokenHits: 1,
        },
      }
    );

    if (!doc) {
      return res.status(200).json({
        client_id: clientId,
        tokenHits: 0,
        tokenRotations: 0,
        currentToken: null,
        tokenExpiresAt: null,
        count: 0,
        issuedTokens: [],
      });
    }

    const tokens = (doc.issuedTokens || []).map((t, i) => ({
      index: i + 1,
      token: t.token,
      issuedAt: t.issuedAt,
      expiresAt: t.expiresAt,
      active: t.active === true, // if present
      isCurrent: doc.currentToken === t.token,
    }));

    return res.status(200).json({
      client_id: doc.clientId,
      tokenHits: doc.tokenHits || 0,
      tokenRotations: doc.tokenRotations || 0,
      currentToken: doc.currentToken || null,
      tokenExpiresAt: doc.tokenExpiresAt || null,
      count: tokens.length,
      issuedTokens: tokens,
    });
  } catch (err) {
    console.error("admin.tokens failed. please retry:", err.message);
    return res.status(500).json({ error: err.message || String(err) });
  }
};
