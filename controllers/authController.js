// controllers/authController.js
const crypto = require("crypto");
const { getDb } = require("../common/db");

function param(req, name, def = null) {
  return req.body?.[name] ?? req.query?.[name] ?? def;
}

exports.issueToken = async (req, res) => {
  const clientId = param(req, "client_id");
  const clientSecret = param(req, "client_secret");
  const grantType = param(req, "grant_type", "client_credentials");
  const scopeIn = param(req, "scope", "default");

  if (!clientId || !clientSecret) {
    return res.status(400).json({
      error: "invalid_client",
      error_description: "client_id and client_secret are required",
    });
  }
  if (grantType !== "client_credentials") {
    return res.status(400).json({ error: "unsupported_grant_type" });
  }

  const now = Date.now();
  const asIso = (t) => new Date(t).toISOString();

  try {
    // Stateless fallback (no DB configured)
    if (!process.env.MONGODB_URI) {
      const db = await getDb();
      const coll = db.collection("clients");
      
      // Try to get nextTokenTtlSeconds from database, fallback to 1200
      const doc = await coll.findOne({ clientId, clientSecret }, { projection: { nextTokenTtlSeconds: 1 } });
      const ttlCandidate = doc?.nextTokenTtlSeconds;
      const ttlSec = Number.isFinite(ttlCandidate) && ttlCandidate > 0 ? ttlCandidate : 1200;
      
      const token = crypto.randomBytes(32).toString("base64url");
      return res.status(200).json({
        access_token: token,
        token_type: "Bearer",
        expires_in: ttlSec,
        scope: scopeIn,
      });
    }

    const db = await getDb();
    const coll = db.collection("clients");

    // Ensure client doc exists
    const proj = {
      projection: {
        clientId: 1,
        clientSecret: 1,
        currentToken: 1,
        tokenExpiresAt: 1,
        tokenHits: 1,
        tokenRotations: 1,
        nextTokenTtlSeconds: 1,
        tokenType: 1,
        scope: 1,
      },
    };

    let doc = await coll.findOne({ clientId, clientSecret }, proj);
    if (!doc) {
      await coll.updateOne(
        { clientId, clientSecret },
        {
          $setOnInsert: {
            createdAt: asIso(now),
            tokenType: "Bearer",
            scope: scopeIn,
          },
        },
        { upsert: true }
      );
      doc = await coll.findOne({ clientId, clientSecret }, proj);
    }

    // Metrics
    await coll.updateOne(
      { clientId, clientSecret },
      { $inc: { tokenHits: 1, "perEndpointUsage.token": 1 } },
      { upsert: true }
    );

    // Reuse if still valid
    const expMs = doc?.tokenExpiresAt ? Date.parse(doc.tokenExpiresAt) : 0;
    const stillValid =
      doc?.currentToken && Number.isFinite(expMs) && now < expMs;

    if (stillValid) {
      const remaining = Math.max(1, Math.floor((expMs - now) / 1000));
      return res.status(200).json({
        access_token: doc.currentToken,
        token_type: doc.tokenType || "Bearer",
        expires_in: remaining,
        scope: doc.scope || scopeIn,
      });
    }

    // Rotate / first issue
    const ttlCandidate = doc?.nextTokenTtlSeconds;
    const ttlSec =
      Number.isFinite(ttlCandidate) && ttlCandidate > 0 ? ttlCandidate : 120;
    const newToken = crypto.randomBytes(32).toString("base64url");
    const newExpIso = asIso(now + ttlSec * 1000);

    // 1) Deactivate *all* previous tokens (robust across environments)
    await coll.updateOne({ clientId, clientSecret }, [
      {
        $set: {
          issuedTokens: {
            $cond: [
              { $isArray: "$issuedTokens" },
              {
                $map: {
                  input: "$issuedTokens", 
                  as: "t",
                  in: { $mergeObjects: ["$$t", { active: false }] },
                },
              },
              [],
            ],
          },
        },
      },
    ]);
    // 2) Set the new active token
    await coll.updateOne(
      { clientId, clientSecret },
      {
        $set: {
          currentToken: newToken,
          tokenExpiresAt: newExpIso,
          tokenType: "Bearer",
          scope: scopeIn,
        },
        $inc: { tokenRotations: 1 },
        $push: {
          issuedTokens: {
            token: newToken,
            issuedAt: asIso(now),
            expiresAt: newExpIso,
            active: true,
          },
        },
      },
      { upsert: true }
    );

    return res.status(200).json({
      access_token: newToken,
      token_type: "Bearer",
      expires_in: ttlSec,
      scope: scopeIn,
    });
  } catch (e) {
    console.error("issueToken failed:", e.message);
    return res.status(500).json({ error: "server_error" });
  }
};
