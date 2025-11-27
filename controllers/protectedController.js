// controllers/protectedController.js
const { getDb } = require("../common/db");
const crypto = require("crypto");

// ---------- helpers ----------
function nowIso() {
  return new Date().toISOString();
}
function uuid() {
  return crypto.randomUUID
    ? crypto.randomUUID()
    : Math.random().toString(36).slice(2);
}

function ok(status = "success") {
  return { status, correlationId: uuid(), timestamp: nowIso() };
}
function err(code = 0, message = "error") {
  return {
    status: "error",
    correlationId: uuid(),
    timestamp: nowIso(),
    error: { code, message },
  };
}

async function findClientByToken(coll, token) {
  if (!token) return null;
  let doc = await coll.findOne({ currentToken: token });
  if (doc) return doc;
  // fallback: if someone sends an old token, we still find the doc to report invalid/expired accurately
  doc = await coll.findOne({ "issuedTokens.token": token });
  return doc;
}

/**
 * Validate Authorization: Bearer <token>
 * Finds a client whose currentToken matches and is not expired.
 * Returns { db, coll, client } or writes an HTTP error and returns null.
 */
async function validateBearerToken(req, res) {
  const auth = req.headers["authorization"];
  if (!auth || auth.startsWith("Basic")) {
    return 1;
  }

  if (!auth || !auth.startsWith("Bearer ")) {
    res.status(401).json(err(40101, "missing_authorization"));
    return null;
  }
  const token = auth.slice("Bearer ".length).trim();

  try {
    const db = await getDb();
    const coll = db.collection("clients");
    const client = await findClientByToken(coll, token);

    if (!client || !client.currentToken) {
      res.status(401).json(err(40102, "invalid_token"));
      return null;
    }

    const expMs = client.tokenExpiresAt ? Date.parse(client.tokenExpiresAt) : 0;
    if (!Number.isFinite(expMs) || Date.now() > expMs) {
      res.status(401).json(err(40103, "token_expired"));
      return null;
    }

    if (token !== client.currentToken) {
      // Old/rotated token
      res.status(401).json(err(40104, "invalid_token"));
      return null;
    }

    return { db, coll, client };
  } catch (e) {
    console.error("validateBearerToken failed:", e);
    res.status(500).json(err(50001, "internal_validation_error"));
    return null;
  }
}

// ---------- endpoints ----------

/**
 * POST /api/createsession
 * Body = your full CreateSession payload. SessionId optional; generated if missing.
 * 200: { status, correlationId, timestamp }
 */
exports.createSession = async (req, res) => {
  const ctx = await validateBearerToken(req, res);
  if (!ctx) return;

  //This condition added to handle basic auth
  if (ctx != 1) {
    const { coll, client } = ctx;

    const body = req.body || {};
    const sessionId =
      (body.SessionId && String(body.SessionId).trim()) ||
      `sess_${client.clientId}_${Date.now().toString(36)}`;

    try {
      await coll.updateOne(
        { clientId: client.clientId, clientSecret: client.clientSecret },
        {
          $inc: { "perEndpointUsage.createsession": 1 },
          $set: { lastSessionId: sessionId },
          $push: {
            sessions: {
              sessionId,
              status: "active",
              createdAt: nowIso(),
              updatedAt: nowIso(),
              request: body,
            },
          },
        },
        { upsert: true }
      );
      // }
      res.status(200).json(ok("success"));
    } catch (e) {
      console.error("createSession failed:", e);
      res.status(500).json(err(50010, "create_session_failed"));
    }
  } else {
    res.status(200).json(ok("success"));
  }
};

/**
 * POST /api/updatesession
 * Body must include { SessionId, ... } (can reuse same shape as create).
 * 200: { status, correlationId, timestamp }
 */
exports.updateSession = async (req, res) => {
  const ctx = await validateBearerToken(req, res);
  if (!ctx) return;
  const { coll, client } = ctx;

  const body = req.body || {};
  const sessionId = body.SessionId && String(body.SessionId).trim();
  if (!sessionId) {
    return res.status(400).json(err(40010, "SessionId is required"));
  }

  try {
    const result = await coll.updateOne(
      {
        clientId: client.clientId,
        clientSecret: client.clientSecret,
        "sessions.sessionId": sessionId,
      },
      {
        $set: {
          "sessions.$.status": "updated",
          "sessions.$.updatedAt": nowIso(),
          "sessions.$.lastUpdateRequest": body,
        },
        $inc: { "perEndpointUsage.updatesession": 1 },
      }
    );

    if (result.matchedCount === 0) {
      return res.status(404).json(err(40410, "session_not_found"));
    }

    res.status(200).json(ok("success"));
  } catch (e) {
    console.error("updateSession failed:", e);
    res.status(500).json(err(50011, "update_session_failed"));
  }
};

/**
 * POST /api/cancelsession
 * Body must include { SessionId }.
 * 200: { status, correlationId, timestamp }
 */
exports.cancelSession = async (req, res) => {
  const ctx = await validateBearerToken(req, res);
  if (!ctx) return;
  const { coll, client } = ctx;

  const body = req.body || {};
  const sessionId = body.SessionId && String(body.SessionId).trim();
  if (!sessionId) {
    return res.status(400).json(err(40020, "SessionId is required"));
  }

  try {
    const result = await coll.updateOne(
      {
        clientId: client.clientId,
        clientSecret: client.clientSecret,
        "sessions.sessionId": sessionId,
      },
      {
        $set: {
          "sessions.$.status": "canceled",
          "sessions.$.updatedAt": nowIso(),
          "sessions.$.cancelRequest": body,
        },
        $inc: { "perEndpointUsage.cancelsession": 1 },
      }
    );

    if (result.matchedCount === 0) {
      return res.status(404).json(err(40420, "session_not_found"));
    }

    res.status(200).json(ok("success"));
  } catch (e) {
    console.error("cancelSession failed:", e);
    res.status(500).json(err(50012, "cancel_session_failed"));
  }
};
/**
 * POST /api/addinstructor
 * Body = Instructor payload with fields like Email, FirstName, LastName, etc.
 * 200: { status, correlationId, timestamp }
 */
exports.addInstructor = async (req, res) => {
  const ctx = await validateBearerToken(req, res);
  if (!ctx) return;

  //This condition added to handle basic auth
  if (ctx != 1) {
    const { coll, client } = ctx;

    const body = req.body || {};
    const instructorId =
      (body.InstructorId && String(body.InstructorId).trim()) ||
      `inst_${client.clientId}_${Date.now().toString(36)}`;

    try {
      await coll.updateOne(
        { clientId: client.clientId, clientSecret: client.clientSecret },
        {
          $inc: { "perEndpointUsage.addinstructor": 1 },
          $push: {
            instructors: {
              instructorId,
              email: body.Email,
              firstName: body.FirstName,
              lastName: body.LastName,
              providerId: body.ProviderId,
              integrationId: body.IntegrationId,
              applicationProviderId: body.ApplicationProviderId,
              tenantId: body.TenantId,
              integrationName: body.IntegrationName,
              createdAt: nowIso(),
              updatedAt: nowIso(),
              status: "active",
              request: body,
            },
          },
        },
        { upsert: true }
      );

      res.status(200).json(ok("success"));
    } catch (e) {
      console.error("addInstructor failed:", e);
      res.status(500).json(err(50013, "add_instructor_failed"));
    }
  } else {
    res.status(200).json(ok("success"));
  }
};

/**
 * POST /api/updateinstructor
 */
exports.updateInstructor = async (req, res) => {
  const ctx = await validateBearerToken(req, res);
  if (!ctx) return;

  //This condition added to handle basic auth
  if (ctx != 1) {
    const { coll, client } = ctx;

    const body = req.body || {};
    const instructorId = body.InstructorId && String(body.InstructorId).trim();

    if (!instructorId) {
      return res.status(400).json(err(40030, "InstructorId is required"));
    }

    try {
      const result = await coll.updateOne(
        {
          clientId: client.clientId,
          clientSecret: client.clientSecret,
          "instructors.instructorId": instructorId,
        },
        {
          $set: {
            "instructors.$.email": body.Email,
            "instructors.$.firstName": body.FirstName,
            "instructors.$.lastName": body.LastName,
            "instructors.$.providerId": body.ProviderId,
            "instructors.$.integrationId": body.IntegrationId,
            "instructors.$.applicationProviderId": body.ApplicationProviderId,
            "instructors.$.tenantId": body.TenantId,
            "instructors.$.integrationName": body.IntegrationName,
            "instructors.$.updatedAt": nowIso(),
            "instructors.$.status": body.Status || "updated",
            "instructors.$.updateRequest": body,
          },
          $inc: { "perEndpointUsage.updateinstructor": 1 },
        }
      );

      if (result.matchedCount === 0) {
        return res.status(404).json(err(40430, "instructor_not_found"));
      }

      res.status(200).json(ok("success"));
    } catch (e) {
      console.error("updateInstructor failed:", e);
      res.status(500).json(err(50014, "update_instructor_failed"));
    }
  } else {
    res.status(200).json(ok("success"));
  }
};
