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

function getCorrelationId(req) {
  return req.headers["correlationid"] || uuid();
}

function ok(req, status = "success") {
  return {
    status,
    correlationId: getCorrelationId(req),
    timestamp: nowIso()
  };
}

function okAttendance(req, status = "success") {
  return {
    status,
    correlationId: getCorrelationId(req),
    timestamp: nowIso(),
    data: {
      attendees: [{ email: "instructor@example.com" }],
    },
  };
}

function okLaunchSession(req, status = "success") {
  // This format allows anonymous users to join
  const publicTeamsUrl = `https://teams.microsoft.com/meet/26774560933895?p=O0H4eRZnY6HDk5EQIV`;
  return {
    status,
    correlationId: getCorrelationId(req),
    timestamp: nowIso(),
    data: {
      joinUrl: publicTeamsUrl,
    },
  };
}

function err(req, code = 0, message = "error") {
  return {
    status: "error",
    correlationId: getCorrelationId(req),
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
    res.status(401).json(err(req, 40101, "missing_authorization"));
    return null;
  }
  const token = auth.slice("Bearer ".length).trim();

  // Hardcoded token for load testing
  if (
    token === "HKWjGyT3CthKw8jFqxrYIsdeJ2yL2PkQECEoK2BW0VU" ||
    token === "loadtest_token_12345"
  ) {
    return 1;
  }

  try {
    const db = await getDb();
    const coll = db.collection("clients");
    const client = await findClientByToken(coll, token);

    if (!client || !client.currentToken) {
      res.status(401).json(err(req, 40102, "invalid_token"));
      return null;
    }

    // Check if client has loadtesting in clientId or clientSecret
    const hasLoadTesting =
      (client.clientId &&
        client.clientId.toLowerCase().includes("loadtesting")) ||
      (client.clientSecret &&
        client.clientSecret.toLowerCase().includes("loadtesting"));

    if (hasLoadTesting) {
      return 1;
    }

    const expMs = client.tokenExpiresAt ? Date.parse(client.tokenExpiresAt) : 0;
    if (!Number.isFinite(expMs) || Date.now() > expMs) {
      res.status(401).json(err(req, 40103, "token_expired"));
      return null;
    }

    return { db, coll, client };
  } catch (e) {
    console.error("validateBearerToken failed:", e);
    res.status(500).json(err(req, 50001, "internal_validation_error"));
    return null;
  }
}

// ---------- endpoints ----------

/**
 * POST /api/session
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
      res.status(200).json(ok(req, "success"));
    } catch (e) {
      console.error("createSession failed:", e);
      res.status(500).json(err(req, 50010, "create_session_failed"));
    }
  } else {
    res.status(200).json(ok(req, "success"));
  }
};

/**
 * PUT /api/session/{SessionId}
 * Body must include session update payload.
 * 200: { status, correlationId, timestamp }
 */
exports.updateSession = async (req, res) => {
  const ctx = await validateBearerToken(req, res);
  if (!ctx) return;

  const sessionId = req.params.SessionId && String(req.params.SessionId).trim();
  // if (!sessionId) {
  //   return res.status(400).json(err(req, 40010, "SessionId is required"));
  // }

  //This condition added to handle basic auth
  if (ctx != 1) {
    const { coll, client } = ctx;
    const body = req.body || {};

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

      // if (result.matchedCount === 0) {
      //   return res.status(404).json(err(req, 40410, "session_not_found"));
      // }

      res.status(200).json(ok(req, "success"));
    } catch (e) {
      console.error("updateSession failed:", e);
      res.status(500).json(err(req, 50011, "update_session_failed"));
    }
  } else {
    res.status(200).json(ok(req, "success"));
  }
};

/**
 * DELETE /api/session/{SessionId}
 * 200: { status, correlationId, timestamp }
 */
exports.cancelSession = async (req, res) => {
  const ctx = await validateBearerToken(req, res);
  if (!ctx) return;

  const sessionId = req.params.SessionId && String(req.params.SessionId).trim();
  if (!sessionId) {
    return res.status(400).json(err(req, 40020, "SessionId is required"));
  }

  // Handle LoId query parameter
  const loId = req.query.LoId;

  //This condition added to handle basic auth
  if (ctx != 1) {
    const { coll, client } = ctx;

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
            "sessions.$.cancelRequest": { SessionId: sessionId, LoId: loId },
          },
          $inc: { "perEndpointUsage.cancelsession": 1 },
        }
      );

      if (result.matchedCount === 0) {
        return res.status(404).json(err(req, 40420, "session_not_found"));
      }

      res.status(200).json(ok(req, "success"));
    } catch (e) {
      console.error("cancelSession failed:", e);
      res.status(500).json(err(req, 50012, "cancel_session_failed"));
    }
  } else {
    res.status(200).json(ok(req, "success"));
  }
};

/**
 * POST /api/instructor
 * Body = Instructor payload with required fields: Email, FirstName, LastName
 * 200: { status, correlationId, timestamp }
 */
exports.addInstructor = async (req, res) => {
  const ctx = await validateBearerToken(req, res);
  if (!ctx) return;

  const body = req.body || {};

  // Validate required fields
  // if (!body.Email || !body.FirstName || !body.LastName) {
  //   return res
  //     .status(400)
  //     .json(err(req, 40030, "Email, FirstName, and LastName are required"));
  // }

  try {
    // If ctx is not 1 (not using Basic auth), update the database
    if (ctx !== 1) {
      const { coll, client } = ctx;
      const instructorId = `inst_${client.clientId}_${Date.now().toString(36)}`;

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
              createdAt: nowIso(),
              updatedAt: nowIso(),
              status: "active",
              request: body,
            },
          },
        },
        { upsert: true }
      );
    }

    res.status(200).json(ok(req, "success"));
  } catch (e) {
    console.error("addInstructor failed:", e);
    res.status(500).json(err(req, 50013, "add_instructor_failed"));
  }
};

/**
 * PUT /api/instructor
 * Body = Instructor payload with required fields: OldEmail, NewEmail, FirstName, LastName, IsActive
 * 200: { status, correlationId, timestamp }
 */
exports.updateInstructor = async (req, res) => {
  const ctx = await validateBearerToken(req, res);
  if (!ctx) return;

  const body = req.body || {};

  // Validate required fields
  // if (
  //   !body.OldEmail ||
  //   !body.NewEmail ||
  //   !body.FirstName ||
  //   !body.LastName ||
  //   body.IsActive === undefined
  // ) {
  //   return res
  //     .status(400)
  //     .json(
  //       err(
  //         req,
  //         40031,
  //         "OldEmail, NewEmail, FirstName, LastName, and IsActive are required"
  //       ),
  //     );
  // }

  try {
    // If ctx is not 1 (not using Basic auth), update the database
    if (ctx !== 1) {
      const { coll, client } = ctx;

      const result = await coll.updateOne(
        {
          clientId: client.clientId,
          clientSecret: client.clientSecret,
          "instructors.email": body.OldEmail,
        },
        {
          $set: {
            "instructors.$.email": body.NewEmail,
            "instructors.$.firstName": body.FirstName,
            "instructors.$.lastName": body.LastName,
            "instructors.$.status": body.IsActive ? "active" : "inactive",
            "instructors.$.updatedAt": nowIso(),
            "instructors.$.updateRequest": body,
          },
          $inc: { "perEndpointUsage.updateinstructor": 1 },
        }
      );

      if (result.matchedCount === 0) {
        return res.status(404).json(err(req, 40430, "instructor_not_found"));
      }
    }

    res.status(200).json(ok(req, "success"));
  } catch (e) {
    console.error("updateInstructor failed:", e);
    res.status(500).json(err(req, 50014, "update_instructor_failed"));
  }
};

/**
 * GET /api/session/{SessionId}/attendees
 * 200: { status, correlationId, timestamp, data: { attendees: [{ email: string }] } }
 */
exports.getAttendance = async (req, res) => {
  const ctx = await validateBearerToken(req, res);
  if (!ctx) return;

  //This condition added to handle basic auth
  if (ctx != 1) {
    const { coll, client } = ctx;

    try {
      await coll.updateOne(
        { clientId: client.clientId, clientSecret: client.clientSecret },
        {
          $inc: { "perEndpointUsage.getattendance": 1 },
        },
        { upsert: true }
      );
    } catch (e) {
      console.error("getAttendance DB operation failed:", e);
      // Continue anyway for this endpoint
    }
  }

  res.status(200).json(okAttendance(req, "success"));
};

/**
 * GET /api/session/{SessionId}/user/{base64EncodedEmail}/url
 * 200: { status, correlationId, timestamp, data: { joinUrl: string } }
 */
exports.launchSession = async (req, res) => {
  const ctx = await validateBearerToken(req, res);
  if (!ctx) return;

  //This condition added to handle basic auth
  if (ctx != 1) {
    const { coll, client } = ctx;

    try {
      await coll.updateOne(
        { clientId: client.clientId, clientSecret: client.clientSecret },
        {
          $inc: { "perEndpointUsage.launchsession": 1 },
        },
        { upsert: true }
      );
    } catch (e) {
      console.error("launchSession DB operation failed:", e);
      // Continue anyway for this endpoint
    }
  }

  res.status(200).json(okLaunchSession(req, "success"));
};
function okExtendedOptions(req, status = "success") {
  return {
    status,
    correlationId: getCorrelationId(req),
    timestamp: nowIso(),
    data: {
      extendedOptions: [
        {
          Type: "Label",
          Id: "1",
          ParentId: null,
          Name: "Session Extended Options",
          Description: null,
          Placeholder: null,
          Value: null,
          IsNameVisible: true,
          IsMultiline: false,
          IsChecked: false,
          ChildExtendedOptions: [
            {
              Type: "CheckBox",
              Id: "2",
              ParentId: "1",
              Name: "Allow Attendee To Enable Camera",
              Description: null,
              Placeholder: null,
              Value: null,
              IsNameVisible: true,
              IsMultiline: false,
              IsChecked: true,
              ChildExtendedOptions: []
            },
            {
              Type: "CheckBox",
              Id: "3",
              ParentId: "1",
              Name: "Allow Attendee To Enable Mic",
              Description: null,
              Placeholder: null,
              Value: null,
              IsNameVisible: true,
              IsMultiline: false,
              IsChecked: true,
              ChildExtendedOptions: []
            },
            {
              Type: "CheckBox",
              Id: "4",
              ParentId: "1",
              Name: "Record Automatically",
              Description: null,
              Placeholder: null,
              Value: null,
              IsNameVisible: true,
              IsMultiline: false,
              IsChecked: false,
              ChildExtendedOptions: []
            }
          ]
        }
      ]
    }
  };
}

/**
 * GET /api/session/{SessionId}/extendedoptions
 * Headers: debug (boolean, optional, default: false)
 * 200: { status, correlationId, timestamp, data: { extendedOptions: [...] } }
 */
exports.getExtendedOptions = async (req, res) => {
  const ctx = await validateBearerToken(req, res);
  if (!ctx) return;

  if (ctx !== 1) {
    const { coll, client } = ctx;

    try {
      // Just increment usage counter - no session validation
      await coll.updateOne(
        { clientId: client.clientId, clientSecret: client.clientSecret },
        {
          $inc: { "perEndpointUsage.getextendedoptions": 1 },
        },
        { upsert: true }
      );
    } catch (e) {
      console.error("getExtendedOptions DB operation failed:", e);
      // Continue anyway for this endpoint
    }
  }

  // Always return the same hardcoded response regardless of session existence
  res.status(200).json(okExtendedOptions(req, "success"));
};