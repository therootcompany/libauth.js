"use strict";

let MyAuth = module.exports;

let DB = require("./db.js");

let LibAuth = require("libauth");

function userToClaims(user) {
  return {
    // "Subject" the user ID or Pairwise ID (required)
    sub: user.sub || user.id,

    // ID Token Info (optional)
    given_name: user.first_name,
    family_name: user.first_name,
    picture: user.photo_url,
    email: user.email,
    email_verified: user.email_verified_at || false,
    zoneinfo: user.timezoneName,
    locale: user.localeName,
  };
}

let ChallengeStore = {
  _db: {},
  set: async function (challenge) {
    ChallengeStore._db[challenge.id] = challenge;
    ChallengeStore._db[challenge.identifier_value] = challenge;
  },
  get: async function ({ id }) {
    return ChallengeStore._db[id];
  },
};
MyAuth.ChallengeStore = ChallengeStore;

MyAuth.expireCurrentSession = function (req, res, next) {
  async function mw() {
    // Invalidate the old session, if any
    let sessionId = req.libauth.get("currentSessionClaims")?.jti;
    if (sessionId) {
      //await DB.Session.set({ id: sessionId, deleted_at: new Date() });
    }

    next();
  }

  // (shim for adding await support to express)
  Promise.resolve().then(mw).catch(next);
};

MyAuth.saveNewSession = function (req, res, next) {
  async function mw() {
    // Save the new session
    let newSessionClaims = req.libauth.get("sessionClaims");
    if (!newSessionClaims) {
      next();
      return;
    }

    let newSessionId = newSessionClaims.jti;
    let userId = newSessionClaims.sub;

    //await DB.Session.set({ id: newSessionId, user_id: userId });

    next();
  }

  // (shim for adding await support to express)
  Promise.resolve().then(mw).catch(next);
};

MyAuth.getUserClaimsByBearer = function (req, res, next) {
  async function mw() {
    let userId = req.libauth.get("bearerClaims").sub;

    // get a new access token from an ID token (or refresh token?)
    let user = await DB.get({ id: userId });

    let accessClaims = userToClaims(user);
    req.libauth.set({ accessClaims });

    next();
  }

  Promise.resolve().then(mw).catch(next);
};

MyAuth.getUserClaimsBySession = function (req, res, next) {
  async function mw() {
    let userId = req.libauth.get("sessionClaims").sub;

    // get a new access token from an ID token (or refresh token?)
    let user = await DB.get({ id: userId });

    let idClaims = userToClaims(user);
    req.libauth.set({ idClaims });

    next();
  }

  Promise.resolve().then(mw).catch(next);
};

MyAuth.getUserClaimsBySub = function (req, res, next) {
  async function mw() {
    let sub = req.libauth.get("userClaims")?.sub;

    // get a new session
    // TODO check if it's actually email!
    let user = await DB.get({ id: sub });

    let idClaims = userToClaims(user);
    req.libauth.set({ idClaims: idClaims, accessClaims: {} });

    next();
  }

  Promise.resolve().then(mw).catch(next);
};

MyAuth.getUserClaimsByIdentifier = function (req, res, next) {
  async function mw() {
    let challenge = req.libauth.get("challenge");

    let email = challenge.order?.identifier?.value;

    // get a new session
    // TODO check if it's actually email!
    let user = await DB.get({ email: email });

    let idClaims = userToClaims(user);
    req.libauth.set({ idClaims: idClaims, accessClaims: {} });

    next();
  }

  Promise.resolve().then(mw).catch(next);
};

MyAuth.getUserClaimsByPassword = function (req, res, next) {
  async function mw() {
    let creds = req.libauth.get("credentials");
    let user = await DB.get({ email: creds.email });

    // TODO assertSecureCompare?
    let valid = LibAuth.secureCompare(
      creds.password,
      //user.password,
      "my-password",
      6,
    );
    if (!valid) {
      // Note: the behavior of send-magic-link-on-auth-failure
      // belongs to the client side
      let err = new Error("password is too short or doesn't match");
      err.code = "E_CREDENTIALS_INVALID";
      err.status = 400;
      throw err;
    }

    let idClaims = userToClaims(user);
    req.libauth.set({ idClaims: idClaims, accessClaims: {} });

    next();
  }

  Promise.resolve().then(mw).catch(next);
};

MyAuth.getUserClaimsByOidcEmail = function (req, res, next) {
  async function mw() {
    let email = req.libauth.get("email");
    let user = await DB.get({ email: email });

    let idClaims = userToClaims(user);
    console.log("[DEBUG] getUserClaimsByOidcEmail", email, user, idClaims);
    req.libauth.set({ idClaims: idClaims, accessClaims: {} });

    next();
  }

  Promise.resolve().then(mw).catch(next);
};

MyAuth.sendCodeToUser = function (req, res, next) {
  async function mw() {
    let vars = req.libauth.get("challenge");
    let scheme = "http:";

    //let vars = req.authn;
    // Notify via CLI
    console.info(vars);
    console.info({
      subject: `Your Magic Link is here! ${vars.code}.`,
      text:
        `Enter this login code when prompted: ${vars.code}. \n` +
        // `Or login with this link: ${vars.iss}/login/#/${vars.id}/${vars.code}`,
        `Or login with this link: ${scheme}//${req.headers.host}/#login?id=${vars.order.id}&code=${vars.code}`,
    });

    next();
  }

  Promise.resolve().then(mw).catch(next);
};
