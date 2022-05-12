"use strict";

let crypto = require("crypto");

let E = require("./errors.js");

module.exports.decodeAuthorizationBasic = decodeAuthorizationBasic;
module.exports.decodeAuthorizationBasicValue = decodeAuthorizationBasicValue;
module.exports.secureCompare = secureCompare;

/**
 * @param {string | import('express').Request} req
 */
function decodeAuthorizationBasic(req) {
  if (!req) {
    req = "";
  }

  let basic;
  if ("string" === typeof req) {
    basic = req.toString();
  } else {
    basic = req?.headers?.authorization?.toString() || "";
  }

  let parts = basic.split(" ");
  if ("Basic" !== parts[0]) {
    throw E.WRONG_TOKEN_TYPE();
  }

  let auth = parts[1] || "";
  return decodeAuthorizationBasicValue(auth);
}

/**
 * @param {string} auth
 */
function decodeAuthorizationBasicValue(auth) {
  let parts;
  try {
    parts = Buffer.from(auth, "base64").toString("utf8").split(":");
  } catch (e) {
    throw E.WRONG_TOKEN_TYPE();
  }

  let u = parts[0];
  let p = parts.slice(1).join(":");
  return {
    username: u,
    password: p,
  };
}

/*
function assertSecureCompare(trusted, given, min) {
  if (secureCompare(trusted, given, min)) {
    return true;
  }
  throw E.WRONG_CREDENTIAL("");
}
*/

function secureCompare(trusted = "", given = "", min = 16) {
  // a safeguard against accidental empty string and NaN comparison
  let longEnough = trusted.length >= min;
  if (!longEnough) {
    return false;
  }

  if (trusted.length !== given.length) {
    return false;
  }

  return crypto.timingSafeEqual(Buffer.from(trusted), Buffer.from(given));
}

/**
 * @param {import('express').Handler} fn
 * @param {import('express').Request} req
 * @param {import('express').Response} res
 * @returns {Promise<any>}
 */
/*
async function promisifyHandler(fn, req, res) {
  let err = await new Promise(async function (resolve, reject) {
    try {
      //@ts-ignore
      await fn(req, res, resolve).catch(reject);
    } catch (err) {
      reject(err);
    }
  });
  if (err) {
    throw err;
  }
}
*/

/*
let localhosts = ["::ffff:127.0.0.1", "127.0.0.1", "::1"];
*/

/**
 * @param {import('express').Handler} mw1
 * @param {import('express').Handler} mw2
 * @returns {import('express').Handler}
 */
/*
function chain(mw1, mw2) {
  // Please excuse the ugly, but I needed both `express.Handler`s
  // to execute as one. ¯\_(ツ)_/¯

  /** @type {import('express').Handler} */
/*
  function plainHandler1(req, res, next) {
    //@ts-ignore
    return Promise.resolve()
      .then(async function () {
        /// @ts-ignore (for next / error handler)
        await mw1(req, res, plainNext2);
      })
      .catch(next);

    //@ts-ignore
    function plainNext2(err) {
      if (err) {
        throw err;
      }
      return Promise.resolve()
        .then(async function () {
          await mw2(req, res, next);
        })
        .then(next)
        .catch(next);
    }
  }
  return plainHandler1;
}
*/
