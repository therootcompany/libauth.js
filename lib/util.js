"use strict";

let E = require("./errors.js");

let Util = module.exports;

/**
 * @param {string | import('express').Request} req
 */
Util.decodeAuthorizationBasic = function (req) {
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
  return Util.decodeAuthorizationBasicValue(auth);
};

/**
 * @param {string} auth
 */
Util.decodeAuthorizationBasicValue = function (auth) {
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
};

/*
function assertSecureCompare(trusted, given, min) {
  if (secureCompare(trusted, given, min)) {
    return true;
  }
  throw E.WRONG_CREDENTIAL("");
}
*/

Util._textEncoder = new TextEncoder();

Util.secureCompare = async function (trusted = "", given = "", min = 16) {
  // a safeguard against accidental empty string and NaN comparison
  let longEnough = trusted.length >= min;
  if (!longEnough) {
    return false;
  }

  if (!trusted || !given || trusted.length !== given.length) {
    return false;
  }

  let trustedBytes = Util._textEncoder.encode(trusted);
  let givenBytes = Util._textEncoder.encode(given);
  let trustedHashAb = await crypto.subtle.digest("SHA-256", trustedBytes);
  let givenHashAb = await crypto.subtle.digest("SHA-256", givenBytes);
  let trustedHashBytes = new Uint8Array(trustedHashAb);
  let givenHashBytes = new Uint8Array(givenHashAb);

  for (let i = 0; i < trustedHashBytes.length; i += 1) {
    if (trustedHashBytes[i] !== givenHashBytes[i]) {
      return false;
    }
  }
  return true;
};

Util.sleep = async function sleep(n = 0) {
  return await new Promise(function (resolve) {
    setTimeout(resolve, n);
  });
};

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

// TODO expose for library use
/*
let isUnsafe = !prefixesUrl(trustedUrl, requestedRedirect + "/");
if (isUnsafe) {
  throw E.OIDC_BAD_REDIRECT({
    trustedUrl: opts.issuer,
    finalUrl: requestedRedirect,
  });
}
*/
