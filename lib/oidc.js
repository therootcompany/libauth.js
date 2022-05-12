"use strict";

let crypto = require("crypto");
let OIDC = module.exports;
let Errors = require("../errors.js");

let request = require("@root/request");

/*
OIDC._queryparse = function (search) {
  let params = {};
  new URLSearchParams(search).forEach(function (v, k) {
    // Note: technically the same key _could_ come twice
    // ex: 'names[]=aj&names[]=ryan'
    // (but we're ignoring that case)
    params[k] = v;
  });
  return params;
};
*/

/**
 * @param {String} oidcBaseUrl
 * @param {String} client_id
 * @param {String} redirect_uri
 * @param {String} state
 * @param {String} scope
 * @param {String} login_hint
 * @returns {URL}
 */
OIDC.generateOidcUrl = function (
  oidcBaseUrl,
  { client_id, redirect_uri, state, scope = "", login_hint = "" },
) {
  // response_type=id_token requires a nonce (one-time use random value)
  // response_type=token (access token) does not
  var nonce = crypto.randomUUID().replace(/-/g, "");
  var options = { state, client_id, redirect_uri, scope, login_hint, nonce };
  // transform from object to 'param1=escaped1&param2=escaped2...'
  var params = new URLSearchParams(options).toString();

  return new URL(
    `${oidcBaseUrl}?response_type=code&access_type=online&${params}`,
  );
};

// TODO @root/request
/** @param {any} resp */
async function mustOk(resp) {
  if (resp.ok) {
    return resp;
  }
  throw Errors.OIDC_BAD_GATEWAY();
}

/** @param {String} issuer */
OIDC.getConfig = async function (issuer) {
  // TODO check cache headers / cache for 5 minutes
  let oidcUrl = issuer;
  if (!oidcUrl.endsWith("/")) {
    oidcUrl += "/";
  }
  oidcUrl += ".well-known/openid-configuration";

  // See examples:
  // Google: https://accounts.google.com/.well-known/openid-configuration
  // Auth0: https://example.auth0.com/.well-known/openid-configuration
  // Okta: https://login.writesharper.com/.well-known/openid-configuration
  let resp = await request({ url: oidcUrl, json: true })
    .then(mustOk)
    //@ts-ignore
    .catch(function (err) {
      console.error(`Could not get '${oidcUrl}':`);
      console.error(err);
      throw Errors.create(
        "could not fetch OpenID Configuration - try inspecting the token and checking 'iss'",
        {
          code: "E_BAD_REMOTE",
          status: 422,
        },
      );
    });

  return resp.body;
};
