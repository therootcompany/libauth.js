"use strict";

let crypto = require("crypto");
let OIDC = module.exports;
let Errors = require("../errors.js");

let request = require("@root/request");

OIDC._querystringify = function (params) {
  // { foo: 'bar', baz: 'qux' } => foo=bar&baz=qux
  return new URLSearchParams(params).toString();
};

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

OIDC.generateOidcUrl = function (
  oidcBaseUrl,
  client_id,
  redirect_uri,
  state,
  scope = "",
  login_hint = ""
) {
  // response_type=id_token requires a nonce (one-time use random value)
  // response_type=token (access token) does not
  var nonce = crypto.randomUUID().replace(/-/g, "");
  var options = { state, client_id, redirect_uri, scope, login_hint, nonce };
  // transform from object to 'param1=escaped1&param2=escaped2...'
  var params = OIDC._querystringify(options);

  return `${oidcBaseUrl}?response_type=code&access_type=online&${params}`;
};

async function mustOk(resp) {
  if (resp.statusCode >= 200 && resp.statusCode < 300) {
    return resp;
  }
  throw Errors.OIDC_BAD_GATEWAY();
}

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
    .catch(function (err) {
      console.error(`Could not get '${oidcUrl}':`);
      console.error(err);
      throw Errors.create(
        "could not fetch OpenID Configuration - try inspecting the token and checking 'iss'",
        {
          code: "E_BAD_REMOTE",
          status: 422,
        }
      );
    });

  return resp.body;
};
