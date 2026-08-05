/**
 * @license
 * jwt.js - JWT for node.js and browsers
 *
 * Authored in 2025 by AJ ONeal <aj@therootcompany.com>
 * To the extent possible under law, the author(s) have dedicated all copyright
 * and related and neighboring rights to this software to the public domain
 * worldwide. This software is distributed without any warranty.
 *
 * You should have received a copy of the CC0 Public Domain Dedication along with
 * this software. If not, see <https://creativecommons.org/publicdomain/zero/1.0/>.
 */
"use strict";

let JWT = module.exports;

JWT._textEncoder = new TextEncoder();

/** @typedef {String} URLBase64 */

/** @typedef {JWKEC|JWKRSA} JWK */

/**
 * Untyped JSON Web Key for ECDSA.
 * @typedef JWKAny
 * @prop {String} kty - Key type, must be "EC".
 * @prop {String} [crv] - Curve name, must be {"P-256"|"P-384"|"P-521"}.
 * @prop {URLBase64} [n] - Modulus of the RSA key, URL-safe base64-encoded.
 * @prop {URLBase64} [e] - Public exponent of the RSA key, URL-safe base64-encoded.
 * @prop {URLBase64} [x] - X coordinate of the public key
 * @prop {URLBase64} [y] - Y coordinate of the public key
 * @prop {URLBase64} [d] - Private key
 * @prop {String} [use] - Key use (sig for private, enc for public)
 * @prop {String} [kid] - Key ID
 */

/**
 * JSON Web Key for ECDSA.
 * @typedef JWKEC
 * @prop {String} kty - Key type, must be "EC".
 * @prop {String} crv - Curve name, must be {"P-256"|"P-384"|"P-521"}.
 * @prop {URLBase64} x - X coordinate of the public key
 * @prop {URLBase64} y - Y coordinate of the public key
 * @prop {URLBase64} [d] - Private key
 * @prop {String} [use] - Key use (sig for private, enc for public)
 * @prop {String} [kid] - Key ID
 */

/**
 * JSON Web Key for ECDSA (ES256).
 * @typedef JWKES256
 * @prop {"EC"} kty - Key type, must be "EC".
 * @prop {"P-256"} crv - Curve name, must be {"P-256"|"P-384"|"P-521"}.
 * @prop {URLBase64} x - X coordinate of the public key
 * @prop {URLBase64} y - Y coordinate of the public key
 * @prop {URLBase64} [d] - Private key
 * @prop {"sig"|"enc"} [use] - Key use (sig for private, enc for public)
 * @prop {String} [kid] - Key ID
 */

/**
 * JSON Web Key for RSA.
 * @typedef JWKRSA
 * @prop {String} kty - Key type, must be "RSA".
 * @prop {URLBase64} n - Modulus of the RSA key, URL-safe base64-encoded.
 * @prop {URLBase64} e - Public exponent of the RSA key, URL-safe base64-encoded.
 * @prop {URLBase64} [d] - Private exponent, URL-safe base64-encoded (optional, for private keys).
 * @prop {String} [use] - Key use, must be {"sig"|"enc"} (optional).
 * @prop {String} [kid] - Key ID (optional).
 */

/**
 * @typedef  JWTOpts
 * @prop {Partial<JWTHeader>} header
 * @prop {Partial<JWTClaims>} claims
 * @prop {String|false} iss
 * @prop {String} alg
 * @prop {Number|false} iat
 * @prop {String|Number|false} exp
 */

/**
 * @typedef  JWTHeader
 * @prop {String} alg
 * @prop {String|false} kid
 * @prop {String} crv
 * @prop {String} typ
 * @prop {JWKAny|JWKEC|JWKRSA} jwk
 */

/**
 * @typedef  JWTClaims
 * @prop {String|false} iss
 * @prop {Number|false} iat
 * @prop {String|Number|false} exp
 */

/**
 * Signs a JWT using ES256 (ECDSA SHA-256) or RS256 (RSA SHA-256) with a JWK private key.
 * @param {JWKAny|JWKEC|JWKRSA} privateKeyJwk - The JWK private key (EC or RSA).
 * @param {JWTOpts} opts
 * @returns {Promise<string>} The signed JWT.
 */
JWT.sign = async function (privateKeyJwk, opts) {
  let keyAlgo;
  let signAlgo;

  let header = opts.header || {};
  {
    header.typ = "JWT";
    if (!header.kid) {
      if (!header.jwk && header.kid !== false) {
        header.kid = await JWT.thumbprint(privateKeyJwk);
      }
    }
    if (!header.alg && opts.alg) {
      header.alg = opts.alg;
    }
  }

  let claims = Object.assign({}, opts.claims);
  {
    if (!claims.iat) {
      if (claims.iat === false || opts.iat === false) {
        claims.iat = undefined;
      } else {
        claims.iat = Math.round(Date.now() / 1000);
      }
    }

    if (opts.exp) {
      claims.exp = timeOrDurationToSeconds(opts.exp);
    } else if (!claims.exp) {
      if (claims.exp === false || opts.exp === false) {
        claims.exp = undefined;
      } else {
        throw new Error(
          "opts.claims.exp should be the expiration date as seconds, human form (i.e. '1h' or '15m') or false",
        );
      }
    }

    if (opts.iss) {
      claims.iss = opts.iss;
    } else if (!claims.iss) {
      if (claims.iss === false || opts.iss === false) {
        claims.iss = undefined;
      } else {
        throw new Error(
          "opts.claims.iss should be in the form of https://example.com/, a secure OIDC base url",
        );
      }
    }
  }

  if (isJWKEC(privateKeyJwk)) {
    if (!privateKeyJwk.crv || !privateKeyJwk.d) {
      throw new Error("Invalid EC JWK: missing crv or d");
    }
    header = Object.assign({ alg: "ES256", typ: "JWT" }, header);
    keyAlgo = { name: "ECDSA", namedCurve: privateKeyJwk.crv };
    signAlgo = { name: "ECDSA", hash: "SHA-256" };
  } else if (isJWKRSA(privateKeyJwk)) {
    if (!privateKeyJwk.n || !privateKeyJwk.d) {
      throw new Error("Invalid RSA JWK: missing n or d");
    }
    header = Object.assign({ alg: "RS256", typ: "JWT" }, header);
    keyAlgo = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" };
    signAlgo = { name: "RSASSA-PKCS1-v1_5" };
  } else {
    throw new Error(`Unsupported JWK key type: ${privateKeyJwk.kty}`);
  }

  let sortedHeader = JWT._shallowCanonicalCopy(header);
  let headerJson = JSON.stringify(sortedHeader);
  let headerB64 = JWT._binstrToUrlBase64(headerJson);

  let sortedPayload = JWT._shallowCanonicalCopy(claims);
  let payloadJson = JSON.stringify(sortedPayload);
  let payloadB64 = JWT._utf8ToUrlBase64(payloadJson);

  let key = await crypto.subtle.importKey(
    "jwk",
    privateKeyJwk,
    keyAlgo,
    false,
    ["sign"],
  );

  let input = `${headerB64}.${payloadB64}`;
  let inputBytes = JWT._textEncoder.encode(input);
  let signatureAb = await crypto.subtle.sign(signAlgo, key, inputBytes);
  let signatureBytes = new Uint8Array(signatureAb);
  //@ts-expect-error - Uint8Array is ArrayLike
  let signatureBin = String.fromCharCode.apply(null, signatureBytes);
  let signatureB64 = JWT._binstrToUrlBase64(signatureBin);

  let jwt = `${input}.${signatureB64}`;
  return jwt;
};

/**
 * Make a copy with lexicographically-sorted keys
 * @param {Object.<String, String>} obj
 * @returns {Object.<String, String>}
 */
JWT._shallowCanonicalCopy = function (obj) {
  let copy = {};

  let keys = Object.keys(obj).sort();
  for (let key of keys) {
    copy[key] = obj[key];
  }

  return copy;
};

/**
 * @param {Number|String} time
 */
function timeOrDurationToSeconds(time) {
  if ("number" === typeof time) {
    return time;
  }

  var t = time.match(/^(\-?\d+)([dhms])$/i);
  if (!t || !t[0]) {
    throw new Error(
      "'" +
        time +
        "' should be datetime in seconds or human-readable format (i.e. 3d, 1h, 15m, 30s",
    );
  }

  var now = Math.round(Date.now() / 1000);
  var num = parseInt(t[1], 10);
  var unit = t[2];
  var mult = 1;
  switch (unit) {
    // fancy fallthrough, what fun!
    case "d":
      mult *= 24;
    /*falls through*/
    case "h":
      mult *= 60;
    /*falls through*/
    case "m":
      mult *= 60;
    /*falls through*/
    case "s":
      mult *= 1;
  }

  return now + mult * num;
}

/**
 * Computes the JWK thumbprint for an EC key per RFC 7638.
 * @param {JWKAny|JWKEC|JWKRSA} jwk - The JWK EC key (public or private).
 * @returns {Promise<URLBase64>} URL-safe base64-encoded thumbprint.
 */
JWT.thumbprint = async function (jwk) {
  let required;
  if (isJWKEC(jwk)) {
    if (!jwk.crv || !jwk.x || !jwk.y) {
      throw new Error("Invalid EC JWK: missing crv, x, or y");
    }
    required = { crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y };
  } else if (isJWKRSA(jwk)) {
    if (!jwk.n || !jwk.e) {
      throw new Error("Invalid RSA JWK: missing n or e");
    }
    required = { e: jwk.e, kty: jwk.kty, n: jwk.n };
  } else {
    throw new Error(`Unsupported JWK key type: ${jwk.kty}`);
  }

  let sortedJson = JSON.stringify(required);
  let bytes = JWT._textEncoder.encode(sortedJson);
  let hashAb = await crypto.subtle.digest("SHA-256", bytes);
  let hashBytes = new Uint8Array(hashAb);
  //@ts-expect-error - Uint8Array is ArrayLike
  let bin = String.fromCharCode.apply(null, hashBytes);
  let base64 = JWT._binstrToUrlBase64(bin);

  return base64;
};

/**
 * Type guard to narrow a JWK to JWKEC.
 * @param {JWKAny|JWKEC|JWKRSA} jwk - The JWK to check.
 * @returns {jwk is JWKEC} True if the JWK is an EC key.
 */
function isJWKEC(jwk) {
  return jwk.kty === "EC";
}

/**
 * Type guard to narrow a JWK to JWKRSA.
 * @param {JWKAny|JWKEC|JWKRSA} jwk - The JWK to check.
 * @returns {jwk is JWKRSA} True if the JWK is an RSA key.
 */
function isJWKRSA(jwk) {
  return jwk.kty === "RSA";
}

/** @typedef {String} UTF8Str */

/**
 * Encode to Base64 URL-safe string
 * @param {UTF8Str} utf8
 * @returns {URLBase64}
 */
JWT._utf8ToUrlBase64 = function (utf8) {
  let bytes = JWT._textEncoder.encode(utf8);
  let bin = String.fromCharCode.apply(null, bytes);
  let b64 = JWT._binstrToUrlBase64(bin);
  return b64;
};

/** @typedef {String} BinStr */

/**
 * Encode to Base64 URL-safe string
 * @param {BinStr} bin
 * @returns {URLBase64}
 */
JWT._binstrToUrlBase64 = function (bin) {
  let base64 = btoa(bin);
  base64 = base64.replace(/\+/g, "-");
  base64 = base64.replace(/\//g, "_");
  base64 = base64.replace(/=+$/, "");
  return base64;
};
