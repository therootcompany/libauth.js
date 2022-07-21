# libauth.js

> Modern, OpenID Connect compatible authentication.

```js
// ...
let LibAuth = require("libauth");
let libauth = LibAuth.create(issuer, privkey, {
  cookies: { path: "/api/authn/" },
});

// ...
app.post("/api/authn/session/credentials", setCookieByCredentials);
app.post("/api/authn/session/id_token", sendIdTokenBySession);
app.post("/api/authn/access_token", sendAccessTokenByIdToken);
app.delete("/api/authn/session", revokeCookieAndIdToken);

app.use("/.well-known/openid-configuration", libauth.wellKnownOidc());
app.use("/.well-known/jwks.json", libauth.wellKnownJwks());
```

# Features

- [x] Standards-based session management (localStorage not necessary)
  - [x] Long-lived refresh tokens (default 30d)
  - [x] Long-lived session cookies (default 30d)
  - [x] Short-lived id & access tokens (default 1d, 15m)
  - [x] Logout (expire refresh cookie)
- [x] Supports common login strategies
  - [x] Credentials-based login (HTTP Basic Auth)
  - [x] OIDC (OpenID Connect, OAuth2) login (Google Sign In, etc)
  - [x] Challenge-Response (Magic Link)
- [x] Idiomatic, Composable Express.js Routing
- [x] Email & SMS Verification flow (bring-your-own-mailer)
- [x] No need for `localStorage`!

# Table of Contents

- [Installation](#installation)
  - Node.js
  - libauth
- [Philosophy](#philosophy)
- [Usage](#usage)

# Installation

Install Node.js:

```bash
curl https://webinstall.dev/node@v16 | bash
export PATH="$HOME/.local/opt/node/bin:$PATH"
```

Install libauth:

```bash
npm install --save libauth@v0
```

Note: The v1 API is not yet locked. Some names may change. Any changes from
v0.90.x on will be noted in migration notes.

# Philosophy

The goal of LibAuth is to _minimize magic_ (anything difficult to understand or
configure), and _maximize control_, without sacrificing _ease-of-use_,
convenience, or security.

To do this we require **more copy-and-paste boilerplate** than other auth
libraries - with the upside is that it's all just normal, easy-to-replace
_middleware_ - hopefully nothing unexpected or constraining.

You'll also notice that we try to use the proper, official technical language
rather than potentially ambiguous sugar-coated terms (for example: 'cookie' or
'token' when specificity is required, or 'session' when it could be either).

# Usage

## Prerequisites: Generate Secrets

There's a few keys, secrets, and salts that you'll need. Here's how you can
generate them:

### Automatic

You can generate a `.env` with the required secrets **all at once**:

```bash
npx libauth@v0 envs ./.env
```

`.env`:

```txt
COOKIE_SECRET=xxxx
MAGIC_SALT=xxxx
PRIVATE_KEY='{"d": "xxxx"}'
```

### Option B: Manual

Or you can generate them one-by-one with the _libauth commands_:

```bash
npx libauth@v0 privkey
npx libauth@v0 rnd
```

which are **the same** as running the following:

```bash
./node_modules/libauth/bin/libauth.js privkey
./node_modules/libauth/bin/libauth.js rnd
```

Each of these should be included in your `.env` file:

1. Generate the `PRIVATE_KEY`:
   ```bash
   echo "PRIVATE_KEY='$(
    npx libauth@v0 privkey
   )'" >> .env
   ```
2. Generate the `COOKIE_SECRET`:
   ```bash
   echo "COOKIE_SECRET=$(
    npx libauth@v0 rnd 16
   )" >> .env
   ```
3. Generate the `MAGIC_SALT`:
   ```bash
   echo "MAGIC_SALT=$(
    npx libauth@v0 rnd 16
   )" >> .env
   ```

You could also use [keypairs](https://webinstall.dev/keypairs) and
`openssl rand -base64 16`.

## 1. Top-Level Routes

```js
"use strict";

let FsSync = require("fs");

let issuer = process.env.BASE_URL || `http://localhost:${process.env.PORT}`;
let privkey = JSON.parse(FsSync.readFileSync("./key.jwk.json", "utf8"));

let bodyParser = require("body-parser");
app.use("/api/authn", bodyParser.json({ limit: "100kb" }));

let cookieParser = require("cookie-parser");
let cookieSecret = process.env.COOKIE_SECRET;
app.use("/api/authn/session", cookieParser(cookieSecret));

let authRoutes = require("./auth-routes.js").create(issuer, privkey, {
  cookies: { path: "/api/authn/session/", sameSite: "strict" },
});

app.post("/api/authn/session/credentials", authRoutes.setCookieByCredentials);
app.post("/api/authn/session/id_token", authRoutes.sendIdTokenBySession);
app.delete("/api/authn/session", authRoutes.revokeCookieAndIdToken);

app.post("/api/authn/access_token", authRoutes.sendAccessTokenByIdToken);

app.get("/.well-known/openid-configuration", authRoutes.wellKnownOidc);
app.get("/.well-known/jwks.json", authRoutes.wellKnownJwks);

module.exports = app;
```

```js
"use strict";

let AuthRoutes = module.exports;

let LibAuth = require("libauth");

AuthRoutes.create = function () {
  let authRoutes = {};

  let libauth = LibAuth.create(issuer, privkey, {
    cookies: {
      path: "/api/authn/",
      sameSite: "strict",
    },
    /*
    refreshCookiePath: "/api/authn/",
    accessCookiePath: "/api/assets/",
    */
  });

  // Create session by login credentials
  AuthRoutes.setCookieByCredentials = [
    libauth.readCredentials(),
    MyDB.getUserClaimsByPassword,
    libauth.newSession(),
    libauth.initClaims(),
    libauth.initTokens(),
    libauth.initCookie(),
    MyDB.expireCurrentSession,
    MyDB.saveNewSession,
    libauth.setCookieHeader(),
    libauth.sendTokens(),
  ];

  // Refresh ID Token via Session
  AuthRoutes.sendIdTokenBySession = [
    libauth.requireCookie(),
    MyDB.getUserClaimsBySub,
    libauth.initClaims({ idClaims: {} }),
    libauth.initTokens(),
    libauth.sendTokens(),
  ];

  // Exchange Access Token via ID Token
  AuthRoutes.sendAccessTokenByIdToken = [
    libauth.requireBearerClaims(),
    MyDB.getUserClaimsBySub,
    libauth.initClaims({ accessClaims: {} }),
    libauth.initTokens(),
    libauth.sendTokens(),
  ];

  // Logout (delete session cookie)
  AuthRoutes.revokeCookieAndIdToken = [
    libauth.readCookie(),
    MyDB.expireCurrentSession,
    libauth.expireCookie(),
    libauth.sendOk({ success: true }),
    libauth.sendError({ success: true }),
  ];

  AuthRoutes.wellKnownOidc = libauth.wellKnownOidc();
  AuthRoutes.wellKnownJwks = libauth.wellKnownJwks();

  return authRoutes;
};
```

```js
"use strict";

require("dotenv").config({ path: ".env" });

let Http = require("http");
let Express = require("express");

let server = Express();
let app = new Express.Router();

let port = process.env.PORT || 3000;
Http.createServer(server).listen(port, function () {
  /* jshint validthis:true */
  console.info("Listening on", this.address());
});
```

Handling the following strategies:

- [x] `oidc` - ex: Facebook Connect, Google Sign In, Microsoft Live
- [x] `credentials` - bespoke, specified by you
  - [x] Username / Password
  - [x] API Key
- [x] `challenge` - a.k.a. "verification email" or "Magic Link" ( or SMS code)
- [x] `refresh` - to refresh an `id_token` via refresh token cookie
- [x] `exchange` - to exchange an `id_token` for an `access_token`
  - [x] JWK

# Node API

## Errors

| Name                         | Status   | Message (truncated)                              |
| ---------------------------- | -------- | ------------------------------------------------ |
| E_CODE_NOT_FOUND             | 404      | That verification code isn't valid. It might ... |
| E_CODE_INVALID               | 400\|403 | That verification code isn't valid. It might ... |
| E_CODE_REDEEMED              | 400      | That verification code has already been used ... |
| E_CODE_RETRY                 | 400      | That verification code isn't correct. It may ... |
| E_OIDC_UNVERIFIED_IDENTIFIER | 400      | You cannot use the identifier associated with... |
| E_SESSION_INVALID            | 400      | Missing or invalid cookie session. Please log... |
| E_SUSPICIOUS_REQUEST         | 400      | Something suspicious is going on - as if ther... |
| E_SUSPICIOUS_TOKEN           | 400      | Something suspicious is going on - the given ... |
| E_DEVELOPER_ERROR            | 422      | Oops! One of the programmers made a mistake. ... |
| " -> WRONG_TOKEN_TYPE        | 422      | the HTTP Authorization was not given in a sup... |
| " -> MISSING_TOKEN           | 401      | the required authorization token was not prov... |

## Glossary

| Term            | Meaning                                                       |
| --------------- | ------------------------------------------------------------- |
| JWS             | A decoded JWT (non-compact JWS), or JSON Web Signature        |
| JWT             | A compact (or encoded) JWS, or JSON Web Token                 |
| `id_token`      | A JWT with information about the user, such `given_name`      |
| `access_token`  | A JWT with information about an account or resource           |
| `refresh_token` | A long-lived JWT, stored in a session cookie (or config file) |
| `amr`           | The list of methods used for Multi-Factor Authentication      |
| `acr`           | For specifying [LoA Profiles][loa] (mostly useless)           |

[loa]: https://www.iana.org/assignments/loa-profiles/loa-profiles.xhtml

## Design Decisions

- directed flow of data
  - `libauth` passes data to you through `req.authn` via middleware
  - You pass data to `libauth` by POST or by calling functions

# Resources

- [Live Recordings](https://www.youtube.com/playlist?list=PLxki0D-ilnqYmidRxvrQoF2jX67wH5OS0)
  of the making of this project
- [Express Cookies Cheat Sheet](https://github.com/BeyondCodeBootcamp/beyondcodebootcamp.com/blob/main/articles/express-cookies-cheatsheet.md)
- [How to add Google Sign In](https://therootcompany.com/blog/google-sign-in-javascript-api/)
- [How many Bits of Entropy per Character in...](https://therootcompany.com/blog/how-many-bits-of-entropy-per-character/)

### Live Code Project

This code was written live, in front of a combined YouTube & Twitch audience.

If you want to see all 40+ hours of painstaking coding... here ya go:

<https://www.youtube.com/playlist?list=PLxki0D-ilnqYmidRxvrQoF2jX67wH5OS0>
