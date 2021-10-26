# auth3000

> Modern, OpenID Connect compatible authentication.

```js
// Authenticate Users
let Auth3000 = require("auth3000");
let issuer = "http://localhost:3000";
let privkey = JSON.parse(fs.readFileSync("./key.jwk.json"));
let sessionMiddleware = Auth3000(issuer, privkey, { DEVELOPMENT: false });

sessionMiddleware.login(async function (req, res) {
  let { strategy, email, iss, ppid, oidc_claims } = req.authn;

  switch (strategy) {
    case "oidc":
      let claims = await Users.find({ email: email });
      return { claims };
    default:
      throw new Error("unsupported auth strategy");
  }
});
sessionMiddleware.oidc({ "accounts.google.com": { clientId: "xxxx" } });
sessionMiddleware.oauth2({
  github: { clientId: "xxxx", clientSecret: "xxxx" },
});
sessionMiddleware.challenge({ notify, store, maxAge: "24h", maxAttempts: 5 });
sessionMiddleware.credentials();

// /api/authn/{session,refresh,exchange,challenge,logout}
app.use("/api/authn", sessionMiddleware.router());
// /.well-known/openid-configuration
app.use("/", sessionMiddleware.wellKnown());
```

```js
// Verify Tokens
let verify = require("auth3000/middleware/");
app.use("/api", verify({ iss: issuer }));

app.use("/api/hello", function (req, res) {
  console.log("claims:", req.user);
  res.json({ message: "hello" });
});
```

# Features

- [x] Short-Lived ID & Access Tokens (default 1h, and 15m)
- [x] Refresh Tokens in Cookie (default 30d)
- [x] Refresh Endpoint (no localStorage!)
- [x] Email & SMS Verification flow (bring-your-own-mailer)
- [x] Logout (expire refresh cookie)

Handling the following strategies:

- [x] `oidc` - ex: Facebook Connect, Google Sign In, Microsoft Live
- [x] `oauth2` - ex: GitHub Sign In
- [x] `credentials` - bespoke, specified by you
  - [x] Username / Password
  - [x] API Key
- [x] `challenge` - a.k.a. "verification email" or "Magic Link" ( or SMS code)
- [x] `refresh` - to refresh an `id_token` via refresh token cookie
- [x] `exchange` - to exchange an `id_token` for an `access_token`
  - [x] JWK

### Live Code Project

This code was written live, in front of a combined YouTube & Twitch audience.

If you want to see all 40+ hours of painstaking coding... here ya go:

<https://www.youtube.com/playlist?list=PLxki0D-ilnqYmidRxvrQoF2jX67wH5OS0>

# Usage

You'll need a private key in JWK format. You can use
[keypairs](https://webinstall.dev/keypairs) for that:

```bash
curl https://webinstall.dev/keypairs | bash
keypairs gen --key key.jwk.json --pub pub.jwk.json
```

Here's the basic boilerplate:

```js
// your base url
let issuer = "http://localhost:3000";
// jwk object (note: if you have a key in another format, see 'Converting PEM' below)
let privkey = JSON.parse(fs.readFileSync("./privkey.jwk.json", "utf8"));

// the private key will be used if `secret` is not provided
let secret = crypto.randomBytes(16).toString("base64");
let sessionMiddleware = require("auth3000")(issuer, privkey, {
  DEVELOPMENT: false,
  secret: secret,
  authnParam: "authn",
});

// Login will issue (at least) an id_token, and set a refresh_token cookie
sessionMiddleware.login(loginHandler);
// load optional login strategies...
sessionMiddleware.oidc({ "accounts.google.com": { clientId: "xxxx" } });
sessionMiddleware.oauth2({
  "github.com": { clientId: "xxxx", clientSecret: "zzzz" },
});
sessionMiddleware.challenge({ notify, store, maxAge: "24h", maxAttempts: 5 });
sessionMiddleware.credentials();

// Refresh will re-issue an id_token
sessionMiddleware.refresh(exchangeHandler);

// Exchange will exchange an id_token for an access_token
sessionMiddleware.exchange(exchangeHandler);

// Logout will revoke the refresh_token
// (this is an extra security feature to protect against scenarios in which
// an attacker is able to get a copy of a cookie before a browser expires it)
sessionMiddleware.logout(logoutHandler);

// /api/authn/{session,refresh,exchange,challenge,logout}
app.use("/api/authn", sessionMiddleware.router());

// /.well-known/openid-configuration
// /.well-known/jwks.json
app.use("/", sessionMiddleware.wellKnown());

//
// Securing the API with ID & Access Tokens
//
let verify = require("auth3000/middleware/");
app.use("/api", verify({ iss: issuer, optional: true }));

app.use("/api/debug/inspect", function (req, res) {
  res.json({ success: true, user: req.user || null });
});

app.use("/api/hello", function (req, res) {
  if ("admin" !== req.user.role) {
    res.json({ message: "goodbye" });
    return;
  }

  res.json({ message: "hello" });
});

// The various auth handlers are where you do the real decision-making.
// You have full access to the `req` object to use as you see fit.

async function loginHandler(req, res) {
  let { strategy, email } = req.authn;
  let idClaims;

  switch (strategy) {
    case "oauth2":
      {
        let { iss, id } = req.authn;
        idClaims = await db.User.find({ email: email, iss: iss, id: id });
      }
      break;
    case "oidc":
      {
        let { iss, ppid } = req.authn;
        idClaims = await db.User.find({ email: email, iss: iss, ppid: ppid });
      }
      break;
    case "credentials":
      // you could also handle an API key here
      idClaims = await db.User.findAndVerifyPassword({
        user: req.body.user,
        pass: req.body.pass,
      });
      break;
    case "challenge":
      idClaims = await db.User.find({ email: email });
      break;
    default:
      throw new Error("unsupported login strategy");
  }
  if (!idClaims) {
    throw new Error("login failed");
  }

  let jti = crypto.randomBytes(16).toString("base64");
  // this can also be used as an audit log
  await db.Session.insert({ jti, revoked_at: null });

  // You can return a simple id_token (just profile info, no privileges)
  // or an access_token (including roles, permissions, etc), or both

  let { role = "user" } = await db.Account.getRole({ user_id: sub });
  await res.issue({
    // 'sub' is "subject" a.k.a. user_id
    // 'jti' is the token id
    claims: { jti, sub: idClaims.user_id },
    id_claims: { familiar_name: idClaims.familiar_name },
    access_claims: { role },
  });
}

async function exchangeHandler(req, res) {
  // 'jws' refers to the signed jwt cookie
  // 'jti' is the token id
  let jti = req.authn.jws.claims.jti;

  let session = await db.Session.find({ id: jti, revoked_at: null });
  if (!session) {
    throw new Error("revoked auth");
  }

  // 'sub' is "subject" a.k.a. user_id
  let sub = req.authn.jws.claims.sub;
  let user = await db.User.find({ id: sub });
  let id_claims;
  let access_claims;

  switch (req.authn.strategy) {
    case "refresh":
      // Generally the 'refresh' is for id_tokens,
      // but could also refresh other tokens here as well.
      id_claims = { jti, sub, familiar_name: idClaims.familiar_name };
      break;
    case "exchange":
      // Generally the 'exchange' is for access_tokens,
      // but could also refresh other tokens here as well.
      let { role = "user" } = await db.Account.getRole({ user_id: sub });
      access_claims = { jti, role };
      break;
    default:
      throw new Error("unsupported login strategy");
  }

  await res.issue({ id_claims, access_claims });
}

// Note: this will be called whenever an id cookie is destroyed
// (including when it is replaced by another login cookie)
async function logoutHandler(req) {
  let jti = req.authn.jwt.claims.jti;
  // Revoke rather than delete to keep an audit trail
  db.Session.patch({ id: jti, revoked_at: new Date() });
}
```

# Node API

## Errors

| Name                         | Status | Message (truncated)                              |
| ---------------------------- | ------ | ------------------------------------------------ |
| E_CODE_INVALID               | 400    | That verification code isn't valid. It might ... |
| E_CODE_REDEEMED              | 400    | That verification code has already been used ... |
| E_CODE_RETRY                 | 400    | That verification code isn't correct. It may ... |
| E_OIDC_UNVERIFIED_IDENTIFIER | 400    | You cannot use the identifier associated with... |
| E_SESSION_INVALID            | 400    | Missing or invalid cookie session. Please log... |
| E_SUSPICIOUS_REQUEST         | 400    | Something suspicious is going on - as if ther... |
| E_SUSPICIOUS_TOKEN           | 400    | Something suspicious is going on - the given ... |
| E_DEVELOPER_ERROR            | 422    | Oops! One of the programmers made a mistake. ... |
| " -> WRONG_TOKEN_TYPE        | 422    | the HTTP Authorization was not given in a sup... |
| " -> MISSING_TOKEN           | 401    | the required authorization token was not prov... |

## Authentication (Issuer) Middleware

```js
let Auth3000 = require("auth3000");

let sessionMiddleware = Auth3000(issuer, privkey, {});

sessionMiddleware.login(loginHandler);

sessionMiddleware.oidc({ "accounts.google.com": { clientId: "xxxx" } });
sessionMiddleware.oauth2({
  "github.com": { clientId: "xxxx", clientSecret: "zzzz" },
});
sessionMiddleware.challenge({ notify, store, maxAge: "24h", maxAttempts: 5 });
sessionMiddleware.credentials();

sessionMiddleware.logout(function (req) {
  let jti = req.authn.jws.claims.jti;
  // invalidate server-side session
});

sessionMiddleware.router();
sessionMiddleware.wellKnown();
```

```js
function loginHandler(req, res) {
  let { strategy, email, iss, ppid } = req.authn;

  await res.issue({
    claims: { sub: "<user-id>" },
    id_claims: { nickname: "<display-name>" },
    access_claims: { role: "<optional-role>" },
    refresh_claims: {
      /*overrides*/
    },
  });
}
```

```txt
req.authn     - holds all strategy-specific data

strategy      - the name of the authentication method
                (each strategy receives different arguments)

  - oidc        - 3rd party login via OAuth / OpenID Connect
                  ex: Google Sign In, Facebook Connect, etc
                Uses: { email, iss, ppid, oidc_claims } = req.authn
                Sends: Set-Cookie (refresh_token), id_token

  - oauth2      - 3rd party login via OAuth2 (bespoke profile data)
                  ex: GitHub
                Uses: { email, iss, id, oauth_profile } = req.authn
                Sends: Set-Cookie (refresh_token), id_token

  - challenge   - send a code to the user (via email or phone)
                  and ask them to enter it, or click a link
                  a.k.a. Magic Link, Password Reset, Verification
                  Code, etc
                Uses: req.body
                Sends: Set-Cookie (refresh_token), id_token

  - credentials - get (typically) a username & password  from
                  the user and validate it on your end
                Uses: { email, phone } = req.authn
                Sends: Set-Cookie (refresh_token), id_token

  - exchange    - exchange an ID token for an access token
                Uses: req.body, { jws } = req.authn
                Sends: access_token

  - refresh     - exchange a Cookie with a Refresh Token for an
                  id and/or access token
                Uses: req.body, { jws } = req.authn
                Sends: id_token


email         - a verified email address
                ex: john@example.com
              Provided by: oidc, challenge

iss           - the base url of an issuer
                (where `.well-known/openid-configuration` is found)
                ex: https://example.com
              Provided by: oidc, challenge

ppid          - a pairwise id for the user, specific to your oidc client id
                ex: xxxxxxxx
              Provided by: oidc

oidc_claims   - these are the claims present on the oidc provider's token -
                they may be standard claims such as `nickname`, `gender`,
                and `picture`, etc, or bespoke custom values specific to
                that provider.
                ex: { nickname: "AJ", picture: "https://example.com/aj.jpg" }
              Provided by: oidc

jws           - a verified, decoded jwt with headers, claims, and signature
                (from the refresh cookie or Authorization: Bearer)
              Provided by: exchange, refresh

req.body      - whatever you send in - completely up to you how to use it
```

What you return defines which tokens will be sent

```txt
claims          - defaults that apply to any granted tokens, which will be over-
                  written by other values

id_claims       - will cause an ID Token to be granted with the contained claims

access_claims   - will cause an Access Token to be granted with the contained claims

refresh_claims  - IF a refresh token NOT USED, except for on the will cause an Access Token to be granted with the contained claims

Common claims include:

  - sub           - Subject. The ppid or id of the user, bot, or bearer of the token.

  - exp           - Human readable expiry age, such as '300s', '60m', '12h', or '30d',
                    which can be used to extend or shorten the life of each token
                    indvidually.

  - jti           - A (random) identifier for the token, useful for revoking tokens.

  - nickname      - A display name for the user.

  - role(s)       - A group such as 'admin' or 'owner' to enable broad permissions without
    non-standard    looking up the permissions of the individual user.
    access-only
```

## Challenge (Magic Link)

Exposed so that you can use the challenge response outside of the login process.

```js
let verifier = require("@root/auth3000/verifier").create({
  maxAge: "24h",
  maxAttempts: 5,

  // important
  notify: async function (req) {},
  store: {
    get: async function (id) {},
    set: async function (id, val) {},
  },

  // optional
  coolDownMs: 250,
  idByteCount: 4,
  idEncoding: "base64",
  maxAge: "24h",
  maxAttempts: 5,
  receiptByteCount: 16,
  receiptEncoding: "base64",

  // important, but defaults will be set from auth3000 if not provided
  iss: "",
  secret: "",
  authnParam: "authn",
});

auth3000.challenge(verifier);
```

```js
let c = verifier.create({ type: "email", value: "me@example.com" }, req, opts);

verifier.get(id);
verifier.set(id, c);
verifier.notify(c, req, opts);

// `code` is optional. If provided it will count against the maxAttempts
verifier.check(id, code, req);
verifier.redeem(id, code, req);
verifier.exchange(id, receipt, req);

// used by auth3000 to set `iss`, `secret`, and `authnParam`
verifier.setDefaults({
  iss: iss,
  secret: secret,
  authParam: authParam,
});
```

### store (for Verification)

The store is a simple Key/Value store. You could use any database, a file, or
use the default (in-memory) if you're developing locally.

```js
// The store keeps track of state information for the
// challenge verification. The values are intended to
// be opaque.

// `key`   - a string identifier
// `value` - a JSON object (you should stringify this)
await store.set(key, value);

await store.get(key);
```

### notify (for Verification)

The notify function is intended to be used for:

- Email Verification
- Phone Number Verification
- Magic Link Login
- Forgot Password

```js
function notify(req) {
  let { type, value, code, id, jws, issuer } = req.authn;
  // type = "email"
  // value = "john@example.com"

  // What you should do:
  //
  //   1. Construct a URL with the ID and Secret
  //      (or at least a page where the user can enter the code)
  //
  //   2. Send a message via Email, SMS, or whatever you want to verify
  //      (must provide 'code', 'id' is somewhat optional)
  //
  //   3. `req.body` will have whatever you sent
  //      (I use 'req.body.template' to send different messages for
  //       forgot password, email verification, etc...)

  await sendMessage(
    req.body.template,
    `${issuer}/my-login?id=${id}&code=${code}`
  );

  return null;
}
```

```txt
type    - the type of identifier you wish to verify
          ex: 'email' or 'phone' (completely arbitrary, up to you)

value   - the identifier itself
          ex: 'john@example.com' or '+18005551234'

code    - the random string required to finalize the verification
          ex: AB34-EF78

id      - public id used for checking status of verification
          ex: aBc1-3

issuer  - what you provided as your base own url
          ex: http://localhost:3000
```

### Verifier (Consumer) Middleware

The verifier middleware checks that the token in `Authorization: Bearer <token>`
has a valid signature by a trusted issuer, decodes it, and populates `req.user`
and `req.jws` accordingly.

```js
let verify = require("auth3000/middleware/");

app.use(
  "/api",
  verify({ iss: issuer, optional: true, userParam: "user", jwsParam: "jws" })
);
```

These are the options that can be passed to `verify`:

```txt
iss         - the base url of the token issuer
              ex: https://myapp.example.com

optional    - token is not required
              (but invalid tokens will be rejected)

jwsParam    - the verified, decoded jwt will be available at `req[jwsParam]`
              (default: 'jws' for `req.jws`, false to disable)

userParam    - the `jws.claims` will be available at `req[userParam]`
              (default: 'user' for `req.user`, false to disable)
```

`req.user` and `req.jws` will be available on all subsequent middleware.

```js
app.use("/api/debug/inspect", function (req, res) {
  console.log(req.user);
  console.log(req.jws);
  res.json({ jws: req.jws, user: req.user });
});
```

There are a variety of standard options, which you can read about in
[the OIDC spec](https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims),
as well as your own custom "claims" as provided by you in `loginHandler`.

```txt
req.user    - the same as req.jws.claims, which include what you passed back
              in `loginHandler`, for example:
              {
                jti: "xxxx",
                iat: 1622849000, // seconds since unix epoch
                exp: 1622849600, // seconds since unix epoch
                //
                // + whatever you passed back in 'claims' for this token type
                //
                // Although claims is arbitrary, there is a set of Standard Claims:
                // https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
                //
              }

req.jws     - JWS is the name for a decoded JWT. It looks like this:
              {
                header: {
                  alg: "ES256",
                  kid: "xxxxxxxx",
                  typ: "JWT",
                },
                claims: {
                  // see req.user above
                },
                protected: "<url-safe-base64-encoded-header>",
                payload: "<url-safe-base64-encoded-claims>",
                signature: "<verified-hash>",
              }
```

## Generating Secrets & Private Keys

Create a random string:

```bash
# OpenSSL
openssl rand -base64 16

# Or /dev/urandom
xxd -l16 -ps /dev/urandom
```

Create a private key:

```bash
curl https://webinstall.dev/keypairs | bash
keypairs gen --key key.jwk.json --pub pub.jwk.json
```

Or for converting PEM keys, use
[keypairs.js](https://www.npmjs.com/package/keypairs-cli):

```bash
npm install --global keypairs-cli
keypairs ./privkey.pem
```

```bash
#!/bin/bash

keypairs gen > key.jwk.json 2> pub.jwk.json
echo "PRIVATE_KEY='./key.jwk.json'" >> .env
```

Create a server-to-server pre-shared token

```bash
# sign a token to be valid for 50 years
keypairs sign --exp '1577880000s' ./key.jwk.json '{ "sub": "admin" }'
```

```bash
#!/bin/bash

SERVER_TOKEN="$(keypairs sign --exp '1577880000s' ./key.jwk.json '{ "iss": "http://localhost:3000", "sub": "admin" }' 2>/dev/null )"
echo "SERVER_TOKEN=${SERVER_TOKEN}" >> .env
```

# HTTP Session API

## POST /api/authn/session

Request

```txt
POST /api/auth/session
Authentication: Basic <base64hash>
```

```json
{
  "user": "john.doe@gmail.com",
  "pass": "secret",
  "account": 0
}
```

Response

```txt
200 OK
Set-Cookie: xxxxx

```

```json
{
  "id_token": "xxxx.yyyy.zzzz",
  "access_token": "xxxx.yyyy.zzzz"
}
```

## POST /api/authn/session/oidc/accounts.google.com

Request

```txt
POST /api/authn/session/oidc/accounts.google.com
Authorization: Bearer <token>
```

```json
{
  "account": 0
}
```

Response

```txt
200 OK
Set-Cookie: xxxxx

```

```json
{
  "id_token": "xxxx.yyyy.zzzz",
  "access_token": "xxxx.yyyy.zzzz"
}
```

## POST /api/authn/refresh

Request

```txt
POST /api/authn/refresh
Cookie: xxxxx

```

```json
{ "account": 0 }
```

Response

```txt
200 OK
Set-Cookie: xxxxx

```

```json
{
  "id_token": "xxxx.yyyy.zzzz",
  "access_token": "xxxx.yyyy.zzzz"
}
```

## POST /api/authn/exchange

Request

```txt
POST /api/authn/exchange
Authorization: Bearer <token>

```

```json
{ "account": 0 }
```

Response

```txt
200 OK

```

```json
{
  "access_token": "xxxx.yyyy.zzzz"
}
```

## DELETE /api/authn/session

Request

```txt
DELETE /api/auth/session
Cookie: xxxxx
```

Response

```txt
200 OK
Set-Cookie: <empty-and-expired-cookie-value>

```

```json
{
  "success": true
}
```

# HTTP Magic Link (verification) API

This is complex because there are at least 3 components:

- API for creating & exchanging verification tokens
- `notify` function for sending verification tokens / links
- Browser interaction for 3 tabs (login, email, verification) on perhaps 2
  devices

A possible flow for that:

1. Order Challenge
   - Login via Email
   - Reset Password
   - Failed Login via Password Attempt
   - Email verification (already logged in - such as the first login)
2. Click Link (email) or Enter Code (phone) to Complete Verification
   - May be opened on the original device, or a different device
3. Login on verified devices
   - When verifying in a single browser
     - Original tab will be in background, it should display "you may close this
       tab" (and auto-close if possible)
     - Verification tab should ask "Remember this Device for 30 days?" and
       continue to login
   - When verifying between two different browsers
     - Original tab should present "Remember this Device for 30 days?" and login
     - Verification tab should ask "Continue to App?" and then "Remember this
       Device for 30 days?"

## POST /api/authn/challenge/order

This should call `notify` which should send an email according to a template.

Request

```txt
POST /api/authn/challenge/order
```

```json
{
  "type": "email",
  "value": "john.doe@gmail.com"
}
```

Response

```txt
200 OK

```

```js
{
  "success": "true",
  //"retry_after": "2021-06-01T13:59:59.000Z",
  "receipt": "xxxx.yyyy.zzzz"
}
```

## POST /api/authn/challenge/finalize

Request

```txt
POST /api/auth/challenge/finalize
```

```json
{
  "id": "abc123",
  "code": "AB34-EF78"
}
```

Response

```txt
200 OK

```

(either a retry, an `id_token`, or an actual error)

```json
{
  "id_token": "xxxx.yyyy.zzzz",
  "access_token": "xxx2.yyy2.zzz2"
}
```

## GET /api/authn/challenge

Request

Use either `receipt` or `code`.

```txt
GET /api/auth/challenge
    ?id=abc123
    &receipt=yyyyyyyy
    &code=AB34-EF78
```

Response

```txt
200 OK

```

Either `verified_at` will be empty, or it will have a value.

```json
{
  "success": true,
  "status": "pending",
  "ordered_at": "2021-06-20T13:30:59Z",
  "ordered_by": "Chrome/x.y.z Windows 10",
  "verified_at": "",
  "verified_by": ""
}
```

```json
{
  "success": true,
  "status": "valid",
  "ordered_at": "2021-06-20T13:30:59Z",
  "ordered_by": "Chrome/x.y.z Windows 10",
  "verified_at": "2021-06-20T13:31:42Z",
  "verefied_by": "Safari/x.y iPhone iOS 17"
}
```

## POST /api/authn/challenge/exchange

Request

```txt
POST /api/auth/challenge/exchange
```

```json
{
  "id": "abc123",
  "receipt": "yyyyyyyy"
}
```

Response

```txt
200 OK

```

(either a retry, an `id_token`, or an actual error)

```json
{
  "success": true,
  "status": "valid",
  "id_token": "xxxx.yyyy.zzzz",
  "access_token": "xxx2.yyy2.zzz2"
}
```

# Resources

- [Live Recordings](https://www.youtube.com/playlist?list=PLxki0D-ilnqYmidRxvrQoF2jX67wH5OS0)
  of the making of this project
- [Express Cookies Cheat Sheet](https://github.com/BeyondCodeBootcamp/beyondcodebootcamp.com/blob/main/articles/express-cookies-cheatsheet.md)
- [How to add Google Sign In](https://therootcompany.com/blog/google-sign-in-javascript-api/)
- [How many Bits of Entropy per Character in...](https://therootcompany.com/blog/how-many-bits-of-entropy-per-character/)
