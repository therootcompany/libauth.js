# auth3000

> Modern, OpenID Connect compatible authentication.

```js
// Authenticate Users
let Auth3000 = require("auth3000");
let sessionMiddleware = Auth3000(issuer, secret, privkey, {
  oidc: { google: { clientId: "xxxx" } },
  getClaims: function (req) {
    let { strategy, email, iss, ppid } = req.authn;

    switch (strategy) {
      case "oidc":
        let claims = await Users.find({ email: email });
        return { claims };
      default:
        throw new Error("unsupported auth strategy");
    }
  },
});

// /api/authn/{session,refresh,exchange,challenge,logout}
app.use("/", sessionMiddleware);
```

```js
// Verify Tokens
let verify = require("auth3000/middleware/");
app.use("/api", verify({ iss: issuer, optional: true }));

app.use("/api/debug/inspect", function (req, res) {
  res.json({
    success: true,
    user: req.user || null,
  });
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
- [x] `credentials` - bespoke, specified by you (probably username/password)
- [x] `challenge` - a.k.a. "verification email" or "Magic Link" ( or SMS code)
- [x] `refresh` - to refresh an `id_token` via refresh token cookie
- [ ] `jwt` - to exchange an `id_token` for an `access_token`
- [ ] `exchange`
- [ ] `apikey`

### Live Code Project

This code was written live, in front of a combined YouTube & Twitch audience.

If you want to see all 40+ hours of painstaking coding... here ya go:

<https://www.youtube.com/playlist?list=PLxki0D-ilnqYmidRxvrQoF2jX67wH5OS0>

# Usage

```js
let issuer = "http://localhost:3000";
let secret = crypto.randomBytes(16).toString("base64");
let privkey = fs.readFileSync("privkey.jwk.json", "utf8"); // or privkey.pem

let sessionMiddleware = require("auth3000")(issuer, secret, privkey, {
  getClaims,
  notify,
});

function getClaims(req) {
  let { strategy, email } = req.authn;
  let idClaims;
  let accessClaims;

  switch (strategy) {
    case "oidc":
      idClaims = await Users.find({ email: email, iss: iss, ppid: ppid });
      break;
    case "credentials":
      idClaims = await Users.findAndVerifyPassword({
        user: req.body.user,
        pass: req.body.pass,
      });
      break;
    case "challenge":
      idClaims = await Users.find({ email: email });
      break;
    default:
      throw new Error("unsupported login strategy");
  }

  let { sub = "user_id", familiar_name = "Demo User" } = idClaims;
  let { role = "user" } = await User.getRole({ user_id: sub });

  // You can return a simple id_token (just profile info, no privileges)
  // or an access_token (including roles, permissions, etc)
  return {
    id_claims: { sub, familiar_name },
    access_claims: { sub, role },
  };
}

// /api/authn/{session,refresh,exchange,challenge,logout}
app.use("/", sessionMiddleware);

// /.well-known/openid-configuration
// /.well-known/jwks.json
app.use("/", sessionMiddleware.wellKnown);

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
```

```bash
curl https://webinstall.dev/keypairs | bash
keypairs gen --key key.jwk.json --pub pub.jwk.json
```

# Node API

## Authentication (Issuer) Middleware

```js
let Auth3000 = require("auth3000");
let sessionMiddleware = Auth3000(issuer, secret, privkey, {
  oidc: { google: { clientId: "xxxx" } },
  getClaims,
});
```

### notify (for Verification)

The notify function is intended to be used for:

- Email Verification
- Phone Number Verification
- Magic Link Login
- Forgot Password

```js
function notify(req) {
  let {
    // ex: email | phone
    type,
    // ex: john@example.com | +1 555-555-1234
    value,
    // ex: A78D-E211 - what you use to finalize the verification
    secret,
    // random string used for checking status of verification
    id,
    // ex: http://localhost:3000 - what you provided as your base own url
    issuer,
  } = req.authn;

  // What YOU do:
  // Construct and send and email or SMS message to your user
  // with a URL that they click where you take the parameters
  // and send them back to the API.
  await sendMessage(
    req.body.template,
    `${issuer}/my-login?id=${id}&secret=${secret}`
  );

  return null;
}
```

### Verifier (Consumer) Middleware

```js
let verify = require("auth3000/middleware/");

app.use(
  "/api",
  verify({
    iss: issuer,
    optional: true,
    userParam: "user",
    jwsParam: "jws",
  })
);
```

```txt
iss         - the base url of the token issuer
              ex: https://accounts.google.com

optional    - token is not required
              (but invalid tokens will be rejected)

jwsParam    - the verified, decoded jwt will be available at `req[jwsParam]`
              (default: 'jws' for `req.jws`, false to disable)

userParam    - the `jws.claims` will be available at `req[userParam]`
              (default: 'user' for `req.user`, false to disable)
```

```js
app.use("/api/debug/inspect", function (req, res) {
  console.log(req.user);
  console.log(req.jws);
  res.json({ jws: req.jws, user: req.user });
});
```

```txt
req.user    - the same as req.jws.claims, which include what you passed back
              in `getClaims`, for example:
              {
                jti: "xxxx",
                iat: 1622849000, // seconds since unix epoch
                exp: 1622849600, // seconds since unix epoch
                //
                // + whatever you passed back in 'claims' for this token type
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

## POST /api/authn/session/oidc/google.com

Request

```txt
POST /api/authn/session/oidc/google.com
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
  "secret": "AB34-EF78"
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

Use either `receipt` or `secret`.

```txt
GET /api/auth/challenge
    ?id=abc123
    &receipt=yyyyyyyy
    &secret=AB34-EF78
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
  "id_token": "xxxx.yyyy.zzzz"
  "access_token": "xxx2.yyy2.zzz2"
}
```

# Resources

- [Live Recordings](https://www.youtube.com/playlist?list=PLxki0D-ilnqYmidRxvrQoF2jX67wH5OS0)
  of the making of this project
- [Express Cookies Cheat Sheet](https://github.com/BeyondCodeBootcamp/beyondcodebootcamp.com/blob/main/articles/express-cookies-cheatsheet.md)
- [How to add Google Sign In](https://therootcompany.com/blog/google-sign-in-javascript-api/)
- [How many Bits of Entropy per Character in...](https://therootcompany.com/blog/how-many-bits-of-entropy-per-character/)
