# NOTE

I made this public because I'm live-streaming the creation of it, not because
it's ready for consumption:

LIVE CODING Recordings:
https://www.youtube.com/playlist?list=PLxki0D-ilnqYmidRxvrQoF2jX67wH5OS0

# auth3000

Yet another auth library by AJ

Exchange Long-Lived (24h - 90d) Refresh Token (in Cookie) for Short-Lived (15m -
24h) Session Token.

Provides a framework for handling the following strategies:

- [x] `oidc` - ex: Facebook Connect, Google Sign In, Microsoft Live
- [x] `credentials` - bespoke, specified by you (probably username/password)
- [x] `challenge` - a.k.a. "verification email" or "Magic Link" ( or SMS code)
- [x] `refresh` - to refresh an `id_token` via refresh token cookie
- [ ] `jwt` - to exchange an `id_token` for an `access_token`
- [ ] `exchange`
- [ ] `apikey`

# Usage

```js
let issuer = "http://localhost:3000";
let secret = crypto.randomBytes(16).toString("base64");
let privkey = fs.readFileSync("privkey.jwk.json", "utf8"); // or privkey.pem

let sessionMiddleware = require("auth3000/lib/session.js")(
  issuer,
  secret,
  privkey,
  { getClaims, notify }
);

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

// /api/authn/{session,refresh,exchange}
app.use("/", sessionMiddleware);

// /.well-known/openid-configuration
// /.well-known/jwks.json
app.use("/", sessionMiddleware.wellKnown);
```

```js
function getClaims(req) {
  let;
}
```

```bash
curl https://webinstall.dev/keypairs | bash
keypairs gen --key key.jwk.json --pub pub.jwk.json
```

# Verification

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

```bash
#!/bin/bash

PRIVATE_KEY="$(keypairs gen 2>/dev/null)"
echo "PRIVATE_KEY='${PRIVATE_KEY}'" >> .env
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

# Session API

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

# Magic Link API

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

## POST /api/authn/challenge/issue

This should call `notify` which should send an email according to a template.

Request

```txt
POST /api/authn/challenge/issue
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
  "challenge_token": "xxxx.yyyy.zzzz"
}
```

## POST /api/authn/challenge/complete

Request

```txt
POST /api/auth/challenge/complete
```

```json
{
  "verification_token": "xxxx.yyyy.zzzz"
}
```

Response

```txt
200 OK

```

(either a retry, an `id_token`, or an actual error)

```json
{
  "id_token": "xxxx.yyyy.zzzz"
}
```

## GET /api/authn/challenge

Request

Use either `challenge_token` or `secret`.

```txt
GET /api/auth/challenge
    ?challenge_token=xxxx.yyyy.zzzz
    &secret=xxyyzz
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
  "ordered_by": "Safari/x.y iPhone iOS 17"
}
```

## POST /api/authn/challenge/exchange

Request

```txt
POST /api/auth/challenge/claim
Authorization: Bearer <challenge_token>
```

```json
{
  "challenge_token": "xxxx.yyyy.zzzz"
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
}
```

# Resources

- [Live Recordings](https://www.youtube.com/playlist?list=PLxki0D-ilnqYmidRxvrQoF2jX67wH5OS0)
  of the making of this project
- [Express Cookies Cheat Sheet](https://github.com/BeyondCodeBootcamp/beyondcodebootcamp.com/blob/main/articles/express-cookies-cheatsheet.md)
- [How to add Google Sign In](https://therootcompany.com/blog/google-sign-in-javascript-api/)
