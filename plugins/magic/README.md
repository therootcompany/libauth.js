# @libauth/magic

"Magic Link" Sign In for LibAuth.js (for Email links & SMS codes)

Also known as _Challenge-Response_ or _Second Factor_ authentication - meaning
you can send the answer to the challenge however you like.

Note: We're against 🚫 🧙‍♂️ wizardry. "Magic Link" is a technical term referring
to the UX pattern used by Medium, Slack, and many others.

## Install

```bash
npm install --save libauth @libauth/magic
```

## Usage

Magic Links can be distributed through Email, SMS, and QR Codes.

The demo uses Command Line output, but you'll need to use a service - such as
Postmark, Mailgun, or Twilio - to actually send "magic" auth links to your
users.

### Protecting your Credentials

Don't commit your Salt or email or SMS credentials to code.

Rather use a `.env` for local development and servers, or the _Environment
Configuration_ (or _Secrets Vault_) of your CI/CD service.

For example:

`.env`:

```bash
# Generated with crypto.randomBytes(16).toString('hex')
MAGIC_SALT='xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'

# Found at https://account.postmarkapp.com/servers/{ID}/streams/{NAME}/settings
POSTMARK_SERVER_TOKEN=xxxxxxxx-xxxx-4xxx-8xxx-xxxxxxxxxxxx
```

```js
require("dotenv").config({ path: ".env" });
```

### Example with Express

The goal of LibAuth is

- 🚫 🪄 to minimize _magic_ (anything difficult to understand or configure)
- 👍 🎮 and _maximize control_ \
  without sacrificing
- ✅ 🏪 _ease-of-use_ or convenience

To do this we require more ✂️ 📋 copy-and-paste boilerplate than other auth
libraries - with the upside is that it's all just normal, easy-to-replace 🥞
_middleware_ - hopefully nothing 🤔 unexpected or ⛓ constraining.

```js
// MAGIC LINK SIGN IN
// See https://git.rootprojects.org/root/libauth-magic.js

let magicLink = libauth.challenge(
  require("@libauth/magic")({
    codes: require("@libauth/magic/generator").create({
      magicSalt: process.env.MAGIC_SALT,
    }),
    store: {
      get: async function ({ id }) {
        return await DB.MagicLinks.get(orderId);
      },
      set: async function (challenge) {
        await DB.MagicLinks.set(challenge);
      },
    },
  }),
);
```

```js
// Create an "order", and send the notification
app.post(
  "/api/authn/challenge",
  magicLink.setParams,
  MyDB.getUserByMagicValue,
  magicLink.generateChallenge,
  magicLink.saveChallenge,
  MyNotifier.notify,
  magicLink.sendReceipt,
);

// Check the status of the order
app.get(
  "/api/authn/challenge/:id",
  magicLink.setParams,
  magicLink.getChallenge,
  magicLink.checkStatus,
  magicLink.sendStatus,

  // Error Handler
  magicLink.captureError,
  magicLink.saveChallenge,
  magicLink.releaseError,
  libauth.sendError(),
);

// Exchange the the code (or receipt) for a new session and token
app.post(
  "/api/session/challenge",

  // Handle challenge response
  magicLink.setParams,
  magicLink.getChallenge,
  magicLink.verifyResponse,
  magicLink.saveChallenge,

  // Handle success
  MyDB.getUserByIdentifier,
  libauth.newSession(),
  libauth.setClaims(),
  libauth.setCookie(),
  MyDB.updateSessionId,
  libauth.setCookieHeader(),
  libauth.setTokens(),
  libauth.sendTokens(),

  // Handle error
  magicLink.captureError,
  magicLink.saveChallenge,
  magicLink.releaseError,
  libauth.sendError(),
);

// Invalidate the auth challenge
app.delete(
  "/api/authn/challenge/:id",
  magicLink.setParams,
  magicLink.cancelChallenge,
  magicLink.saveChallenge,
  magicLink.sendStatus,
);
```

### User Middleware

The things that LibAuth **can't** do for you:

1. Get your user from your database
2. Decide what details about the user (_claims_) to include in the token
3. Invalidate a user's device in your database

_Claims_ is a standard term meaning the standard (or private or custom)
properties of a token which describe the user.

The list of Standard OIDC Claims for ID Tokens:
<https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims>

```js
MyDB.getUserClaimsByOidcEmail = async function (req, res, next) {
  // get a new session
  let user = await DB.get({ email: req.authn.email });

  // "claims" is the standard term for "user info",
  // and includes pre-defined values such as:
  let idClaims = {
    // "Subject" the user ID or Pairwise ID (required)
    sub: user.id,

    // ID Token Info (optional)
    given_name: user.first_name,
    family_name: user.first_name,
    picture: user.photo_url,
    email: user.email,
    email_verified: user.email_verified_at || false,
    zoneinfo: user.timezoneName,
    locale: user.localeName,
  };

  let accessClaims = {
    // "Subject" the user ID or Pairwise ID (required)
    sub: user.id,
  };

  libauth.set(req, { idClaims: claims, accessClaims: accessClaims });
};
```

Some claims will be added for you unless provided or set to `false`:

| Claim       | Description                             |
| ----------- | --------------------------------------- |
| `iss`       | Issuer (where public keys can be found) |
| `iat`       | Issued At (defaults to current time)    |
| `jti`       | JWT ID (used for tracking session)      |
| `exp`       | Expiration (ex: '15m' or '2h')          |
| `auth_time` | The original time of authentication     |

Unless otherwise defined, the `refreshClaims` will be computed to contain the
same `sub`, `iss`, `iat`, `aud`, `auth_time`, `azp`, and jti` as the computed
idClaims, after the above claims are added.

Note: In libauth `jti` is expected to be used to invalidate Refresh Tokens and
associated ID and Access Tokens before their given _Expiration_.

## Developing

Rather than a _monorepo_, we've chosen the _git submodule_ approach (to keep
`git tag`s distinct, etc).

```bash
git clone https://github.com/therootcompany/libauth.js
```

```bash
pushd ./libauth.js/
git submodule init
git submodule update
```

```bash
pushd ./plugins/magic/
git checkout main
```
