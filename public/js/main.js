(async function main() {
  "use strict";

  // from env.js
  let ENV = window.ENV;

  // scheme => 'https:'
  // host => 'localhost:3000'
  // pathname => '/api/authn/session/oidc/google.com'
  let baseUrl = document.location.protocol + "//" + document.location.host;

  // AJQuery
  function $(sel) {
    return document.body.querySelector(sel);
  }

  function noop() {}

  function die(err) {
    console.error(err);
    window.alert(
      "Oops! There was an unexpected error on the server.\nIt's not your fault.\n\n" +
        "Technical Details for Tech Support: \n" +
        err.message
    );
    throw err;
  }

  function querystringify(options) {
    return Object.keys(options)
      .filter(function (key) {
        return (
          "undefined" !== typeof options[key] &&
          null !== options[key] &&
          "" !== options[key]
        );
      })
      .map(function (key) {
        // the values must be URI-encoded (the %20s and such)
        return key + "=" + encodeURIComponent(options[key]);
      })
      .join("&");
  }

  function generateOidcUrl(
    oidcBaseUrl,
    client_id,
    redirect_uri,
    scope,
    login_hint
  ) {
    // a secure-enough random state value
    // (all modern browsers use crypto random Math.random, not that it much matters for a client-side state cache)
    var rnd = Math.random().toString();
    // transform from 0.1234... to hexidecimal
    var state = parseInt(rnd.slice(2).padEnd(16, "0"), 10)
      .toString(16)
      .padStart(14, "0");
    // response_type=id_token requires a nonce (one-time use random value)
    // response_type=token (access token) does not
    var nonceRnd = Math.random().toString();
    var nonce = parseInt(nonceRnd.slice(2).padEnd(16, "0"), 10)
      .toString(16)
      .padStart(14, "0");
    var options = { state, client_id, redirect_uri, scope, login_hint, nonce };
    // transform from object to 'param1=escaped1&param2=escaped2...'
    var params = querystringify(options);
    return oidcBaseUrl + "?response_type=id_token&access_type=online&" + params;
  }

  function generateOauth2Url(
    authorize_url,
    client_id,
    redirect_uri,
    scopes,
    login_hint
  ) {
    // <!-- redirect_uri=encodeURIComponent("https://beyondcode.duckdns.org/api/webhooks/oauth2/github") -->
    // <!-- scope=encodeURIComponent("read:user%20user:email") -->
    // <a href="https://github.com/login/oauth/authorize?client_id=0b7cdfa2fde2f019a3b5&redirect_uri=https%3A%2F%2Fbeyondcode.duckdns.org%2Fapi%2Fwebhooks%2Foauth2%2Fgithub&scope=read:user%20user:email&state=1234567890&allow_signup=true&login=">

    // a secure-enough random state value
    // (all modern browsers use crypto random Math.random, not that it much matters for a client-side state cache)
    var rnd = Math.random().toString();
    // transform from 0.1234... to hexidecimal
    var state = parseInt(rnd.slice(2).padEnd(16, "0"), 10)
      .toString(16)
      .padStart(14, "0");
    var login = login_hint;
    var scope = scopes.join(" ");
    var options = {
      state,
      client_id,
      redirect_uri,
      scope,
      login: login_hint,
    };
    var params = querystringify(options);
    return authorize_url + "?allow_signup=true&" + params;
  }

  // because JavaScript's Base64 implementation isn't URL-safe
  function urlBase64ToBase64(str) {
    var r = str % 4;
    if (2 === r) {
      str += "==";
    } else if (3 === r) {
      str += "=";
    }
    return str.replace(/-/g, "+").replace(/_/g, "/");
  }

  function urlBase64ToJson(u64) {
    var b64 = urlBase64ToBase64(u64);
    var str = atob(b64);
    return JSON.parse(str);
  }

  async function attemptRefresh() {
    let resp = await window
      .fetch(baseUrl + "/api/authn/refresh", { method: "POST" })
      .catch(noop);
    if (!resp) {
      return;
    }
    return await resp.json().catch(die);
  }

  async function doStuffWithUser(result) {
    if (!result.id_token && !result.access_token) {
      window.alert("No token, something went wrong.");
      return;
    }
    $(".js-logout").hidden = false;
    window.alert("Congrats! You win! (check the console for your token)");
    let resp = await window
      .fetch(baseUrl + "/api/dummy", {
        method: "GET",
        headers: {
          Authorization: "Bearer " + (result.id_token || result.access_token),
        },
      })
      .catch(noop);
    if (!resp) {
      return;
    }
    let dummies = await resp.json().catch(die);
    console.info("Dummies:");
    console.info(dummies);
  }

  function parseQuerystring(querystring) {
    var query = {};
    querystring.split("&").forEach(function (pairstring) {
      var pair = pairstring.split("=");
      var key = pair[0];
      var value = decodeURIComponent(pair[1]);

      query[key] = value;
    });
    return query;
  }

  async function parseJwt(jwt) {
    var parts = jwt.split(".");
    var jws = {
      protected: parts[0],
      payload: parts[1],
      signature: parts[2],
    };
    jws.header = urlBase64ToJson(jws.protected);
    jws.claims = urlBase64ToJson(jws.payload);
    return jws;
  }

  async function init() {
    $(".js-logout").hidden = true;
    $(".js-social-login").hidden = true;

    // TODO rename to google
    var googleSignInUrl = generateOidcUrl(
      "https://accounts.google.com/o/oauth2/v2/auth",
      ENV.GOOGLE_CLIENT_ID,
      ENV.GOOGLE_REDIRECT_URI,
      "email profile"
      // "JOHN.DOE@EXAMPLE.COM"
    );
    $(".js-google-oidc-url").href = googleSignInUrl;

    var githubSignInUrl = generateOauth2Url(
      "https://github.com/login/oauth/authorize",
      ENV.GITHUB_CLIENT_ID,
      ENV.GITHUB_REDIRECT_URI,
      ["read:user", "user:email"]
    );
    $(".js-github-oauth2-url").href = githubSignInUrl;

    $(".js-logout").addEventListener("click", async function (ev) {
      ev.preventDefault();
      ev.stopPropagation();

      let resp = await window
        .fetch(baseUrl + "/api/authn/session", {
          method: "DELETE",
        })
        .catch(die);
      let result = await resp.json().catch(die);
      window.alert("Logged out!");
      init();
    });

    var querystring = document.location.hash.slice(1);
    var query = parseQuerystring(querystring);
    if (query.id_token) {
      completeOidcSignIn(query);
      return;
    }
    if (query.access_token && "bearer" === query.token_type) {
      completeOauth2SignIn(query);
      return;
    }

    let result = await attemptRefresh();
    console.info("Refresh Token: (may be empty)");
    console.info(result);

    if (result.id_token || result.access_token) {
      await doStuffWithUser(result);
      return;
    }

    $(".js-social-login").hidden = false;
    return;
  }

  async function completeOauth2SignIn(query) {
    // nix token from browser history
    window.history.pushState(
      "",
      document.title,
      window.location.pathname + window.location.search
    );

    // Show the token for easy capture
    console.info("access_token", query.access_token);

    if ("github.com" === query.issuer) {
      // TODO this is moot. We could set the auth cookie at time of redirect
      // and include the real (our) id_token
      let resp = await window
        .fetch(baseUrl + "/api/authn/session/oauth2/github.com", {
          method: "POST",
          headers: {
            authorization: query.access_token,
          },
        })
        .catch(die);
      let result = await resp.json().catch(die);

      console.info("Our bespoken token(s):");
      console.info(result);

      await doStuffWithUser(result);
    }
    // TODO what if it's not github?
  }

  async function completeOidcSignIn(query) {
    // nix token from browser history
    window.history.pushState(
      "",
      document.title,
      window.location.pathname + window.location.search
    );

    // Show the token for easy capture
    console.info("id_token", query.id_token);

    let jws = await parseJwt(query.id_token).catch(die);

    if ("https://accounts.google.com" === jws.claims.iss) {
      // TODO make sure we've got the right options for fetch !!!
      let resp = await window
        .fetch(baseUrl + "/api/authn/session/oidc/google.com", {
          method: "POST",
          headers: {
            authorization: query.id_token,
          },
        })
        .catch(die);
      let result = await resp.json().catch(die);

      console.info("Our bespoken token(s):");
      console.info(result);

      await doStuffWithUser(result);
    }
    // TODO what if it's not google?
  }

  await init().catch(die);
})();
