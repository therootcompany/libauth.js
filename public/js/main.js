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

  async function init() {
    $(".js-logout").hidden = true;
    $(".js-social-login").hidden = true;

    // TODO rename to google
    var googleSignInUrl = Auth3000.generateOidcUrl(
      "https://accounts.google.com/o/oauth2/v2/auth",
      ENV.GOOGLE_CLIENT_ID,
      ENV.GOOGLE_REDIRECT_URI,
      "email profile"
      // "JOHN.DOE@EXAMPLE.COM"
    );
    $(".js-google-oidc-url").href = googleSignInUrl;

    var githubSignInUrl = Auth3000.generateOauth2Url(
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
    var query = Auth3000.parseQuerystring(querystring);
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
          body: JSON.stringify({
            timezone: new Intl.DateTimeFormat().resolvedOptions().timeZone,
            language: window.navigator.language,
          }),
          headers: {
            Authorization: query.access_token,
            "Content-Type": "application/json",
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

    let jws = await Auth3000.parseJwt(query.id_token).catch(die);

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
