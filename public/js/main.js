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

  function generateOidcUrl(client_id, redirect_uri, scope, login_hint) {
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
    var oidcBaseUrl = "https://accounts.google.com/o/oauth2/v2/auth";
    var options = { state, client_id, redirect_uri, scope, login_hint, nonce };
    // transform from object to 'param1=escaped1&param2=escaped2...'
    var params = Object.keys(options)
      .filter(function (key) {
        return options[key];
      })
      .map(function (key) {
        // the values must be URI-encoded (the %20s and such)
        return key + "=" + encodeURIComponent(options[key]);
      })
      .join("&");
    return oidcBaseUrl + "?response_type=id_token&access_type=online&" + params;
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

  var url = generateOidcUrl(
    ENV.GOOGLE_CLIENT_ID,
    ENV.GOOGLE_REDIRECT_URI,
    "email profile"
    // "JOHN.DOE@EXAMPLE.COM"
  );

  $(".js-google-oidc-url").href = url;

  var querystring = document.location.hash.slice(1);
  var query = parseQuerystring(querystring);
  if (!query.id_token) {
    let result = await attemptRefresh();
    if (!result.id_token && !result.access_token) {
      $(".js-google-oidc-url").hidden = false;
    }
    console.log("Refresh Token: (may be empty)");
    console.log(result);
    // TODO carry on with token...
    return;
  }

  // Show the token for easy capture
  console.log("id_token", query.id_token);

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

    console.log("Our bespoken token(s):");
    console.log(result);

    if (result.id_token || result.access_token) {
      window.alert("Congrats! You win! (check the console for your token)");
    } else {
      window.alert("No token, something went wrong.");
    }
  }
})();
