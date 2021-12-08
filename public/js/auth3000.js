var Auth3000 = {};

(async function () {
  Auth3000._querystringify = function (options) {
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
  };

  Auth3000.parseQuerystring = function (querystring) {
    var query = {};
    querystring.split("&").forEach(function (pairstring) {
      var pair = pairstring.split("=");
      var key = pair[0];
      var value = decodeURIComponent(pair[1]);

      query[key] = value;
    });
    return query;
  };

  Auth3000.parseJwt = async function (jwt) {
    var parts = jwt.split(".");
    var jws = {
      protected: parts[0],
      payload: parts[1],
      signature: parts[2],
    };
    jws.header = Auth3000._urlBase64ToJson(jws.protected);
    jws.claims = Auth3000._urlBase64ToJson(jws.payload);
    return jws;
  };

  Auth3000.generateOidcUrl = function (
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
    var params = Auth3000._querystringify(options);
    return oidcBaseUrl + "?response_type=id_token&access_type=online&" + params;
  };

  Auth3000.generateOauth2Url = function (
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
    var params = Auth3000._querystringify(options);
    return authorize_url + "?allow_signup=true&" + params;
  };

  // because JavaScript's Base64 implementation isn't URL-safe
  Auth3000._urlBase64ToBase64 = function (str) {
    var r = str % 4;
    if (2 === r) {
      str += "==";
    } else if (3 === r) {
      str += "=";
    }
    return str.replace(/-/g, "+").replace(/_/g, "/");
  };

  Auth3000._urlBase64ToJson = function (u64) {
    var b64 = Auth3000._urlBase64ToBase64(u64);
    var str = atob(b64);
    return JSON.parse(str);
  };
})();
