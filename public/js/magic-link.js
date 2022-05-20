(async function () {
  "use strict";

  // from env.js
  let ENV = window.ENV;

  // scheme => 'https:'
  // host => 'localhost:3000'
  // pathname => '/api/authn/session/oidc/accounts.google.com'
  let baseUrl = `${document.location.protocol}//${document.location.host}`;

  // AJQuery
  function $(sel) {
    return document.body.querySelector(sel);
  }

  function noop() {}

  function die(err) {
    console.error(err);
    window.alert(
      `Oops! There was an unexpected error on the server.\nIt's not your fault.\n\n` +
        `Technical Details for Tech Support: \n${err.message}`,
    );
    throw err;
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

  function sleep(ms) {
    return new Promise(function (resolve) {
      setTimeout(resolve, ms);
    });
  }

  async function requestVerification(email) {
    let resp = await window.fetch(baseUrl + "/api/authn/challenge/order", {
      method: "POST",
      headers: {
        //Authorization: "Bearer " + (result.id_token || result.access_token),
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        identifier: {
          type: "email",
          value: email,
        },
        type: "email",
        value: email,
        template: "magic-link",
        state: {
          foo: "bar",
        },
      }),
    });

    let body = await resp.json();
    resp.data = body;
    return resp;
  }

  async function checkStatus({ secret = "", receipt = "", id = "" }) {
    let resp = await window.fetch(
      `${baseUrl}/api/authn/challenge/status` +
        `?id=${id}` +
        `&receipt=${receipt}` +
        `&token=${secret}`,
      {},
    );

    let body = await resp.json();
    resp.data = body;
    return resp;
  }

  async function finalizeVerification({ secret, receipt, id, trust }) {
    let url;
    if (secret) {
      url = `${baseUrl}/api/authn/challenge/finalize`;
    } else {
      url = `${baseUrl}/api/authn/challenge/exchange`;
    }

    let resp = await window.fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        receipt,
        token: secret,
        id,
        trust_device: trust,
      }),
    });

    let body = await resp.json();
    // Set-Cookie: auth3000...
    // {
    //   success: true,
    //   id_token: 'xxxx.yyyy.zzzz',
    //   access_token: 'xxxx.yyyy.zzzz'
    // }
    resp.data = body;
    return resp;
  }

  $("form.js-magic-email").addEventListener("submit", async function (ev) {
    ev.preventDefault();
    ev.stopPropagation();

    let email = $('[name="email"]').value;
    console.log(email);
    // TODO send email
    $("form.js-magic-email").hidden = true;

    $(".js-magic-check").hidden = false;
    $(".js-magic-check .js-email").innerText = email;

    let resp = await requestVerification(email).catch(die);

    if (resp.data._development_secret) {
      let link =
        `${baseUrl}#login` +
        `?id=${resp.data.id}` +
        `&token=${resp.data._development_secret}`;
      $("a.js-magic-dev-link").href = link;
      $("a.js-magic-dev-link").innerText = link;
      $("a.js-magic-dev-link").hidden = false;
    }
    console.log("Order Response", resp.data);

    try {
      localStorage.setItem(
        `auth3000:id:${resp.data.id}`,
        Date.now().toString(),
      );
    } catch (e) {
      // TODO fallback when localStorage is not available
    }

    let receipt = resp.data.receipt;
    let id = resp.data.id;
    while (true) {
      // TODO timeout after 15 minutes
      await sleep(1000);
      let statusResp = await checkStatus({ id, receipt });
      let meta = statusResp.data;
      console.log("[DEBUG] Poll Result", meta);
      if (meta.verified_by) {
        if (meta.ordered_by === meta.verified_by) {
          // On mobile, close *this* window
          // On desktop, *keep* this window (and close the other)
          window.alert("[original] Verified. You can close this window now.");
          return;
        }
        $(".js-magic-check").hidden = true;
        await promptRememberDevice({ receipt, id });
        break;
      }
    }
  });

  // look for #login?token=
  async function continueLogin() {
    var querystring = document.location.hash.slice("#login?".length);
    var query = parseQuerystring(querystring);
    // TODO let's call this secret_token or verify_token or some such
    if (!query.token) {
      return;
    }

    // TODO hide by default
    $("form.js-magic-email").hidden = true;

    window.history.pushState(
      "",
      document.title,
      // remove the hash with token from browser url bar
      window.location.pathname + window.location.search,
    );

    // TODO loading spinner
    $("form.js-magic-info").hidden = false;

    let resp = await checkStatus({ id: query.id, secret: query.token });
    // Show the token for easy capture
    console.log("magic info:", resp.data);
    if (!resp.data.ordered_by) {
      window.alert("invalid token");
      return;
    }

    if (
      resp.data.ordered_by === navigator.userAgent &&
      localStorage.getItem(`auth3000:id:${resp.data.id}`)
    ) {
      // this is the same browser we started in
      $(".js-login-message").innerText = "";
    } else {
      $(".js-login-message").innerText = resp.data.ordered_by;
    }
    await promptRememberDevice({ secret: query.token, id: query.id });
  }

  async function promptRememberDevice({ secret, receipt, id }) {
    $("form.js-magic-info").hidden = false;

    return new Promise(function (resolve, reject) {
      function removeHandlers() {
        $("form.js-magic-info").removeEventListener("submit", trustDevice);
        $(".js-login-temporary").removeEventListener("click", doNotTrust);
      }

      async function trustDevice(ev) {
        ev.preventDefault();
        ev.stopPropagation();

        // TODO change this if the default is to NOT trust
        await finalizeVerification({ secret, receipt, id, trust: true })
          .then(dashboardOrClose)
          .catch(die)
          .then(resolve)
          .catch(reject)
          .finally(removeHandlers);
      }

      async function doNotTrust(ev) {
        ev.preventDefault();
        ev.stopPropagation();

        await finalizeVerification({ receipt, secret, trust: false })
          .then(dashboardOrClose)
          .catch(die)
          .then(resolve)
          .catch(reject)
          .finally(removeHandlers);
      }

      $("form.js-magic-info").addEventListener("submit", trustDevice);
      $(".js-login-temporary").addEventListener("click", doNotTrust);
    });
  }

  function dashboardOrClose(resp) {
    // TODO clear localStorage of challenge_id
    // Use shared object if session (token) should not persist on refresh
    // Use sessionStorage if session (token) should not persist between tabs
    // Use localStorage if session (token) should not be long-lived
    // Use Secure, Same-Site, HTTP-Only Cookie for a long-lived refresh token
    localStorage.setItem("auth3000:me", resp.data.id_token);
    window.alert("Success! It's safe to close this tab");
    // or give dashboard button
  }

  if (document.location.hash.startsWith("#login?")) {
    continueLogin();
  }
})().catch(function (err) {
  console.error("top level error:");
  console.error(err);
});
