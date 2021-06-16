#!/usr/bin/env node

"use strict";

require("dotenv").config();
require("dotenv").config({ path: ".env.test" });

let colors = require("colors/safe");
let PASS = colors.green("PASS");
let request = require("@root/request");
let PORT = process.env.PORT;
let TEST_EMAIL = process.env.TEST_EMAIL || "john.doe@example.com";

function getResponse(resp) {
  if (resp.status >= 300) {
    let err = new Error(
      "unexpected error status code on response:" +
        resp.status +
        ": " +
        JSON.stringify(resp.body || null)
    );
    err.response = resp;
    throw err;
  }
  return resp.toJSON();
}

function getBody(resp) {
  return getResponse(resp).body;
}

function expect4xx(resp) {
  if ((resp.status >= 200 && resp.status < 300) || resp.status > 500) {
    let err = new Error(
      "unexpected success status code on response:" +
        resp.status +
        ": " +
        JSON.stringify(resp.body || null)
    );
    err.response = resp;
    throw err;
  }
  return resp.body;
}

async function main() {
  let ua1 = "magic-link-test-requester/1.0";
  let ua2 = "magic-link-test-fulfiller/1.0";
  console.info("Running Magic Link Tests...");

  let baseUrl = `http://localhost:${PORT}/api/authn`;

  // 1. Order Verification Challenge
  // Order a new email verification challenge
  // (an email will be sent that contains a secret code)
  let order = await request({
    url: `${baseUrl}/challenge/issue`,
    method: "POST",
    headers: { "User-Agent": ua1 },
    json: { type: "email", value: `${TEST_EMAIL}` },
  }).then(getBody);
  // This challenge token can be used to check the status of the challenge order
  // (think of it as the receipt / tracking number)
  let my_challenge_token = order.challenge_token;
  let my_secret = order.secret;
  if (!my_challenge_token) {
    throw new Error("didn't get back 'challenge_token'");
  }
  if (!my_secret) {
    throw new Error(
      "didn't get back 'secret' for testing challenge verification - Check ENV=DEVELOPMENT"
    );
  }
  if ("DEVELOPMENT" !== process.env.ENV) {
    throw new Error("[SECURITY] got 'secret' back not in development mode!!!");
  }
  console.info(`\t${PASS}: Order Challenge Verification`);

  // 2. Check Status of Challenge Order
  // We can check the challenge order and see that it is not yet fulfilled
  // (the user did not yet receive the email and click the secret link)
  let status1 = await request({
    url: `${baseUrl}/challenge?challenge_token=${my_challenge_token}`,
    headers: { "User-Agent": ua1 },
    json: true,
  }).then(getBody);
  if (status1.ordered_by != ua1) {
    throw new Error(
      `status1: 'ordered_by' should be '${ua1}', not '${status1.ordered_by}'`
    );
  }
  /*
  if ("pending" != status1.status) {
    throw new Error(
      "status1: 'status' is not set to 'pending':" + JSON.stringify(status1)
    );
  }
  */
  if (status1.verified_by || status1.verified_at) {
    throw new Error(
      "status1: 'verified_by' must not be set yet:" + status1.verified_by
    );
  }
  console.info(`\t${PASS}: Challenge Status w/ challenge_token`);

  // 3. Check (Secret) Status of Challenge Order
  // Here we are checking to see that the secret is still valid
  // (is not expired, has not been used - good for debugging)
  let status2 = await request({
    url: `${baseUrl}/challenge?token=${my_secret}`,
    headers: { "User-Agent": ua1 },
    json: true,
  }).then(getBody);
  if (status2.ordered_by != ua1) {
    throw new Error(
      "status2: 'ordered_by' not set correctly:" + JSON.stringify(status2)
    );
  }
  /*
  if ("pending" != status2.status) {
    throw new Error(
      "status2: 'status' is not set to 'pending':" + JSON.stringify(status2)
    );
  }
  */
  if (status2.verified_by || status2.verified_at) {
    throw new Error(
      "status2: 'verified_by' must not be set yet:" + JSON.stringify(status2)
    );
  }
  console.info(`\t${PASS}: Challenge Status w/ secret`);

  // 2+3b: Invalid Status Requests
  // Make sure bad values are handled correctly.
  await request({
    url: `${baseUrl}/challenge?challenge_token=doesntexist`,
    json: true,
  }).then(expect4xx);
  await request({
    url: `${baseUrl}/challenge?token=doesntexist`,
    json: true,
  }).then(expect4xx);
  await request({
    url: `${baseUrl}/challenge`,
    json: true,
  }).then(expect4xx);
  console.info(`\t${PASS}: Challenge Status w/ bad values`);

  // 4. Get ID Token: Verify Challenge / Finalize Order (with Secret)
  // Here we finalize the order with the secret, and get back an id token
  // (the user clicks the link in the email)
  await request({
    url: `${baseUrl}/challenge/complete`,
    method: "POST",
    headers: { "User-Agent": ua2 },
    json: { wrong_token: my_secret },
  }).then(expect4xx);
  await request({
    url: `${baseUrl}/challenge/complete`,
    method: "POST",
    headers: { "User-Agent": ua2 },
    json: { token: "wrong_" + my_secret },
  }).then(expect4xx);
  console.info(`\t${PASS}: Complete Challenge Incorrectly`);

  let finalize = await request({
    url: `${baseUrl}/challenge/complete`,
    method: "POST",
    headers: { "User-Agent": ua2 },
    json: { token: my_secret },
  }).then(getResponse);
  /*
  if ("valid" != finalize.body.status) {
    throw new Error(
      "finalize: 'status' is not set to 'valid':" + JSON.stringify(finalize)
    );
  }
  */
  if (!finalize.body.id_token) {
    console.log("[DEBUG] finalize:", finalize);
    throw new Error(
      "finalize: 'id_token' is not set:" + JSON.stringify(finalize)
    );
  }
  if (!finalize.headers["set-cookie"]) {
    throw new Error(
      "finalize: 'set-cookie' was not found among the headers:" +
        JSON.stringify(finalize)
    );
  }
  console.info(`\t${PASS}: Complete Challenge`);

  await request({
    url: `${baseUrl}/challenge/complete`,
    method: "POST",
    headers: { "User-Agent": ua2 },
    json: { token: my_secret },
  }).then(expect4xx);
  console.info(`\t${PASS}: Complete Challenge Replay`);

  // 5. Check Status of Challenge Order
  // We check to see that the challenge token (which can only be used after
  // the secret has been provided from the email link) is usable. This is
  // the same thing we did up in step 2.
  let status3 = await request({
    url: `${baseUrl}/challenge?challenge_token=${my_challenge_token}`,
    headers: { "User-Agent": ua1 },
    json: true,
  }).then(getBody);
  /*
    {
      "success": true,
      "status": "valid",
      "ordered_at": "2021-06-20T13:30:59Z",
      "ordered_by": "Chrome/x.y.z Windows 10",
      "verified_at": "2021-06-20T13:31:42Z",
      "verified_by": "Safari/x.y iPhone iOS 17"
    }
  */
  if (status3.ordered_by != ua1) {
    throw new Error(
      "status3: 'ordered_by' not set correctly:" + JSON.stringify(status3)
    );
  }
  /*
  if ("valid" != status3.status) {
    throw new Error(
      "status3: 'status' is not set to 'valid':" + JSON.stringify(status3)
    );
  }
  */
  if (status3.verified_by != ua2) {
    throw new Error(
      `status3: 'verified_by' should be set to '${ua2}':` +
        JSON.stringify(status3)
    );
  }
  console.info(`\t${PASS}: Valid Challenge Status w/ challenge_token`);

  // TODO what about secret? that's invalid now, right?

  // 6. Get ID Token (2): Exchange Challenge (non-secret) Token
  // We exchange the original non-secret challenge token for an id_token also
  // (this is for the case that the user clicked the email in a different browser
  // or device - such as their phone - than were they originally using)
  await request({
    url: `${baseUrl}/challenge/exchange`,
    method: "POST",
    headers: { "User-Agent": ua1 },
    json: { wrong_challenge_token: my_challenge_token },
  }).then(expect4xx);
  await request({
    url: `${baseUrl}/challenge/exchange`,
    method: "POST",
    headers: { "User-Agent": ua1 },
    json: { challenge_token: "x" + my_challenge_token },
  }).then(expect4xx);
  await request({
    url: `${baseUrl}/challenge/exchange`,
    method: "POST",
    headers: { "User-Agent": ua1 },
    json: { challenge_token: my_challenge_token + "x" },
  }).then(expect4xx);
  // TODO check wrong user agent
  console.info(
    `\t${PASS}: Verified Challenge Exchange w/ invalid challenge_token`
  );

  let exchange = await request({
    url: `${baseUrl}/challenge/exchange`,
    method: "POST",
    headers: { "User-Agent": ua1 },
    json: { challenge_token: my_challenge_token },
  }).then(getResponse);
  /*
  if ("valid" != exchange.body.status) {
    throw new Error(
      "exchange: 'status' is not set to 'valid':" + JSON.stringify(exchange)
    );
  }
  */
  if (!exchange.body.id_token) {
    throw new Error(
      "exchange: 'id_token' is not set:" + JSON.stringify(exchange)
    );
  }
  if (!exchange.headers["set-cookie"]) {
    throw new Error(
      "exchange: 'set-cookie' was not found among the headers:" +
        JSON.stringify(exchange)
    );
  }
  /*
    {
      "success": true, "status": "valid",
      "id_token": "xxxx.yyyy.zzzz"
    }
  */
  console.info(`\t${PASS}: Verified Challenge Exchange w/ challenge_token`);

  await request({
    url: `${baseUrl}/challenge/exchange`,
    method: "POST",
    headers: { "User-Agent": ua1 },
    json: { challenge_token: my_challenge_token },
  }).then(expect4xx);
  console.info(
    `\t${colors.green(
      "PASS"
    )}: Spent Challenge Exchange w/ spent challenge_token`
  );
}

if (module === require.main) {
  main()
    .then(function () {
      console.info(`${PASS}`);
    })
    .catch(function (err) {
      console.error("Fail:");
      console.error(err);
      process.exit(1);
    });
}

module.exports = main;
