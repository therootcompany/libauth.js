"use strict";

module.exports = async function notify(req) {
  let { type, value, secret, id, issuer } = req.authn;

  let challenge_url = `${issuer}/#login?id=${id}&token=${secret}`;
  let template = {
    subject: "Verify your email",
    html: `<p>Here's your verification code: ${secret}\n\n<br><br>${challenge_url}</p>`,
    text: `Here's your verification code: ${secret}\n\n${challenge_url}`,
  };

  console.debug("[dev mode]");
  console.debug("[dev mode]");
  console.debug(
    "[dev mode] Hey you! Replace this default `notify` function with your own."
  );
  console.debug(
    "[dev mode] (see the Verfication section of README to see how)"
  );
  console.debug("[dev mode]");
  console.debug("[dev mode] Example Message:");
  console.debug("[dev mode]");
  console.debug(`[dev mode] Subject: ${template.subject}`);
  console.debug(`[dev mode] HTML Body: ${template.html}`);
  console.debug(`[dev mode] Text Body: ${template.text}`);
  console.debug("[dev mode]");
  console.debug("[dev mode]");

  return await new Promise(function (resolve) {
    resolve(null);
  });
};
