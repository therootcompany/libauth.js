#!/usr/bin/env node
"use strict";

require("dotenv").config({ path: ".env" });
require("dotenv").config({ path: ".env.secret" });

let Crypto = require("crypto");
let Fs = require("fs").promises;

let Keypairs = require("keypairs");

async function main() {
  let cmd = process.argv[2];
  let opt = process.argv[3];

  if ("envs" === cmd) {
    let magicSalt = await rndgen();
    let cookieSecret = await rndgen();
    let privateKey = await genkey();
    if (!opt) {
      opt = ".env";
    }

    console.info(`Initializing '${opt}':`);

    let findings = await initEnv({
      cookieSecret: cookieSecret,
      filename: opt,
      magicSalt: magicSalt,
      prefix: process.argv[4],
      privateKey: privateKey,
    });
    Object.keys(findings).forEach(function (key) {
      let num = findings[key];
      let action = "found";
      if (!num) {
        action = "created";
      }
      console.info(`    ${action} '${key}'`);
    });
    return;
  }

  if ("privkey" === cmd) {
    let privkey = await genkey();
    let indent = 0;
    if ("--pretty" === opt) {
      indent = 2;
    }
    let jwk = JSON.stringify(privkey, null, indent);

    console.info(jwk);
    return;
  }

  if ("rnd" === cmd) {
    let bytes = parseInt(opt || 16, 10);
    if (bytes < 16) {
      console.warn();
      console.warn(
        `Warn: secrets should have >= 128-bits (16 bytes) of entropy`,
      );
      console.warn();
    }
    let rnd = await rndgen(bytes);

    console.info(rnd);
    return;
  }

  usage(cmd);
}

function usage(cmd) {
  console.error("");
  console.error("Usage:");
  console.error("    npx libauth@v0 envs .env [ENV_PREFIX_]");
  console.error("    npx libauth@v0 privkey [--pretty]");
  console.error("    npx libauth@v0 rnd [16]");
  console.error("");
  console.error("Examples:");
  console.error("    npx libauth@v0 envs ./.env 'LIBAUTH_'");
  console.error("    npx libauth@v0 privkey --pretty");
  console.error("    npx libauth@v0 rnd 16");
  console.error("");

  if (!["--help", "-h", "help"].includes(cmd)) {
    process.exit(1);
  }
}

async function initEnv(opts) {
  let text = await Fs.readFile(opts.filename, "utf8").catch(function (err) {
    if ("ENOENT" !== err.code) {
      throw err;
    }
    return "";
  });
  if (!opts.prefix) {
    opts.prefix = "";
  }

  let found = {};
  let kCookieSecret = `${opts.prefix}COOKIE_SECRET`;
  let kMagicSalt = `${opts.prefix}MAGIC_SALT`;
  let kPrivateKey = `${opts.prefix}PRIVATE_KEY`;

  function checkLine(line, i, key) {
    let num = i + 1;
    let hasKey = line.startsWith(key) || line.startsWith(`export ${key}`);
    if (!hasKey) {
      return;
    }
    if (!found[key]) {
      found[key] = num;
      return;
    }
    let prev = found[key];
    console.warn(
      `${opts.filename}:${num} '${key}' already defined on line ${prev}`,
    );
  }

  let lines = text.split(/\n/g);

  lines.forEach(function (line, i) {
    checkLine(line, i, kMagicSalt);
    checkLine(line, i, kCookieSecret);
    checkLine(line, i, kPrivateKey);
  });

  let newlines = [];

  if (!found[kCookieSecret]) {
    let rnd = await rndgen(16);
    newlines.push(`${kCookieSecret}=${rnd}`);
    found[kCookieSecret] = 0;
  }
  if (!found[kMagicSalt]) {
    let rnd = await rndgen(16);
    newlines.push(`${kMagicSalt}=${rnd}`);
    found[kMagicSalt] = 0;
  }
  if (!found[kPrivateKey]) {
    let key = await genkey();
    let keyStr = JSON.stringify(key, null, 0);
    // IMPORTANT: needs single quotes due to double quotes
    newlines.push(`${kPrivateKey}='${keyStr}'`);
    found[kPrivateKey] = 0;
  }

  let newEnvs = newlines.join("\n");
  if (newEnvs) {
    newEnvs = `${newEnvs}\n\n`;
  }
  await Fs.writeFile(opts.filename, `${newEnvs}${text}`, "utf8");

  return found;
}

async function genkey() {
  let pair = await Keypairs.generate();
  return pair.private;
}

async function rndgen(bytes) {
  let rnd = Crypto.randomBytes(bytes)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
  return rnd;
}

main().catch(function (err) {
  console.error("Fail:");
  console.error(err.stack || err);
});
