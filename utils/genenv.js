"use strict";

let args = process.argv.slice(2);
if (!args.length) {
  require("dotenv").config();
} else {
  args.forEach(function (path) {
    require("dotenv").config({ path: path });
  });
}

let fs = require("fs");
let path = require("path");
let envjs = fs.readFileSync(path.join(__dirname, "env.tpl.js"), "utf8");

console.info("");
Object.keys(process.env).forEach(function (envname) {
  // match, literally "${GOOGLE_CLIENT_ID}" (including quotes)
  let reVar = new RegExp('"\\$\\{' + envname + '\\}"', "g");
  let newEnvjs = envjs.replace(reVar, JSON.stringify(process.env[envname]));

  // match ENV.GOOGLE_CLIENT_ID;
  // becomes ENV.GOOGLE_CLIENT_ID = "xxxx";
  let reExp = new RegExp("ENV\\." + envname + ";", "g");
  newEnvjs = newEnvjs.replace(
    reExp,
    "ENV." + envname + " = " + JSON.stringify(process.env[envname]) + ";"
  );

  if (envjs !== newEnvjs) {
    console.info("Adding", envname, "...");
  }
  envjs = newEnvjs;
});

let outfile = "./public/js/env.js";
fs.writeFileSync(outfile, envjs, "utf8");
console.info("Wrote", outfile, "from .env (and other existing ENVs)");
console.info("");
