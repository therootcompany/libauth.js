"use strict";

require("dotenv").config();

let fs = require("fs");
let envjs = fs.readFileSync("./env.tpl.js", "utf8");

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
