"use strict";

module.exports = require("./lib/session.js");

let util = require("./lib/util.js");
module.exports.decodeAuthorizationBasic = util.decodeAuthorizationBasic;
module.exports.decodeAuthorizationBasicValue =
  util.decodeAuthorizationBasicValue;
module.exports.secureCompare = util.secureCompare;
