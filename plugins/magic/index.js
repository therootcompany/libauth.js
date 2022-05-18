"use strict";

//@ts-ignore
//let E = require("libauth/lib/errors.js");

/**
 * @typedef MagicLinkOpts
 * @property {Object} [store]
 * @property {Function} store.set
 * @property {Function} store.get
 */

/**
 * @param {MagicLinkOpts} userOpts
 */
function create(userOpts) {
  let myOpts = {
    store: userOpts.store ?? require("./store-dummy.js").create(),
  };

  return myOpts;
}

create.create = create;
module.exports = create;
