"use strict";

function create() {
  let store = {
    _db: {},
    set: async function (id, val) {
      store._db[id] = val;
    },
    get: async function (id) {
      return store._db[id];
    },
  };
  return store;
}

module.exports = create();
module.exports.create = create;
