"use strict";

// TODO MemoryStore should be an Interface

/**
 * @typedef {Object} MemoryStore
 * @property {function} set
 * @property {function} get
 */

function create() {
  /** @type MemoryStore */
  let store = {
    //@ts-ignore
    _db: {},
    set:
      /**
       * @param {string} id
       * @param {any} val
       * @returns {Promise<void>}
       */
      async function (id, val) {
        //@ts-ignore
        store._db[id] = val;
      },
    get:
      /**
       * @param {string} id
       * @returns {Promise<any>}
       */
      async function (id) {
        //@ts-ignore
        return store._db[id];
      },
  };
  return store;
}

module.exports = create();
module.exports.create = create;
