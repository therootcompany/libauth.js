"use strict";

let DB = module.exports;
DB._data = require("./users.json");
DB.get = async function (query) {
  let id;

  // TODO check that at least one valid query exists
  // Note: it's perfectly valid to have both email AND ppid
  if (!(query.id || query.email || query.ppid)) {
    throw new Error("must query by account alias: email, ppid, or id");
  }

  if (query.id) {
    id = query.id;
  } else {
    if (query.email) {
      id = DB._data.map[query.email];
      if (!id) {
        // 404?
        return null;
      }
    }
    if (!id && query.ppid) {
      id = DB._data.map[query.ppid];
      if (!id) {
        // 404?
        return null;
      }
    }
    if (!id) {
      throw new Error("invalid account alias: " + (query.email || query.ppid));
    }
  }

  let user = DB._data.users[id] || null;
  if (!user) {
    // internal error
    throw new Error("DB Error: [SANITY Fail] user by id '" + id + "' vanished");
  }

  let account;
  if (query.accountId) {
    account = user.accounts[query.accountId];
    if (!account) {
      throw new Error(
        "Unauthorized: not authorized for account '" + query.accountId + "'"
      );
    }
  } else {
    account = Object.values(user.accounts).sort(function (a, b) {
      return a.priority - b.priority;
    })[0];
  }
  if (account) {
    user.roles = account.roles;
    user.account_id = account.id;
  }

  return user;
};
