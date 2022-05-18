"use strict";

let E = require("./errors.js");
let parseDuration = require("./parse-duration.js");

let MagicOrder = module.exports;

/**
 * @param {MagicVerifierOpts} _pluginOpts
 */
MagicOrder.create = function (_pluginOpts) {
  let defaultOpts = {
    // optional
    duration: "24h",
    // TODO rename to retries?
    maxAttempts: 5,
  };

  let pluginOpts = Object.assign({}, defaultOpts, _pluginOpts || {});

  let durationMs = parseDuration(pluginOpts.duration);

  let magicOrder = {};

  /**
   * @param {MagicParts} parts
   * @param {MagicDevice} device
   * @param {MagicRequest} request
   * @returns {MagicResponse}
   */
  magicOrder.initialize = function (parts, device, request) {
    if (!request?.identifier?.value) {
      throw E.DEVELOPER_ERROR(
        "'value' (the email/phone/contact) is missing from the request body",
      );
    }

    if (!parts.id || !parts.code || !parts.receipt) {
      throw E.DEVELOPER_ERROR(
        "'id', 'code', or 'receipt' is missing from the the request state",
      );
    }

    let d = new Date();
    let expiration = new Date(d.valueOf() + durationMs);

    /** @type MagicOrder */
    let order = {
      id: parts.id,
      receipt: parts.receipt, //
      state: request.state,
      identifier: request.identifier,
      attempts: 0,
      expires_at: expiration.toISOString(), //
      duration: pluginOpts.duration,
      ordered_at: d.toISOString(),
      ordered_by: device.userAgent,
      ordered_ip: device.ip,
    };

    return {
      order,
      //@ts-ignore - TODO
      status: MagicOrder.toStatus(order),
    };
  };

  /**
   * Handles the mutex-y bits of the attempt counter / cool-off-er
   * @param {MagicOrder} order
   * @param {String} code
   * @param {MagicAssertOpts} assertOpts
   */
  magicOrder.assertValid = async function (order, code, assertOpts) {
    //let magic = libauth.get(req, "magic");
    //let code = magic.params.code;

    if (!code && false === assertOpts.requireExchange) {
      magicOrder.assertIsFresh(order, assertOpts);
      return MagicOrder.toStatus(order);
    }

    if (!code) {
      throw E.DEVELOPER_ERROR("'code' is missing from the request parameters");
    }
  };

  /**
   * Handles the mutex-y bits of the attempt counter / cool-off-er
   * @param {MagicOrder} order
   * @param {String} code
   * @param {MagicAssertOpts} assertOpts
   */
  magicOrder.assertVerified = async function (order, code, assertOpts) {
    //let pass = await pluginOpts.codes.verify(order, code);
    assertOpts.failedValidation = assertOpts.failedValidation ?? true;
    magicOrder.assertIsFresh(order, assertOpts);

    if (false === assertOpts.failedValidation) {
      return;
    }

    throw E.CODE_RETRY();
  };

  /**
   * Increment on failure, mark verified (redeem) on success.
   * @param {MagicOrder} order
   * @param {MagicParams} params
   * @param {MagicDevice} device
   */
  magicOrder.redeem = async function (order, params, device) {
    // TODO if (!magic.verified) { throw ... }

    let nowStr = new Date().toISOString();

    if (params.code) {
      /* if (order.verified_at) { throw E_CODE_REDEEMED } */
      order.verified_at = nowStr;
      order.verified_by = device.userAgent;
      order.verified_ip = device.ip;
      if (params.finalize) {
        order.exchanged_at = nowStr;
        //order.exchanged_by = "";
        //order.exchanged_ip = "";
      }
      return order;
    }

    if (params.receipt) {
      // We only check the userAgent, not IP address.
      // It's far more probable that the WiFi might change than that
      // an attacker has the same token at a different IP address
      if (order.ordered_by !== device.userAgent) {
        throw E.SUSPICIOUS_REQUEST();
      }

      if (!order.verified_at) {
        // TODO better message and error code
        throw E.DEVELOPER_ERROR(
          "a challenge code exchange was requested before the challenge code was submitted",
        );
      }

      /* if (order.exchanged_at) { throw E_CODE_REDEEMED } */
      order.exchanged_at = nowStr;
      //order.exchanged_by = device.userAgent;
      //order.exchanged_ip = device.ip;
      return order;
    }

    throw E.DEVELOPER_ERROR(
      "'code' or 'receipt' is missing from the request parameters",
    );
  };

  // Atomic-ish Operations

  /**
   * @param {MagicOrder} order
   * @returns {MagicOrder}
   */
  magicOrder.increment = function (order) {
    // tracking attempts is the sole reason for using an ID
    // rather than just the receipt and secret verification code
    order.attempts += 1;

    return order;
  };

  /**
   * @param {MagicOrder} order
   * @param {MagicDevice} device
   * @returns {MagicOrder}
   */
  magicOrder.cancel = function (order, device) {
    let dateStr = new Date().toISOString();

    order.canceled_at = dateStr;
    order.canceled_by = device.userAgent;
    order.canceled_ip = device.ip;

    return order;
  };

  // Helpers

  /**
   * @param {MagicOrder} order
   * @param {MagicAssertOpts} assertOpts
   * @returns {Boolean}
   * @throws
   */
  magicOrder.assertIsFresh = function (
    order,
    {
      requireUnusedCode = true,
      requireUnusedReceipt = true,
      failedValidation = true,
    },
  ) {
    if (order.attempts >= pluginOpts.maxAttempts) {
      throw E.CODE_INVALID("tried too many times", failedValidation);
    }
    if (requireUnusedCode) {
      // Note: E.CODE_REDEEMED means all other checks passed
      if (order.verified_at) {
        throw E.CODE_REDEEMED(failedValidation);
      }
    }
    if (requireUnusedReceipt) {
      // Note: E.CODE_REDEEMED means all other checks passed
      if (order.exchanged_at) {
        throw E.CODE_REDEEMED(failedValidation);
      }
    }
    if (order.canceled_at) {
      throw E.CODE_INVALID("canceled", failedValidation);
    }
    //@ts-ignore
    if (order.deleted_at) {
      throw E.CODE_INVALID("deleted", failedValidation);
    }

    let now = Date.now();
    //@ts-ignore
    let d = new Date(order.ordered_at).valueOf();
    let fresh = now - d < durationMs;
    if (!fresh) {
      throw E.CODE_INVALID("expired", failedValidation);
    }

    return true;
  };

  //
  // different code types
  //
  return magicOrder;
};

/**
 * @param {MagicOrder} order
 * @returns {MagicStatus}
 */
MagicOrder.toStatus = function (order) {
  let status = "pending";
  if (order.canceled_by) {
    status = "invalid";
  } else if (order.verified_by) {
    status = "valid";
  }

  return {
    id: order.id,
    status: status,
    // TODO always include?
    // receipt: receipt,
    state: order.state,
    duration: order.duration,
    expires_at: order.expires_at,
    canceled_at: order.canceled_at,
    canceled_by: order.canceled_by,
    exchanged_at: order.exchanged_at,
    ordered_at: order.ordered_at,
    ordered_by: order.ordered_by,
    verified_at: order.verified_at,
    verified_by: order.verified_by,
  };
};
