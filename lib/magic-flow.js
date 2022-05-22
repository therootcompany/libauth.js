"use strict";

let E = require("./errors.js");
let parseDuration = require("./parse-duration.js");

let MagicFlow = module.exports;

/**
 * @param {MagicVerifierOpts} _pluginOpts
 * @returns {MagicCodeFlow}
 */
MagicFlow.create = function (_pluginOpts) {
  let defaultOpts = {
    // optional
    duration: "24h",
    // TODO rename to retries?
    maxAttempts: 5,
  };

  let pluginOpts = Object.assign({}, defaultOpts, _pluginOpts || {});
  let durationMs = parseDuration(pluginOpts.duration);
  let magicFlow = {};

  /**
   * @param {MagicParts} parts
   * @param {MagicDevice} device
   * @param {MagicRequest} request
   * @returns {MagicOrder}
   */
  magicFlow.initialize = function (parts, device, request) {
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

    return order;
  };

  /**
   * @param {Boolean} valid
   * @param {MagicOrder} order
   * @param {MagicParams} params
   * @param {MagicDevice} device
   * @returns {Promise<Boolean>}
   * @throws
   */
  magicFlow.assertValid = async function (valid, order, params, device) {
    // TODO skipExpired: magic.verified
    let assertOpts = { valid };
    return await magicFlow.assertIsFresh(order, params, assertOpts);
  };

  /**
   * Increment on failure, mark verified (redeem) on success.
   * @param {Boolean} verified
   * @param {MagicOrder} order
   * @param {MagicParams} params
   * @param {MagicDevice} device
   */
  magicFlow.redeem = async function (verified, order, device, params) {
    if (!verified) {
      throw E.DEVELOPER_ERROR(
        "@libauth/magic: tried to redeem an non-verified response",
      );
    }
    let failedValidation = false;

    let nowStr = new Date().toISOString();

    if (params.code) {
      /*
      // TODO maybe?
      if (!validations.code) {
        throw E.DEVELOPER_ERROR(
          "@libauth/magic: tried to redeem an non-verified response",
        );
      }
      */
      if (order.verified_at) {
        // TODO is this not also a developer error?
        throw E.CODE_REDEEMED();
      }

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

    if (params.receipt || params.finalize) {
      /*
      // TODO maybe?
      if (!validations.code) {
        throw E.DEVELOPER_ERROR(
          "@libauth/magic: tried to redeem an non-verified response",
        );
      }
      */
      if (order.finalized_at) {
        throw E.DEVELOPER_ERROR("the challenge has already been finalized");
      }

      // We only check the userAgent, not IP address.
      // It's far more probable that the WiFi might change than that
      // an attacker has the same token at a different IP address
      // TODO move elsewhere?
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
      if (params.receipt) {
        order.exchanged_at = nowStr;
        //order.exchanged_by = device.userAgent;
        //order.exchanged_ip = device.ip;
      }
      order.finalized_at = nowStr;
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
  magicFlow.increment = function (order) {
    // tracking attempts is the sole reason for using an ID
    // rather than just the receipt and secret verification code
    order.attempts += 1;

    return order;
  };

  /**
   * @param {MagicOrder} order
   * @param {MagicParams} params
   * @param {MagicDevice} device
   * @returns {MagicOrder}
   */
  magicFlow.cancel = function (order, params, device) {
    let dateStr = new Date().toISOString();

    order.canceled_at = dateStr;
    order.canceled_by = device.userAgent;
    order.canceled_ip = device.ip;

    return order;
  };

  // Helpers

  /**
   * @typedef MagicAssertOpts
   * @property {Boolean} [valid]
   * @property {Number} [timestamp] - only for debugging and unit testing
   */

  /**
   * @param {MagicOrder} order
   * @param {MagicParams} params
   * @param {MagicAssertOpts} assertOpts
   * @returns {Boolean}
   * @throws
   */
  magicFlow.assertIsFresh = function (
    order,
    params,
    { valid = false, timestamp },
  ) {
    //@ts-ignore TODO
    if (order.deleted_at) {
      throw E.CODE_NOT_FOUND();
    }

    if (order.attempts >= pluginOpts.maxAttempts) {
      throw E.CODE_INVALID("tried too many times");
    }

    if (order.canceled_at) {
      throw E.CODE_INVALID("canceled");
    }

    // If the code is old, but it's been verified before
    // and it's valid, we don't throw that it's expired.
    // (because the state may be useful in the future)
    if (order.verified_at && valid) {
      return true;
    }

    // TODO
    // Will get here if not canceled and the verification failed
    // or if the verification succeeded, but no exchange was required
    //
    // IMPORTANT: we still signal partial success via error code,
    // which can be used to redirect to a resource
    if (!timestamp) {
      timestamp = Date.now();
    }
    //@ts-ignore TODO
    let d = new Date(order.expired_at).valueOf();
    let fresh = d - timestamp > 0;
    if (!fresh) {
      throw E.CODE_INVALID("expired");
    }

    return true;
  };

  //
  // different code types
  //
  return magicFlow;
};
