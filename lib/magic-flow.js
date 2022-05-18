"use strict";

let E = require("./errors.js");
let parseDuration = require("./parse-duration.js");

let MagicFlow = module.exports;

/**
 * @param {MagicVerifierOpts} _pluginOpts
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
   * Handles the mutex-y bits of the attempt counter / cool-off-er
   * @param {MagicOrder} order
   * @param {MagicParams} params
   * @param {MagicAssertOpts} assertOpts
   */
  magicFlow.assertValid = async function (order, params, assertOpts) {
    magicFlow.assertIsFresh(order, params, assertOpts);
  };

  /**
   * Increment on failure, mark verified (redeem) on success.
   * @param {MagicOrder} order
   * @param {MagicParams} params
   * @param {MagicDevice} device
   */
  magicFlow.redeem = async function (order, device, params) {
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
  magicFlow.increment = function (order) {
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
  magicFlow.cancel = function (order, device) {
    let dateStr = new Date().toISOString();

    order.canceled_at = dateStr;
    order.canceled_by = device.userAgent;
    order.canceled_ip = device.ip;

    return order;
  };

  // Helpers

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
    { failedValidation = true, requireExchange = true, timestamp },
  ) {
    if (order.attempts >= pluginOpts.maxAttempts) {
      throw E.CODE_INVALID("tried too many times", failedValidation);
    }

    if (requireExchange) {
      if (params.code) {
        if (order.verified_at) {
          throw E.CODE_REDEEMED(failedValidation);
        }
      } else {
        // Note: E.CODE_REDEEMED means all other checks passed
        if (order.exchanged_at) {
          throw E.CODE_REDEEMED(failedValidation);
        }
      }
    }

    if (order.canceled_at) {
      throw E.CODE_INVALID("canceled", failedValidation);
    }
    //@ts-ignore
    if (order.deleted_at) {
      throw E.CODE_INVALID("deleted", failedValidation);
    }

    // Will get here if not canceled and the verification failed
    // or if the verification succeeded, but no exchange was required
    //
    // IMPORTANT: we still signal partial success via error code,
    // which can be used to redirect to a resource
    //
    // TODO send back 'state' on expired but verified?
    if (!timestamp) {
      timestamp = Date.now();
    }
    //@ts-ignore
    let d = new Date(order.ordered_at).valueOf();
    let fresh = timestamp - d < durationMs;
    if (!fresh) {
      throw E.CODE_INVALID("expired", failedValidation);
    }

    return true;
  };

  //
  // different code types
  //
  return magicFlow;
};
