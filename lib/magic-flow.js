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
    // TODO name this?
    identifierTypes: ["email", "phone"],
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
  magicFlow.initialize = function (parts, request, device) {
    if (!request?.identifier?.value) {
      throw E.DEVELOPER_ERROR(
        "'value' (the email/phone/contact) is missing from the request body",
      );
    }

    let typ = String(request.identifier.type);
    if (!pluginOpts.identifierTypes.includes(typ)) {
      throw E.DEVELOPER_ERROR(
        "'identifier.type' must be one of '${pluginOpts.identifierTypes}'",
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
      receipt: parts.receipt,
      state: request.state, // client-side state
      custom: {}, // server-side state
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
   * @param {MagicValidations} validations
   * @param {MagicOrder} order
   * @param {MagicParams} params
   * @param {MagicDevice} device
   * @returns {Promise<Boolean>}
   * @throws
   */
  magicFlow.assertValid = async function (validations, order, params, device) {
    // TODO skipExpired: magic.verified
    let assertOpts = { valid: validations.valid };
    return await magicFlow.assertIsFresh(order, params, assertOpts);
  };

  /**
   * Increment on failure, mark verified (redeem) on success.
   * @param {MagicValidations} validations
   * @param {MagicOrder} order
   * @param {MagicParams} params
   * @param {MagicDevice} device
   */
  magicFlow.redeem = async function (validations, order, params, device) {
    if (!validations.valid) {
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
   * @param {MagicParams} params
   * @param {MagicDevice} device
   * @returns {MagicOrder}
   */
  magicFlow.handleFailure = function (order, params, device) {
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
    if (order.deleted_at) {
      throw E.CODE_NOT_FOUND();
    }

    if (order.attempts >= pluginOpts.maxAttempts) {
      throw E.CODE_INVALID("tried too many times");
    }

    if (order.canceled_at) {
      throw E.CODE_INVALID("canceled");
    }

    // IMPORTANT: A code can only be verified up until it expires.
    //            HOWEVER, the data associated with a verified code
    //            can still be viewed with the receipt until deleted.
    //
    //            This is so that things like invite codes can still
    //            redirect to the correct resource long after the code
    //            has been consumed for login.
    if (order.verified_at && valid) {
      return true;
    }

    if (!timestamp) {
      timestamp = Date.now();
    }
    let exp = new Date(order.expires_at).valueOf();
    let fresh = exp - timestamp > 0;
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
