"use strict";

function DEVELOPER_ERROR(msg) {
  let err = new Error(
    [msg, "Oops! One of the programmers made a mistake. It's not your fault."]
      .filter(Boolean)
      .join(" ")
  );
  err.status = 400;
  err.code = "DEVELOPER_ERROR";
  return err;
}

function INVALID_SESSION() {
  let err = Error("Missing or invalid session. Please logout and login again.");
  err.status = 400;
  err.code = "INVALID_SESSION";
  return err;
}

function INVALID_TOKEN() {
  let err = new Error(
    "the given email verification token does not exist, is expired, or has been used"
  );
  err.status = 400;
  err.code = "INVALID_TOKEN";
  return err;
}

function MISSING_TOKEN() {
  let err = new Error("authorization token required");
  err.code = "MISSING_TOKEN";
  return err;
}

function SUSPICIOUS_REQUEST() {
  let err = new Error(
    "It looks like something suspicious is going on - as if you there are 3 different browsers trying to complete this process."
  );
  err.status = 400;
  err.code = "SUSPICIOUS_REQUEST";
  return err;
}

function SUSPICIOUS_TOKEN() {
  let err = new Error("the given google token does not belong to this app");
  err.code = "SUSPICIOUS_TOKEN";
  return err;
}

function UNVERIFIED_EMAIL() {
  let err = new Error("Email account has not yet been verified.");
  err.code = "INVALID_TOKEN";
  return err;
}

module.exports = {
  DEVELOPER_ERROR,
  INVALID_SESSION,
  INVALID_TOKEN,
  MISSING_TOKEN,
  SUSPICIOUS_REQUEST,
  SUSPICIOUS_TOKEN,
  UNVERIFIED_EMAIL,
};
