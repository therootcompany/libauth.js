"use strict";

function INVALID_TOKEN() {
  let err = new Error(
    "the given email verification token does not exist, is expired, or has been used"
  );
  err.status = 400;
  err.code = "INVALID_TOKEN";
  return err;
}

function SUSPICIOUS_REQUEST() {
  let err = new Error(
    "It looks like something suspicious is going on - as if you there are 3 different browsers trying to complete this process."
  );
  err.status = 400;
  err.code = "SUSPICIOUS_REQUEST";
  throw err;
}

function DEVELOPER_ERROR(msg) {
  let err = new Error(
    msg ||
      "There was an error, but it was due to a mistake a programmer made. It's not your fault."
  );
  err.status = 400;
  err.code = "DEVELOPER_ERROR";
  throw err;
}

module.exports = {
  INVALID_TOKEN,
  SUSPICIOUS_REQUEST,
  DEVELOPER_ERROR,
};
