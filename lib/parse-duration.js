"use strict";

function parseDuration(dur) {
  if ("string" !== typeof dur) {
    throw new TypeError("expected 'duration' to be a string");
  }

  if ("ms" === dur.slice(dur.length - 2)) {
    return Math.round(parseFloat(dur.slice(0, dur.length - 2), 10));
  }

  var d = dur[dur.length - 1];
  var n = parseFloat(dur.slice(0, dur.length - 1), 10);
  switch (d) {
    case "d":
      n *= 24;
    /* falls through */
    case "h":
      n *= 60;
    /* falls through */
    case "m":
      n *= 60;
    /* falls through */
    case "s":
      n *= 1000;
      break;
    default:
      throw new Error(`unexpected suffix '${d}'`);
  }
  return Math.round(n);
}

module.exports = parseDuration;
