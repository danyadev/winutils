'use strict';

const bin = require('./build/Release/winutils.node');

module.exports = {
  isUserAdmin: bin.isUserAdmin,
  elevate: bin.elevate,
  escapeShellArg(arg) {
    return `"${arg.replace(/["%!]/g, ' ')}"`;
  }
}
