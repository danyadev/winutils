'use strict';

const bin = require('./build/Release/winutils.node');

module.exports = {
  isUserAdmin: bin.isUserAdmin,
  elevate: bin.elevate,
  deelevate: bin.deelevate,
  getSystem32Path: bin.getSystem32Path,
  resetIconCache: bin.resetIconCache,
  escapeShellArg(arg) {
    return `"${arg.replace(/["%!]/g, ' ')}"`;
  }
}
