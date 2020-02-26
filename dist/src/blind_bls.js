"use strict";
exports.__esModule = true;
var bls12377js_1 = require("bls12377js");
var bigInt = require("big-integer");
exports.BLIND_DOMAIN = 'OBLIVDIR';
exports.FR_MODULUS = bigInt('8444461749428370424248824938781546531375899335154063827935233455917409239041');
function generateBlindingFactor() {
    return bls12377js_1.BLS.bigToBuffer(bigInt.randBetween(0, exports.FR_MODULUS.minus(bigInt('1'))));
}
exports.generateBlindingFactor = generateBlindingFactor;
function blindMessage(message, blindingFactorBytes) {
    var messagePoint = bls12377js_1.BLS.tryAndIncrement(new Buffer(exports.BLIND_DOMAIN), message);
    var blindingFactor = bls12377js_1.BLS.bufferToBig(blindingFactorBytes);
    var signedMessageScaled = messagePoint.scalarMult(bls12377js_1.Defs.g1Cofactor);
    var signedMessageScaledBlinded = signedMessageScaled.scalarMult(blindingFactor);
    var hashedBytes = bls12377js_1.BLS.compressG1(signedMessageScaledBlinded);
    return hashedBytes;
}
exports.blindMessage = blindMessage;
function computePRF(privateKey, messagePointBytes) {
    var messagePoint = bls12377js_1.BLS.decompressG1(messagePointBytes);
    var privateKeyBig = bls12377js_1.BLS.bufferToBig(privateKey);
    var signedMessage = messagePoint.scalarMult(privateKeyBig);
    var signedMessageScaled = signedMessage.scalarMult(bls12377js_1.Defs.g1Cofactor);
    var signatureBytes = bls12377js_1.BLS.compressG1(signedMessageScaled);
    return signatureBytes;
}
exports.computePRF = computePRF;
function unblindMessage(signedMessageBytes, blindingFactorBytes) {
    var blindingFactor = bls12377js_1.BLS.bufferToBig(blindingFactorBytes);
    var blindingFactorInv = blindingFactor.modInv(exports.FR_MODULUS);
    var signedMessage = bls12377js_1.BLS.decompressG1(signedMessageBytes);
    var signedMessageScaled = signedMessage.scalarMult(blindingFactorInv);
    return bls12377js_1.BLS.compressG1(signedMessageScaled);
}
exports.unblindMessage = unblindMessage;
