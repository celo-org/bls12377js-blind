"use strict";
exports.__esModule = true;
var __1 = require("..");
var bls12377js_1 = require("bls12377js");
var bigInt = require("big-integer");
var chai_1 = require("chai");
require("mocha");
describe('blind bls', function () {
    it('should test blind message', function () {
        // step 1 (user): blind message
        var exampleData = new Buffer('32333435', 'hex');
        var blindingFactor = __1.BLINDBLS.generateBlindingFactor();
        var blinded = __1.BLINDBLS.blindMessage(exampleData, blindingFactor);
        // step 2 (server): compute PRF
        var privateKey = new Buffer('37be4cee3e4322bcbcf4daf48c3315e2bb08b134edfcba2f9294940b2553700e', 'hex');
        var signedBlinded = __1.BLINDBLS.computePRF(privateKey, blinded);
        // step 3 (user): unblind message
        var signed = __1.BLINDBLS.unblindMessage(signedBlinded, blindingFactor);
        // assert with non-blinded signed message
        var one = bls12377js_1.BLS.bigToBuffer(bigInt('1'));
        var nonBlinded = __1.BLINDBLS.blindMessage(exampleData, one);
        var signedNonBlinded = __1.BLINDBLS.computePRF(privateKey, nonBlinded);
        chai_1.expect(signed).to.eql(signedNonBlinded);
    });
});
