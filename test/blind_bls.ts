import { BLINDBLS } from '..'
import {BLS} from 'bls12377js'
import bigInt = require('big-integer')
import { expect } from 'chai'
import 'mocha'

describe('blind bls', () => {
  it('should test blind message', () => {

    // step 1 (user): blind message
    const exampleData = new Buffer('32333435', 'hex')
    const blindingFactor = BLINDBLS.generateBlindingFactor()
    const blinded = BLINDBLS.blindMessage(exampleData, blindingFactor)

    // step 2 (server): compute PRF
    const privateKey = new Buffer('37be4cee3e4322bcbcf4daf48c3315e2bb08b134edfcba2f9294940b2553700e', 'hex')
    const signedBlinded = BLINDBLS.computePRF(privateKey, blinded)

    // step 3 (user): unblind message
    const signed = BLINDBLS.unblindMessage(signedBlinded, blindingFactor)

    // assert with non-blinded signed message
    const one = BLS.bigToBuffer(bigInt('1'))
    const nonBlinded = BLINDBLS.blindMessage(exampleData, one)
    const signedNonBlinded = BLINDBLS.computePRF(privateKey, nonBlinded)

    expect(signed).to.eql(signedNonBlinded)
  })
})
