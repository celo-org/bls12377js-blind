import {Defs, BLS} from 'bls12377js'
import bigInt = require('big-integer')

export let BLIND_DOMAIN = 'OBLIVDIR'
export let FR_MODULUS = bigInt('8444461749428370424248824938781546531375899335154063827935233455917409239041')

export function generateBlindingFactor(): Buffer {
  return BLS.bigToBuffer(bigInt.randBetween(0, FR_MODULUS.minus(bigInt('1'))))
}

export function blindMessage(message: Buffer, blindingFactorBytes: Buffer): Buffer {
  const messagePoint = BLS.tryAndIncrement(
    new Buffer(BLIND_DOMAIN),
    message,
  )
  const blindingFactor = BLS.bufferToBig(blindingFactorBytes)
  const signedMessageScaled = messagePoint.scalarMult(Defs.g1Cofactor)
  const signedMessageScaledBlinded = signedMessageScaled.scalarMult(blindingFactor)
  const hashedBytes = BLS.compressG1(signedMessageScaledBlinded)
  return hashedBytes
}

export function computePRF(privateKey: Buffer, messagePointBytes: Buffer): Buffer {
  const messagePoint = BLS.decompressG1(messagePointBytes)
  const privateKeyBig = BLS.bufferToBig(privateKey)
  const signedMessage = messagePoint.scalarMult(privateKeyBig)
  const signedMessageScaled = signedMessage.scalarMult(Defs.g1Cofactor)
  const signatureBytes = BLS.compressG1(signedMessageScaled)
  return signatureBytes
}

export function unblindMessage(signedMessageBytes: Buffer, blindingFactorBytes: Buffer): Buffer {
  const blindingFactor = BLS.bufferToBig(blindingFactorBytes)
  const blindingFactorInv = blindingFactor.modInv(FR_MODULUS)
  const signedMessage = BLS.decompressG1(signedMessageBytes)
  const signedMessageScaled = signedMessage.scalarMult(blindingFactorInv)
  return BLS.compressG1(signedMessageScaled)
}
