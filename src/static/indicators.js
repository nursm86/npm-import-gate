import { C2_INDICATORS, OBFUSCATION } from '../config/constants.js';

/** Shannon entropy in bits per character. Random base64 sits around 5.5 to 6; prose around 4. */
export function shannonEntropy(text) {
  if (!text.length) return 0;
  const counts = new Map();
  for (const char of text) counts.set(char, (counts.get(char) ?? 0) + 1);
  let entropy = 0;
  for (const count of counts.values()) {
    const probability = count / text.length;
    entropy -= probability * Math.log2(probability);
  }
  return entropy;
}

/** Returns the indicator ids that match a string literal, if any. */
export function matchC2Indicators(text) {
  return C2_INDICATORS.filter(({ pattern }) => pattern.test(text)).map(({ id }) => id);
}

export function isHighEntropyString(text) {
  return text.length >= OBFUSCATION.minHighEntropyStringLength
    && shannonEntropy(text) >= OBFUSCATION.minEntropyBitsPerChar;
}

/** javascript-obfuscator and friends rename everything to _0x1a2b style identifiers. */
export function countHexIdentifiers(sourceText) {
  const matches = sourceText.match(OBFUSCATION.hexIdentifierPattern);
  return matches ? new Set(matches).size : 0;
}

export function hasObfuscatedIdentifiers(sourceText) {
  return countHexIdentifiers(sourceText) >= OBFUSCATION.minHexIdentifiers;
}

/** The string-array rotation loop that javascript-obfuscator emits; not produced by minifiers or bundlers. */
export function hasStringArrayRotation(sourceText) {
  return OBFUSCATION.stringArrayRotationPattern.test(sourceText);
}
