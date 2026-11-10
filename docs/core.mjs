// Browser FSC construction using only the bundled public parameters.
const BODY_LENGTH = 60;
const SIGNATURE_LENGTH = 128;
const DIGEST_LENGTH = 16;
const FSC_LENGTH = BODY_LENGTH + SIGNATURE_LENGTH;
const LOW_BITS_MODULUS = 1n << 128n;
const MAX_QUOTIENT = 256;

const MD5_SHIFTS = [
  7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
  5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
  4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
  6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];
const MD5_CONSTANTS = Array.from(
  { length: 64 },
  (_, index) => Math.floor(Math.abs(Math.sin(index + 1)) * 2 ** 32) >>> 0,
);

export function hexToBytes(hex) {
  if (hex.length % 2 !== 0 || !/^[0-9a-f]*$/i.test(hex)) {
    throw new Error('Invalid hexadecimal data');
  }
  return Uint8Array.from(hex.match(/../g) ?? [], (pair) => parseInt(pair, 16));
}

export function bytesToHex(bytes) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function bytesToInteger(bytes, littleEndian = false) {
  const ordered = littleEndian ? Uint8Array.from(bytes).reverse() : bytes;
  return BigInt(`0x${bytesToHex(ordered) || '0'}`);
}

function integerToBytes(value, length) {
  const hex = value.toString(16).padStart(length * 2, '0');
  if (hex.length !== length * 2) throw new Error('Integer exceeds output size');
  return hexToBytes(hex);
}

function equalBytes(left, right) {
  return left.length === right.length && left.every((byte, index) => byte === right[index]);
}

// MD5 is required by the recovered FSC format; Web Crypto does not expose it.
export function md5(input) {
  const paddedLength = Math.ceil((input.length + 9) / 64) * 64;
  const padded = new Uint8Array(paddedLength);
  padded.set(input);
  padded[input.length] = 0x80;
  const paddedView = new DataView(padded.buffer);
  const bitLength = BigInt(input.length) * 8n;
  paddedView.setUint32(paddedLength - 8, Number(bitLength & 0xffffffffn), true);
  paddedView.setUint32(paddedLength - 4, Number(bitLength >> 32n), true);

  const state = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];
  for (let offset = 0; offset < paddedLength; offset += 64) {
    const words = Array.from({ length: 16 }, (_, index) =>
      paddedView.getUint32(offset + index * 4, true));
    let [a, b, c, d] = state;
    for (let index = 0; index < 64; index++) {
      let mix;
      let wordIndex;
      if (index < 16) {
        mix = (b & c) | (~b & d);
        wordIndex = index;
      } else if (index < 32) {
        mix = (d & b) | (~d & c);
        wordIndex = (5 * index + 1) % 16;
      } else if (index < 48) {
        mix = b ^ c ^ d;
        wordIndex = (3 * index + 5) % 16;
      } else {
        mix = c ^ (b | ~d);
        wordIndex = (7 * index) % 16;
      }
      const sum = (a + mix + MD5_CONSTANTS[index] + words[wordIndex]) >>> 0;
      const shift = MD5_SHIFTS[index];
      const rotated = ((sum << shift) | (sum >>> (32 - shift))) >>> 0;
      [a, b, c, d] = [d, (b + rotated) >>> 0, b, c];
    }
    state[0] = (state[0] + a) >>> 0;
    state[1] = (state[1] + b) >>> 0;
    state[2] = (state[2] + c) >>> 0;
    state[3] = (state[3] + d) >>> 0;
  }
  const digest = new Uint8Array(DIGEST_LENGTH);
  const view = new DataView(digest.buffer);
  state.forEach((word, index) => view.setUint32(index * 4, word, true));
  return digest;
}

function modularPower(base, exponent, modulus) {
  let result = 1n;
  base %= modulus;
  while (exponent > 0n) {
    if (exponent & 1n) result = (result * base) % modulus;
    base = (base * base) % modulus;
    exponent >>= 1n;
  }
  return result;
}

function floorCubeRoot(value) {
  if (value < 0n) throw new Error('Cube-root input must be nonnegative');
  let low = 0n;
  let high = 1n << BigInt(Math.ceil(value.toString(2).length / 3));
  while (low < high) {
    const middle = (low + high + 1n) >> 1n;
    if (middle ** 3n <= value) low = middle;
    else high = middle - 1n;
  }
  return low;
}

function ceilCubeRoot(value) {
  const root = floorCubeRoot(value);
  return root ** 3n === value ? root : root + 1n;
}

function forgeSignature(digest, modulus) {
  const digestValue = bytesToInteger(digest);
  const inverseOfThree = ((1n << 127n) + 1n) / 3n;
  for (let quotient = 0; quotient < MAX_QUOTIENT; quotient++) {
    const q = BigInt(quotient);
    const target = (digestValue + q * modulus) % LOW_BITS_MODULUS;
    if ((target & 1n) === 0n) continue;
    const residue = modularPower(target, inverseOfThree, LOW_BITS_MODULUS);
    if (modularPower(residue, 3n, LOW_BITS_MODULUS) !== target) {
      throw new Error('Modular cube-root check failed');
    }
    const lower = ceilCubeRoot(q * modulus);
    const upper = floorCubeRoot((q + 1n) * modulus - 1n);
    if (residue > upper) continue;
    const candidate = residue + ((upper - residue) / LOW_BITS_MODULUS) * LOW_BITS_MODULUS;
    if (candidate < lower || candidate >= modulus) continue;
    const recovered = integerToBytes(modularPower(candidate, 3n, modulus), SIGNATURE_LENGTH);
    if (!equalBytes(recovered.slice(-DIGEST_LENGTH), digest)) continue;
    return { signature: integerToBytes(candidate, SIGNATURE_LENGTH), quotient, recovered };
  }
  throw new Error('Could not construct a suffix-only signature');
}

export function generateFsc(vin7, appId, data) {
  const vin = vin7.trim().toUpperCase();
  if (!/^[A-Z0-9]{7}$/.test(vin)) throw new Error('Enter exactly seven VIN letters or digits');
  if (![0x017c, 0x0180].includes(appId)) throw new Error('Select App ID 017C or 0180');
  if (data.public_exponent !== 3) throw new Error('Unsupported public exponent');

  const modulus = bytesToInteger(hexToBytes(data.public_modulus_little_endian_hex), true);
  const record = new Uint8Array(FSC_LENGTH);
  record[2] = appId >> 8;
  record[3] = appId & 0xff;
  record.set(new TextEncoder().encode(vin), 26);

  const digest = md5(record.slice(0, BODY_LENGTH));
  const { signature, quotient, recovered } = forgeSignature(digest, modulus);
  record.set(signature, BODY_LENGTH);
  if (!equalBytes(recovered.slice(-DIGEST_LENGTH), digest)) {
    throw new Error('Generated FSC failed its signature self-check');
  }
  return { bytes: record, vin, appId, digest: bytesToHex(digest), quotient };
}
