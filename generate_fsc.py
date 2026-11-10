"""Generate an MDG1-format FSC from the recovered template and public parameters.

The source executable is never imported or executed. Extracted constants are
stored separately in mdg1_public_data.json. This tool runs fully offline.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re

BODY_LEN = 60
SIGNATURE_LEN = 128
VIN_OFFSET = 26
VIN_LEN = 7
APPID_OFFSET = 2
MOD_128 = 1 << 128


@dataclass(frozen=True)
class Parameters:
    modulus: int
    exponent: int
    template: bytes
    md5_digest_info_prefix: bytes
    app_ids: tuple[int, ...]


@dataclass(frozen=True)
class Result:
    fsc: bytes
    digest: bytes
    quotient: int
    rsa_result: bytes
    weak_valid: bool
    strict_valid: bool


def load_parameters(path: Path | None = None) -> Parameters:
    path = path or Path(__file__).with_name('mdg1_public_data.json')
    data = json.loads(path.read_text(encoding='utf-8'))
    modulus = int.from_bytes(bytes.fromhex(data['public_modulus_little_endian_hex']), 'little')
    template = bytes.fromhex(data['built_in_template_hex'])
    if modulus.bit_length() > SIGNATURE_LEN * 8 or modulus <= 0:
        raise ValueError('public modulus has an invalid size')
    if len(template) < BODY_LEN + SIGNATURE_LEN:
        raise ValueError('built-in FSC template is incomplete')
    if int(data['public_exponent']) != 3:
        raise ValueError('this implementation requires public exponent 3')
    return Parameters(modulus, int(data['public_exponent']), template,
                      bytes.fromhex(data['md5_digest_info_prefix_hex']),
                      tuple(data['app_ids']))


def floor_cuberoot(value: int) -> int:
    if value < 0:
        raise ValueError('cube root input must be non-negative')
    lo, hi = 0, 1 << ((value.bit_length() + 2) // 3)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if mid * mid * mid <= value:
            lo = mid
        else:
            hi = mid - 1
    return lo


def ceil_cuberoot(value: int) -> int:
    root = floor_cuberoot(value)
    return root if root * root * root == value else root + 1


def odd_cube_root_mod_2_128(value: int) -> int:
    value %= MOD_128
    if value & 1 == 0:
        raise ValueError('value must be odd')
    inverse_of_three = pow(3, -1, 1 << 127)
    root = pow(value, inverse_of_three, MOD_128)
    if pow(root, 3, MOD_128) != value:
        raise AssertionError('internal modular cube-root failure')
    return root


def forge_suffix_only_signature(digest: bytes, params: Parameters) -> tuple[bytes, int, bytes]:
    if len(digest) != 16:
        raise ValueError('MD5 digest must be 16 bytes')
    digest_int = int.from_bytes(digest, 'big')
    for quotient in range(256):
        target_low = (digest_int + quotient * params.modulus) % MOD_128
        if target_low & 1 == 0:
            continue
        residue = odd_cube_root_mod_2_128(target_low)
        lower = ceil_cuberoot(quotient * params.modulus)
        upper = floor_cuberoot((quotient + 1) * params.modulus - 1)
        if residue > upper:
            continue
        lift = (upper - residue) // MOD_128
        candidate = residue + lift * MOD_128
        if candidate < lower or candidate >= params.modulus:
            continue
        recovered = pow(candidate, params.exponent, params.modulus).to_bytes(SIGNATURE_LEN, 'big')
        if recovered[-16:] != digest:
            continue
        return candidate.to_bytes(SIGNATURE_LEN, 'big'), quotient, recovered
    raise RuntimeError('could not construct a suffix-only signature')


def strict_pkcs1_v1_5_block(digest: bytes, params: Parameters) -> bytes:
    digest_info = params.md5_digest_info_prefix + digest
    padding_len = SIGNATURE_LEN - len(digest_info) - 3
    if padding_len < 8:
        raise ValueError('RSA modulus is too short for DigestInfo')
    return b'\x00\x01' + b'\xff' * padding_len + b'\x00' + digest_info


def load_template(path: Path | None, params: Parameters) -> bytearray:
    data = params.template if path is None else path.read_bytes()
    expected = BODY_LEN + SIGNATURE_LEN
    if len(data) < expected:
        raise ValueError(f'template is {len(data)} bytes; need at least {expected} bytes')
    return bytearray(data[:BODY_LEN] + data[-SIGNATURE_LEN:])


def build_fsc(template: bytearray, vin: bytes, appid: int, params: Parameters) -> Result:
    if len(vin) != VIN_LEN or any(c > 0x7f or not chr(c).isalnum() for c in vin):
        raise ValueError('VIN must contain exactly seven ASCII letters or digits')
    if not 0 <= appid <= 0xffff:
        raise ValueError('App ID must fit in 16 bits')
    output = bytearray(template)
    output[APPID_OFFSET:APPID_OFFSET + 2] = appid.to_bytes(2, 'big')
    output[VIN_OFFSET:VIN_OFFSET + VIN_LEN] = vin
    digest = hashlib.md5(output[:BODY_LEN]).digest()
    signature, quotient, recovered = forge_suffix_only_signature(digest, params)
    output[-SIGNATURE_LEN:] = signature
    stored_signature = int.from_bytes(output[-SIGNATURE_LEN:], 'big')
    checked = pow(stored_signature, params.exponent, params.modulus).to_bytes(SIGNATURE_LEN, 'big')
    weak_valid = checked[-16:] == hashlib.md5(output[:BODY_LEN]).digest()
    strict_valid = checked == strict_pkcs1_v1_5_block(digest, params)
    if not weak_valid or checked != recovered:
        raise AssertionError('generated FSC failed the vulnerable-verifier self-check')
    return Result(bytes(output), digest, quotient, checked, weak_valid, strict_valid)


def parse_appid(text: str) -> int:
    cleaned = text.strip().lower()
    try:
        value = int(cleaned.removeprefix('0x'), 16)
    except ValueError as exc:
        raise argparse.ArgumentTypeError('App ID must be hexadecimal, e.g. 017C') from exc
    if not 0 <= value <= 0xffff:
        raise argparse.ArgumentTypeError('App ID must fit in 16 bits')
    return value


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('vin7', help='exactly seven ASCII letters or digits')
    parser.add_argument('--appid', type=parse_appid, default=0x017c,
                        help='hex App ID; 017C (DME1, default) or 0180 (DME2)')
    parser.add_argument('--template', type=Path, help='optional existing FSC template')
    parser.add_argument('--output', type=Path, help='output path (default: VIN7_APPID.fsc)')
    parser.add_argument('--force', action='store_true', help='replace an existing output file')
    args = parser.parse_args()
    vin7 = args.vin7.upper()
    if not re.fullmatch(r'[A-Z0-9]{7}', vin7):
        parser.error('VIN7 must contain exactly seven ASCII letters or digits')
    if args.appid not in (0x017c, 0x0180):
        parser.error('this remote-start package supports App IDs 017C and 0180')
    output_path = args.output or Path(f'{vin7}_{args.appid:04X}.fsc')
    if output_path.exists() and not args.force:
        parser.error(f'output already exists: {output_path} (use --force to replace it)')
    params = load_parameters()
    result = build_fsc(load_template(args.template, params), vin7.encode('ascii'), args.appid, params)
    output_path.write_bytes(result.fsc)
    print(f'length={len(result.fsc)} appid=0x{args.appid:04X} vin7={vin7} '
          f'md5={result.digest.hex()} quotient={result.quotient} '
          f'weak_valid={result.weak_valid} strict_valid={result.strict_valid}')
    print(f'wrote {output_path.resolve()}')


if __name__ == '__main__':
    main()
