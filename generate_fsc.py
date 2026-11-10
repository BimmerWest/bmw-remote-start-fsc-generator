"""Generate an MDG1-format FSC from the recovered template and public parameters.

The source executable is never imported or executed. Extracted constants are
stored separately in mdg1_public_data.json. This tool runs fully offline.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path

BODY_LEN = 60
SIGNATURE_LEN = 128
VIN_OFFSET = 26
VIN_LEN = 7
APPID_OFFSET = 2
FSC_LEN = BODY_LEN + SIGNATURE_LEN
MD5_LEN = 16
LOW_BITS_MODULUS = 1 << (MD5_LEN * 8)
MAX_QUOTIENT = 256
REMOTE_START_APP_IDS = (0x017C, 0x0180)
PUBLIC_DATA_PATH = Path(__file__).with_name('mdg1_public_data.json')


@dataclass(frozen=True)
class Parameters:
    modulus: int
    exponent: int
    template: bytes
    md5_digest_info_prefix: bytes


@dataclass(frozen=True)
class Result:
    fsc: bytes
    digest: bytes
    quotient: int
    weak_valid: bool
    strict_valid: bool


def load_parameters(path: Path | None = None) -> Parameters:
    """Read the extracted public key and built-in FSC template."""
    path = PUBLIC_DATA_PATH if path is None else path
    data = json.loads(path.read_text(encoding='utf-8'))
    modulus = int.from_bytes(bytes.fromhex(data['public_modulus_little_endian_hex']), 'little')
    template = bytes.fromhex(data['built_in_template_hex'])
    if modulus.bit_length() > SIGNATURE_LEN * 8 or modulus <= 0:
        raise ValueError('public modulus has an invalid size')
    if len(template) < FSC_LEN:
        raise ValueError('built-in FSC template is incomplete')
    exponent = int(data['public_exponent'])
    if exponent != 3:
        raise ValueError('this implementation requires public exponent 3')
    return Parameters(
        modulus=modulus,
        exponent=exponent,
        template=template,
        md5_digest_info_prefix=bytes.fromhex(data['md5_digest_info_prefix_hex']),
    )


def floor_cuberoot(value: int) -> int:
    """Find the largest integer whose cube is no greater than value."""
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
    """Find the cube root of an odd residue modulo 2^128."""
    value %= LOW_BITS_MODULUS
    if value & 1 == 0:
        raise ValueError('value must be odd')
    inverse_of_three = pow(3, -1, LOW_BITS_MODULUS >> 1)
    root = pow(value, inverse_of_three, LOW_BITS_MODULUS)
    if pow(root, 3, LOW_BITS_MODULUS) != value:
        raise AssertionError('internal modular cube-root failure')
    return root


def forge_suffix_only_signature(digest: bytes, params: Parameters) -> tuple[bytes, int]:
    """Construct a signature satisfying the selected ECU's 16-byte comparison."""
    if len(digest) != MD5_LEN:
        raise ValueError('MD5 digest must be 16 bytes')
    digest_int = int.from_bytes(digest, 'big')
    for quotient in range(MAX_QUOTIENT):
        # For s^3 = q*N + m, make the low 128 bits of m equal the digest.
        target_low = (digest_int + quotient * params.modulus) % LOW_BITS_MODULUS
        if target_low & 1 == 0:
            continue
        residue = odd_cube_root_mod_2_128(target_low)
        lower = ceil_cuberoot(quotient * params.modulus)
        upper = floor_cuberoot((quotient + 1) * params.modulus - 1)
        if residue > upper:
            continue
        lift = (upper - residue) // LOW_BITS_MODULUS
        candidate = residue + lift * LOW_BITS_MODULUS
        if candidate < lower or candidate >= params.modulus:
            continue
        recovered = pow(candidate, params.exponent, params.modulus).to_bytes(SIGNATURE_LEN, 'big')
        if recovered[-MD5_LEN:] != digest:
            continue
        return candidate.to_bytes(SIGNATURE_LEN, 'big'), quotient
    raise RuntimeError('could not construct a suffix-only signature')


def strict_pkcs1_v1_5_block(digest: bytes, params: Parameters) -> bytes:
    digest_info = params.md5_digest_info_prefix + digest
    padding_len = SIGNATURE_LEN - len(digest_info) - 3
    if padding_len < 8:
        raise ValueError('RSA modulus is too short for DigestInfo')
    return b'\x00\x01' + b'\xff' * padding_len + b'\x00' + digest_info


def load_template(path: Path | None, params: Parameters) -> bytes:
    """Keep the 60-byte body and trailing signature from a template file."""
    data = params.template if path is None else path.read_bytes()
    if len(data) < FSC_LEN:
        raise ValueError(f'template is {len(data)} bytes; need at least {FSC_LEN} bytes')
    return data[:BODY_LEN] + data[-SIGNATURE_LEN:]


def build_fsc(template: bytes | bytearray, vin: bytes, appid: int, params: Parameters) -> Result:
    """Build a record without changing the caller's template."""
    if len(template) != FSC_LEN:
        raise ValueError(f'template must be exactly {FSC_LEN} bytes')
    if not re.fullmatch(rb'[A-Z0-9]{7}', vin):
        raise ValueError('VIN must contain exactly seven ASCII letters or digits')
    if appid not in REMOTE_START_APP_IDS:
        raise ValueError('remote-start App ID must be 017C or 0180')
    output = bytearray(template)
    output[APPID_OFFSET:APPID_OFFSET + 2] = appid.to_bytes(2, 'big')
    output[VIN_OFFSET:VIN_OFFSET + VIN_LEN] = vin
    digest = hashlib.md5(output[:BODY_LEN]).digest()
    signature, quotient = forge_suffix_only_signature(digest, params)
    output[-SIGNATURE_LEN:] = signature
    checked = pow(int.from_bytes(signature, 'big'), params.exponent, params.modulus)
    checked = checked.to_bytes(SIGNATURE_LEN, 'big')
    weak_valid = checked[-MD5_LEN:] == digest
    strict_valid = checked == strict_pkcs1_v1_5_block(digest, params)
    if not weak_valid:
        raise AssertionError('generated FSC failed its signature self-check')
    return Result(bytes(output), digest, quotient, weak_valid, strict_valid)


def parse_appid(text: str) -> int:
    cleaned = text.strip().lower()
    try:
        value = int(cleaned.removeprefix('0x'), 16)
    except ValueError as exc:
        raise argparse.ArgumentTypeError('App ID must be hexadecimal, e.g. 017C') from exc
    if not 0 <= value <= 0xffff:
        raise argparse.ArgumentTypeError('App ID must fit in 16 bits')
    return value


def main(argv: list[str] | None = None) -> int:
    """Parse CLI arguments, generate the record, and write it once."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('vin7', help='exactly seven ASCII letters or digits')
    parser.add_argument('--appid', type=parse_appid, default=0x017c,
                        help='hex App ID; 017C (DME1, default) or 0180 (DME2)')
    parser.add_argument('--template', type=Path, help='optional existing FSC template')
    parser.add_argument('--output', type=Path, help='output path (default: VIN7_APPID.fsc)')
    parser.add_argument('--force', action='store_true', help='replace an existing output file')
    args = parser.parse_args(argv)
    vin7 = args.vin7.upper()
    if not re.fullmatch(r'[A-Z0-9]{7}', vin7):
        parser.error('VIN7 must contain exactly seven ASCII letters or digits')
    if args.appid not in REMOTE_START_APP_IDS:
        parser.error('this remote-start package supports App IDs 017C and 0180')
    output_path = args.output or Path(f'{vin7}_{args.appid:04X}.fsc')
    try:
        params = load_parameters()
        template = load_template(args.template, params)
        result = build_fsc(template, vin7.encode('ascii'), args.appid, params)
        with output_path.open('wb' if args.force else 'xb') as output_file:
            output_file.write(result.fsc)
    except FileExistsError:
        parser.error(f'output already exists: {output_path} (use --force to replace it)')
    except (OSError, ValueError, KeyError) as exc:
        parser.error(str(exc))
    print(f'length={len(result.fsc)} appid=0x{args.appid:04X} vin7={vin7} '
          f'md5={result.digest.hex()} quotient={result.quotient} '
          f'weak_valid={result.weak_valid} strict_valid={result.strict_valid}')
    print(f'wrote {output_path.resolve()}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
