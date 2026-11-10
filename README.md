# Remote start FSC generator (internal)

Offline Python 3.10+ reproduction of the supplied MDG1 FSC generator's core algorithm. The package uses extracted public parameters and a built-in 188-byte template. It does not use the supplied executable at runtime or need third-party Python packages.

## Use

Download and extract the internal ZIP, keeping `generate_fsc.py` and `mdg1_public_data.json` in the same folder. From that folder:

```powershell
python .\generate_fsc.py YOURVIN --appid 017C
```

Replace `YOURVIN` with the **last seven characters** of the target VIN. App ID `017C` is the DME1 remote-start record; `0180` is the DME2 record. The default output is `YOURVIN_017C.fsc` in the current directory. Set a path with `--output C:\path\to\record.fsc`. To use an existing record as the body template, add `--template C:\path\to\template.fsc`. The command refuses to overwrite an existing output unless `--force` is given.

The tool prints `weak_valid=True` after checking the signature condition that was traced in the selected ECU software. `strict_valid=False` is expected: the output is not a conventional PKCS#1 signature.

## Scope and evidence

The output is a 60-byte record body plus a 128-byte signature. App ID is written at body bytes 2–3, VIN7 at bytes 26–32, and the body is hashed with MD5. The signature construction satisfies the selected ECU software's observed condition `low128(signature^3 mod N) == MD5(body)` using the embedded public key with exponent 3.

The static ECU trace covers MDG1 DME-88T0 SWFL `00004963 070.130.005` paired with BTLD `00005C11 001.035.005`. It establishes the signature comparison for that software and identifies other record, VIN, App ID, and provisioning checks. It does not demonstrate acceptance on other ECU versions, successful installation, or remote-start activation on a vehicle. In particular, this evidence does not establish compatibility with a G30 B58 DME_BAC2. See the parent workspace's `analysis/HANDOFF_FSC_VERIFIER.md` for the full trace.

The source executable was decompiled but not executed. `mdg1_public_data.json` contains the extracted public modulus, exponent, template, and source executable SHA-256 for provenance. Neither a private key nor vehicle data is included in this repository.

## Verify the package

```powershell
python -m unittest discover -s tests -v
```

The tests compare two deterministic FSC hashes and check the weak and strict signature predicates. Generated `.fsc` files are ignored by Git; treat them as vehicle-specific data and distribute this package only through your internal channel.

## Browser version (Pages source branch)

The `web-version` branch adds a dependency-free browser version in `docs/`. It uses the same public parameters and creates the FSC entirely in the browser; it does not collect computer identifiers or upload the VIN. Run it locally from the repository root with:

```powershell
python -m http.server 8000
```

Open `http://localhost:8000/docs/`. The page also accepts an optional template FSC file, matching the Python tool. The browser code is checked with `node --test tests/test_browser.mjs`; its known output hashes match the Python implementation.

GitHub Pages is **not enabled**. BimmerWest is on GitHub Free, which does not offer private Pages publishing for this private organization repository. Publishing a Pages site publicly would conflict with the internal-use scope.
