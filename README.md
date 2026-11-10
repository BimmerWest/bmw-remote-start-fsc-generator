# BimmerWest FSC Lab

Internal browser tool for creating an MDG1 remote-start FSC record. This branch contains only the web implementation in `docs/` and its JavaScript tests. It has no runtime dependencies or build step.

## Use locally

Serve the repository with a local static web server, then open `/docs/`. For example:

```powershell
npx http-server .
```

Enter the last seven VIN characters, select App ID `017C` (DME1) or `0180` (DME2), and download the generated `.fsc` file. You can optionally supply an existing FSC as the template. The VIN and template are processed in the browser; the page does not upload them or collect computer identifiers.

The output is 188 bytes: a 60-byte record body and a 128-byte signature. The browser code and extracted public parameters are in `docs/`. Neither a private key nor vehicle data is included in this branch.

## Check the output

Run the JavaScript tests with Node.js:

```powershell
node --test tests/test_browser.mjs
```

The tests check the MD5 implementation, two known output hashes, template handling, and VIN validation.

## Scope

The generated signature satisfies the comparison traced in one selected MDG1 software version: `low128(signature³ mod N) == MD5(body)`. This does not establish acceptance on other ECU versions, successful installation, or remote-start activation on a vehicle. Compatibility with a G30 B58 DME_BAC2 has not been established.

GitHub Pages is **not enabled**. BimmerWest's GitHub Free plan does not provide private Pages publishing for this private organization repository. Keep this branch private for internal use.
