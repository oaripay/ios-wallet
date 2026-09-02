# Oari Wallet

Oari Wallet is an open-source native SwiftUI iOS wallet for EUDI and W3C
credential interoperability. The app display name is **Oari Wallet**, the
technical target is `OariWallet`, and the bundle identifier is `io.oari.wallet`.

This repository is interoperability software. It does not claim certification,
eIDAS legal recognition, or production readiness.

## Requirements

- macOS with Xcode 26 or a compatible toolchain supporting Swift 6.2 packages.
- iOS 17 or later.
- XcodeGen when regenerating the Xcode project.
- A physical iPhone for camera scanning and device-specific secure-key behavior.

The simulator supports development fixtures and paste-based wallet URLs, but its
camera scanner reports that camera scanning is unavailable.

## Repository layout

```text
App/                 SwiftUI application and app composition
Tests/               Unit and iOS integration tests
UITests/             UI automation
Packages/Sources/    Domain, Wallet Kit, W3C, vault and design-system modules
Packages/Tests/      Package-level tests
OariWallet.xcodeproj Generated Xcode project
```

## Backends

### EUDI Wallet Kit

The pinned EUDI Wallet Kit owns EUDI wallet documents, secure keys, storage,
SD-JWT, mdoc, OpenID4VCI, OpenID4VP, DCQL, and BLE behavior. Oari owns consent,
application metadata, redacted audit, lifecycle UI, and recovery coordination.

### W3C / OpenID4VC backend

The native W3C backend owns W3C credentials and stores them encrypted locally.
It supports OpenID4VCI and OpenID4VP interoperability, EBSI DID resolution,
VCDM 1.1, VCDM 2.0, SD-JWT VC, and selected legacy issuance profiles.

The W3C backend uses one persistent canonical holder `did:key`. DPoP,
credential-response encryption, attestation, and EUDI Wallet Kit keys remain
separate because they have different protocol and lifecycle responsibilities.

## Supported flows

- EUDI mdoc and SD-JWT VC issuance and presentation through the official EUDI
  Wallet Kit.
- Official EUDI Reference Demo interoperability:
  - Issuers: `issuer.eudiw.dev` and `issuer-backend.eudiw.dev`.
  - Verifier: `verifier.eudiw.dev`.
  - Wallet Provider: `wallet-provider.eudiw.dev`.
  - Wallet Kit `0.39.1`, OpenID4VCI `0.53.0`, and OpenID4VP `0.41.0`.
   - Online ETSI reference trust lists with warning-mode ecosystem trust.
- HAIP and EUDI scheme routing:
  - `haip-vci`
  - `haip-vp`
  - `eudi-openid4vp`
  - `mdoc-openid4vp`
- W3C VCDM 1.1 JWT VC formats advertised by issuer metadata.
- W3C VCDM 2.0 `application/vc+jwt` credentials.
- Native `dc+sd-jwt` presentations with a trailing Key Binding JWT.
- OpenID4VCI pre-authorized-code and authorization-code grants.
- OpenID4VCI 1.1 Interactive Authorization using
  `authorization_challenge_endpoint` and `ia_post`.
- OpenID4VP and DCQL consent with query-ID-based `vp_token` responses.
- OpenID4VC final profiles and HTTPS issuer paths ending in `draft-13`,
  `draft-17`, or `draft-18` for legacy interoperability.

For final Interactive Authorization, the initial challenge request carries
`issuer_state` but not `auth_session`. Follow-up requests carry the server-issued
`auth_session` and `openid4vp_response`. A successful challenge response is
accepted with the standard `authorization_code` property and does not require an
OAuth redirect `state` value.

For `auth_via_web`, the wallet opens the Authorization Server's `request_uri`
request in the system Safari context. The HTTPS callback either completes the
flow with `code` or continues it with the latest `auth_session`.
Authorization Server endpoints are discovered from issuer metadata; the wallet
client identifier and registered native redirect URI are supplied separately by
app-level client registration configuration. The iOS app callback is
`oari-wallet://authorization`.

Unknown formats do not fall through as valid. Every enabled profile should have
positive and negative interoperability coverage.

## Security model

- Issuer, request-object, credential, and presentation signatures are verified.
- Credentials and holder-key references are encrypted or protected by the
  system keychain as appropriate.
- App Lock supports Face ID, Touch ID, and device-passcode fallback.
- Credential deletion requires local authentication.
- Missing persistent holder keys fail closed instead of silently rotating the
  holder DID.
- Malformed, expired, replayed, or unsupported protocol messages fail closed.

Missing signer accreditation can produce an explicit user warning. It never
disables cryptographic credential verification.

EUDI Reference Demo counterparties are accepted with explicit warning-mode
ecosystem trust. Signature verification, expiry, holder binding, nonce,
audience, HTTPS, replay checks, and user consent remain mandatory.

## Interoperability configuration

The W3C backend uses the same pinned production registry and interoperability
profile in every build configuration. HTTPS issuer paths ending in `draft-13`,
`draft-17`, or `draft-18` select the corresponding compatibility contract;
other issuers use the final contract.

EUDI Wallet Kit initializes lazily after the root UI is available. Dedicated
EUDI and HAIP requests wait for the same initializer behind a generic Oari
loading overlay. Native W3C requests remain available during this initialization.

Supported launch arguments:

```text
--fixture production|empty|populated|storage-failure
--incoming-url <wallet-url>
--disable-animations
```

## QR scanner

The scanner uses VisionKit's `DataScannerViewController` for QR recognition. The
camera and scanner mask are edge-to-edge, while interactive controls remain
inside the device safe area. A paste fallback is available when camera scanning
is unsupported or unavailable.

VisionKit owns the active camera session and does not expose supported torch
control. iOS also disables the Control Center flashlight while an application is
using the camera. Closing the scanner releases the camera and makes the system
flashlight available again.

## Build and test

Run the package test loop from the repository root:

```sh
swift test
git diff --check
```

Build the application for a simulator:

```sh
xcodebuild \
  -project OariWallet.xcodeproj \
  -scheme OariWallet \
  -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' \
  -configuration Debug \
  build CODE_SIGNING_ALLOWED=NO
```

Use an installed simulator name and OS version if `iPhone 17` with iOS 26.5 is
not available.

Run the application model tests:

```sh
xcodebuild \
  -project OariWallet.xcodeproj \
  -scheme OariWallet \
  -configuration Debug \
  -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' \
  -only-testing:WalletTests/WalletAppModelTests \
  test
```

Regenerate the project after changing `project.yml`:

```sh
xcodegen generate
```

`ReleaseTesting` is run once per completed milestone with a reused DerivedData
directory rather than after every edit.

## Known limitations

- `ia_post.jwt` encrypted Interactive Authorization responses are unsupported.
- `direct_post.jwt` and OpenID4VP 1.1 HPKE responses are unsupported by the
  native W3C backend.
- Full multi-query DCQL, credential-set evaluation, claim-set evaluation, and
  `multiple=true` are unsupported by the native W3C backend.
- Credential-status evaluation before native W3C presentation is not yet
  implemented.
- EUDI Reference Demo credential status is currently reported as not evaluated
  by the app-level status provider.
- EUDI Reference Demo is an interoperability environment, not a certified or
  production EUDI Wallet environment.
- Verifiers receiving native SD-JWT presentations must validate nonce and
  audience in the trailing Key Binding JWT, not in the issuer-signed SD-JWT.
- Interoperability trust warnings are not a substitute for a production trust,
  registration, attestation, status, and accreditation policy.
