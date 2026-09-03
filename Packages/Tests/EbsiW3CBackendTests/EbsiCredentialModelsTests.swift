import CryptoKit
import EbsiW3CBackend
import Foundation
import IdentityDomain
import Testing

struct EbsiCredentialModelsTests {
    @Test("VCDM2 VC JWT profile parses top-level credential and ES256")
    func vcdm2JWT() throws {
        let profile = try EbsiCredentialProfile.vcdm2JWTVC()
        let token = try compactJWT(
            header: ["alg": "ES256", "typ": "vc+jwt"],
            payload: [
                "@context": ["https://www.w3.org/ns/credentials/v2"],
                "type": ["VerifiableCredential", "CarrierLicense"],
                "issuer": "did:ebsi:issuer",
                "credentialSubject": ["id": "did:key:holder"],
                "credentialSchema": ["id": "https://ebsi.oari.io/schema", "type": "FullJsonSchemaValidator2021"],
                "credentialStatus": ["type": "BitstringStatusListEntry"],
                "termsOfUse": ["type": "IssuanceCertificate"],
            ]
        )
        let credential = try EbsiCredentialInspector().inspectCompactJWT(token, profile: profile)
        #expect(credential["issuer"] == .string("did:ebsi:issuer"))
    }

    @Test("Profile rejects wrong context and algorithm")
    func profileMismatch() throws {
        let profile = try EbsiCredentialProfile.vcdm2JWTVC()
        let wrong = try compactJWT(
            header: ["alg": "RS256", "typ": "vc+jwt"],
            payload: ["@context": ["https://www.w3.org/2018/credentials/v1"], "type": ["VerifiableCredential"]]
        )
        #expect(throws: EbsiCredentialError.algorithmNotAllowed) {
            _ = try EbsiCredentialInspector().inspectCompactJWT(wrong, profile: profile)
        }
    }

    @Test("VCDM2 profile rejects nested V1 payload and missing schema status or terms")
    func exactVCDM2Profile() throws {
        let profile = try EbsiCredentialProfile.vcdm2JWTVC()
        let base: [String: Any] = [
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential"],
            "credentialSubject": ["id": "did:key:holder"],
        ]
        for payload in [
            ["vc": base],
            base.merging(["@context": ["https://www.w3.org/2018/credentials/v1"]]) { _, new in new },
        ] {
            let token = try compactJWT(header: ["alg": "ES256", "typ": "vc+jwt"], payload: payload)
            #expect(throws: EbsiCredentialError.profileMismatch) {
                _ = try EbsiCredentialInspector().inspectCompactJWT(token, profile: profile)
            }
        }
    }

    @Test("VCDM2 enforces context, type, issuer, and subject structure")
    func strictVCDM2Structure() throws {
        let profile = try EbsiCredentialProfile.vcdm2JWTVC()
        let valid: [String: Any] = [
            "@context": ["https://www.w3.org/ns/credentials/v2", ["name": "https://schema.org/name"]],
            "type": ["VerifiableCredential", "EmployeeCredential"],
            "issuer": ["id": "https://issuer.example"],
            "credentialSubject": [["id": "did:key:first"], ["id": "did:key:holder"]],
        ]
        let accepted = try compactJWT(
            header: ["alg": "ES256", "typ": "vc+jwt"],
            payload: valid
        )
        #expect(try EbsiCredentialInspector().inspectCompactJWT(accepted, profile: profile)["type"] != nil)

        let invalidValues: [[String: Any]] = [
            valid.merging(["@context": ["https://example.org/context", "https://www.w3.org/ns/credentials/v2"]]) { _, new in new },
            valid.merging(["type": ["EmployeeCredential"]]) { _, new in new },
            valid.merging(["issuer": "not a uri"]) { _, new in new },
            valid.merging(["credentialSubject": []]) { _, new in new },
            valid.merging(["credentialSubject": ["did:key:holder"]]) { _, new in new },
        ]
        for payload in invalidValues {
            let token = try compactJWT(header: ["alg": "ES256", "typ": "vc+jwt"], payload: payload)
            #expect(throws: EbsiCredentialError.profileMismatch) {
                _ = try EbsiCredentialInspector().inspectCompactJWT(token, profile: profile)
            }
        }
    }

    @Test("VCDM2 validity and VC-JOSE registered claims are consistent at validation time")
    func vcdm2ValidityAndRegisteredClaims() throws {
        let profile = try EbsiCredentialProfile.vcdm2JWTVC()
        let now = Date(timeIntervalSince1970: 1_800_000_000)
        let validFrom = "2027-01-15T07:59:00Z"
        let validUntil = "2027-01-15T08:01:00Z"
        let payload: [String: Any] = [
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential"],
            "id": "urn:uuid:credential",
            "issuer": "https://issuer.example",
            "credentialSubject": ["id": "did:key:holder"],
            "validFrom": validFrom,
            "validUntil": validUntil,
            "iss": "https://issuer.example",
            "sub": "did:key:holder",
            "jti": "urn:uuid:credential",
            "nbf": 1_799_999_940,
            "exp": 1_800_000_060,
        ]
        let validationDate = now
        let token = try compactJWT(header: ["alg": "ES256", "typ": "vc+jwt"], payload: payload)
        _ = try EbsiCredentialInspector().inspectCompactJWT(
            token,
            profile: profile,
            validationDate: validationDate
        )

        for mutation in [
            ["iss": "https://attacker.example"],
            ["sub": "did:key:attacker"],
            ["jti": "urn:uuid:other"],
            ["nbf": 0],
            ["exp": 0],
        ] {
            let invalid = payload.merging(mutation) { _, new in new }
            let invalidToken = try compactJWT(header: ["alg": "ES256", "typ": "vc+jwt"], payload: invalid)
            #expect(throws: EbsiCredentialError.profileMismatch) {
                _ = try EbsiCredentialInspector().inspectCompactJWT(
                    invalidToken,
                    profile: profile,
                    validationDate: validationDate
                )
            }
        }

        for date in [
            try #require(ISO8601DateFormatter().date(from: "2027-01-15T07:58:59Z")),
            try #require(ISO8601DateFormatter().date(from: validUntil)),
        ] {
            #expect(throws: EbsiCredentialError.profileMismatch) {
                _ = try EbsiCredentialInspector().inspectCompactJWT(token, profile: profile, validationDate: date)
            }
        }
    }

    @Test("VCDM2 permits equal validity bounds")
    func vcdm2EqualValidityBounds() throws {
        let timestamp = "2027-01-15T08:00:00Z"
        let token = try compactJWT(
            header: ["alg": "ES256", "typ": "vc+jwt"],
            payload: [
                "@context": ["https://www.w3.org/ns/credentials/v2"],
                "type": ["VerifiableCredential"],
                "issuer": "https://issuer.example",
                "credentialSubject": ["name": "Ada"],
                "validFrom": timestamp,
                "validUntil": timestamp,
            ]
        )
        _ = try EbsiCredentialInspector().inspectCompactJWT(token, profile: .vcdm2JWTVC())
    }

    @Test("VCDM2 requires vc+jwt typ while VCDM 1.1 keeps nested legacy behavior")
    func joseTypeAndLegacyVCDM11() throws {
        let v2Payload: [String: Any] = [
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential"],
            "issuer": "did:example:issuer",
            "credentialSubject": ["id": "did:example:holder"],
        ]
        let wrongType = try compactJWT(header: ["alg": "ES256", "typ": "JWT"], payload: v2Payload)
        #expect(throws: EbsiCredentialError.profileMismatch) {
            _ = try EbsiCredentialInspector().inspectCompactJWT(wrongType, profile: .vcdm2JWTVC())
        }

        let legacy = try compactJWT(header: ["alg": "ES256", "typ": "JWT"], payload: [
            "iss": "did:example:issuer",
            "nbf": 1_700_000_000,
            "sub": "did:example:holder",
            "vc": [
                "@context": ["https://www.w3.org/2018/credentials/v1"],
                "type": ["VerifiableCredential", "ExampleCredential"],
            ],
        ])
        let inspected = try EbsiCredentialInspector().inspectCompactJWT(legacy, profile: .vcdm11Jwt())
        #expect(inspected["issuer"] == .string("did:example:issuer"))
        #expect(inspected["credentialSubject"]?.object?["id"] == .string("did:example:holder"))
    }

    @Test("Native validator applies VCDM2 validity and array subject binding at its validation date")
    func nativeVCDM2Validation() async throws {
        let key = P256.Signing.PrivateKey()
        let resolver = KeyDIDResolver()
        let issuer = try resolver.derive(publicKeyX963: key.publicKey.x963Representation)
        let kid = try #require((try await resolver.resolve(issuer)).assertionMethod.first)
        let holder = "did:example:holder"
        let payload: [String: Any] = [
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential", "EmployeeCredential"],
            "issuer": issuer,
            "iss": issuer,
            "credentialSubject": [["id": "did:example:other"], ["id": holder]],
            "validFrom": "2027-01-15T07:59:00Z",
            "validUntil": "2027-01-15T08:01:00Z",
        ]
        let token = try signedCompactJWT(key: key, kid: kid, payload: payload)
        let validator = NativeW3CCredentialValidator(resolver: resolver)
        let validationDate = Date(timeIntervalSince1970: 1_800_000_000)
        let result = try await validator.validate(
            rawCredential: Data(token.utf8),
            profile: .vcdm2JWTVC(),
            expectedIssuer: issuer,
            expectedHolderDID: holder,
            at: validationDate
        )
        #expect(result == issuer)

        await #expect(throws: EbsiCredentialError.profileMismatch) {
            try await validator.validate(
                rawCredential: Data(token.utf8),
                profile: .vcdm2JWTVC(),
                expectedIssuer: issuer,
                expectedHolderDID: holder,
                at: validationDate.addingTimeInterval(60)
            )
        }
    }

    @Test("Standard SD-JWT VC permits optional cnf while the VCDM profile requires it")
    func standardSDJWTVC() throws {
        let token = try compactJWT(
            header: ["alg": "ES256"],
            payload: ["iss": "https://issuer.example", "vct": "urn:example:pid"]
        ) + "~"
        let inspector = EbsiCredentialInspector()
        #expect(throws: EbsiCredentialError.profileMismatch) {
            _ = try inspector.inspectSDJWT(token)
        }
        let payload = try inspector.inspectSDJWT(token, requiresHolderBinding: false)
        #expect(payload["vct"] == .string("urn:example:pid"))
    }

    @Test("Native validator downgrades only unavailable did:ebsi resolution")
    func unavailableEBSIResolutionOutcome() async throws {
        let issuer = "did:ebsi:zyUnavailableIssuer"
        let holder = "did:key:zHolder"
        let token = try compactJWT(
            header: ["alg": "ES256", "typ": "vc+jwt"],
            payload: [
                "@context": ["https://www.w3.org/ns/credentials/v2"],
                "type": ["VerifiableCredential", "EmployeeCredential"],
                "issuer": issuer,
                "iss": issuer,
                "credentialSubject": ["id": holder],
                "validFrom": "2027-01-15T07:59:00Z",
                "validUntil": "2027-01-15T08:01:00Z",
            ]
        )
        let validator = NativeW3CCredentialValidator(resolver: UnavailableDIDResolver())
        let outcome = try await validator.validateAllowingUnavailableEBSIDID(
            rawCredential: Data(token.utf8),
            profile: .vcdm2JWTVC(),
            expectedIssuer: nil,
            expectedHolderDID: holder,
            at: Date(timeIntervalSince1970: 1_800_000_000)
        )
        #expect(outcome == .ebsiDIDResolutionUnavailable(issuer: issuer))

        await #expect(throws: EbsiCredentialError.issuerDIDUnresolved) {
            try await validator.validate(
                rawCredential: Data(token.utf8),
                profile: .vcdm2JWTVC(),
                expectedIssuer: nil,
                expectedHolderDID: holder,
                at: Date(timeIntervalSince1970: 1_800_000_000)
            )
        }
    }

    private func compactJWT(header: Any, payload: Any) throws -> String {
        func encode(_ value: Any) throws -> String {
            try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])
                .base64EncodedString()
                .replacingOccurrences(of: "+", with: "-")
                .replacingOccurrences(of: "/", with: "_")
                .replacingOccurrences(of: "=", with: "")
        }
        return try "\(encode(header)).\(encode(payload)).signature"
    }

    private func signedCompactJWT(
        key: P256.Signing.PrivateKey,
        kid: String,
        payload: [String: Any]
    ) throws -> String {
        func encode(_ value: Any) throws -> String {
            try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])
                .base64EncodedString()
                .replacingOccurrences(of: "+", with: "-")
                .replacingOccurrences(of: "/", with: "_")
                .replacingOccurrences(of: "=", with: "")
        }
        let header = try encode(["alg": "ES256", "kid": kid, "typ": "vc+jwt"])
        let claims = try encode(payload)
        let signingInput = Data("\(header).\(claims)".utf8)
        let signature = try key.signature(for: signingInput).rawRepresentation
            .base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        return "\(header).\(claims).\(signature)"
    }
}

private struct UnavailableDIDResolver: DIDResolver {
    func resolve(_ did: String) async throws -> DIDDocument {
        throw DIDResolutionError.registryUnavailable
    }
}
