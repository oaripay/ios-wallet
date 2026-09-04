import CryptoKit
import EbsiW3CBackend
import Foundation
import IdentityDomain
import Testing

struct OpenID4VPRequestObjectValidatorTests {
    @Test("Signed presentation request is verified before claims are trusted")
    func verifiesRequest() async throws {
        let key = P256.Signing.PrivateKey()
        let did = try KeyDIDResolver().derive(publicKeyX963: key.publicKey.x963Representation)
        let document = try await KeyDIDResolver().resolve(did)
        let kid = try #require(document.authentication.first)
        let jwt = try Self.sign(
            key: key,
            header: ["alg": "ES256", "typ": "oauth-authz-req+jwt", "kid": kid],
            payload: [
                "client_id": "decentralized_identifier:\(did)",
                "response_type": "vp_token",
                "response_mode": "ia_post",
                "nonce": "nonce-value",
                "exp": Int(Date().timeIntervalSince1970) + 300,
                "dcql_query": ["credentials": [["id": "pid", "format": "dc+sd-jwt"]]],
                "client_metadata": ["vp_formats_supported": [
                    "dc+sd-jwt": ["kb-jwt_alg_values": ["ES256"]],
                ]],
            ]
        )
        let request = try await NativeOpenID4VPRequestObjectValidator(
            resolver: KeyDIDResolver()
        ).validate(compactJWT: jwt, at: Date())
        #expect(request.nonce == "nonce-value")
        #expect(request.responseMode == "ia_post")
        #expect(request.signingDID == did)
        #expect(request.vpFormatsSupported?["dc+sd-jwt"] == ["ES256"])
    }

    @Test("Tampered presentation request is rejected")
    func rejectsTampering() async throws {
        let key = P256.Signing.PrivateKey()
        let did = try KeyDIDResolver().derive(publicKeyX963: key.publicKey.x963Representation)
        let document = try await KeyDIDResolver().resolve(did)
        let kid = try #require(document.authentication.first)
        let jwt = try Self.sign(
            key: key,
            header: ["alg": "ES256", "typ": "oauth-authz-req+jwt", "kid": kid],
            payload: [
                "client_id": "decentralized_identifier:\(did)",
                "response_type": "vp_token",
                "response_mode": "ia_post",
                "nonce": "nonce-value",
                "exp": Int(Date().timeIntervalSince1970) + 300,
                "dcql_query": ["credentials": [["id": "pid"]]],
            ]
        )
        var parts = jwt.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        let first = try #require(parts[2].first)
        parts[2].replaceSubrange(parts[2].startIndex...parts[2].startIndex, with: first == "A" ? "B" : "A")
        let tampered = parts.joined(separator: ".")
        await #expect(throws: OpenID4VCBackendError.invalidPresentationChallenge(reason: "signed request signature was invalid")) {
            _ = try await NativeOpenID4VPRequestObjectValidator(
                resolver: KeyDIDResolver()
            ).validate(compactJWT: tampered, at: Date())
        }
    }

    @Test("decentralized_identifier client ID is bound to the signing DID")
    func rejectsMismatchedDecentralizedIdentifier() async throws {
        let key = P256.Signing.PrivateKey()
        let did = try KeyDIDResolver().derive(publicKeyX963: key.publicKey.x963Representation)
        let document = try await KeyDIDResolver().resolve(did)
        let kid = try #require(document.authentication.first)
        let jwt = try Self.sign(
            key: key,
            header: ["alg": "ES256", "typ": "oauth-authz-req+jwt", "kid": kid],
            payload: [
                "iss": did,
                "client_id": "decentralized_identifier:did:key:another-verifier",
                "response_mode": "direct_post",
                "nonce": "nonce-value",
                "exp": Int(Date().timeIntervalSince1970) + 300,
                "dcql_query": ["credentials": [["id": "pid"]]],
            ]
        )
        await #expect(throws: OpenID4VCBackendError.invalidPresentationChallenge(
            reason: "signed request kid was not bound to client_id"
        )) {
            _ = try await NativeOpenID4VPRequestObjectValidator(
                resolver: KeyDIDResolver()
            ).validate(compactJWT: jwt, at: Date())
        }
    }

    @Test("Only the decentralized_identifier and redirect_uri client ID prefixes are supported")
    func rejectsUnsupportedClientIDPrefixes() async throws {
        let key = P256.Signing.PrivateKey()
        let did = try KeyDIDResolver().derive(publicKeyX963: key.publicKey.x963Representation)
        let document = try await KeyDIDResolver().resolve(did)
        let kid = try #require(document.authentication.first)
        for clientID in [
            "did:key:without-prefix", "https://evil.example",
            "x509_san_dns:evil.example", "redirect_uri:http://evil.example/callback",
            "redirect_uri:not-a-url", "redirect_uri:https://user@evil.example/callback",
            "redirect_uri:https://evil.example/callback#fragment",
        ] {
            let jwt = try requestJWT(key: key, kid: kid, clientID: clientID)
            await #expect(throws: OpenID4VCBackendError.invalidPresentationChallenge(reason: "unsupported client_id prefix")) {
                _ = try await NativeOpenID4VPRequestObjectValidator(resolver: KeyDIDResolver())
                    .validate(compactJWT: jwt, at: Date())
            }
        }
    }

    @Test("redirect_uri client ID accepts an unverifiable JAR envelope without a signing DID")
    func acceptsRedirectURIClientIdentifier() async throws {
        let key = P256.Signing.PrivateKey()
        var payload = requestPayload(clientID: "redirect_uri:https://verifier.example/openid/vp/1")
        payload["iss"] = "did:ebsi:zVerifier"
        payload["aud"] = "did:ebsi:zVerifier"
        payload["response_type"] = "vp_token"
        payload["response_uri"] = "https://verifier.example/openid/vp/1"
        let jwt = try Self.sign(
            key: key,
            header: ["alg": "ES256", "typ": "oauth-authz-req+jwt"],
            payload: payload
        )
        let verified = try await NativeOpenID4VPRequestObjectValidator(resolver: KeyDIDResolver())
            .validate(compactJWT: jwt, at: Date())
        #expect(verified.clientID == "redirect_uri:https://verifier.example/openid/vp/1")
        #expect(verified.signingDID == nil)
        #expect(verified.issuer == "did:ebsi:zVerifier")
        #expect(verified.audience == "did:ebsi:zVerifier")
        #expect(verified.responseURI == "https://verifier.example/openid/vp/1")
        #expect(verified.transactionData.isEmpty)
    }

    @Test("Spec-conforming transaction_data arrays are decoded for redirect_uri clients")
    func decodesTransactionDataArrayForRedirectURIClients() async throws {
        let key = P256.Signing.PrivateKey()
        var payload = requestPayload(clientID: "redirect_uri:https://verifier.example/openid/vp/1")
        // base64url({"type":"example"})
        payload["transaction_data"] = ["eyJ0eXBlIjoiZXhhbXBsZSJ9"]
        let jwt = try Self.sign(
            key: key,
            header: ["alg": "ES256", "typ": "oauth-authz-req+jwt"],
            payload: payload
        )
        let verified = try await NativeOpenID4VPRequestObjectValidator(resolver: KeyDIDResolver())
            .validate(compactJWT: jwt, at: Date())
        #expect(verified.transactionData == [OpenID4VPTransactionData(
            encoded: "eyJ0eXBlIjoiZXhhbXBsZSJ9",
            decoded: ["type": .string("example")]
        )])
    }

    @Test("iss is ignored, including when absent or mismatched")
    func ignoresIssuerClaim() async throws {
        let key = P256.Signing.PrivateKey()
        let did = try KeyDIDResolver().derive(publicKeyX963: key.publicKey.x963Representation)
        let document = try await KeyDIDResolver().resolve(did)
        let kid = try #require(document.authentication.first)
        for issuer: Any? in [nil, "did:key:attacker"] {
            var payload = requestPayload(clientID: "decentralized_identifier:\(did)")
            if let issuer { payload["iss"] = issuer }
            let jwt = try Self.sign(
                key: key,
                header: ["alg": "ES256", "typ": "oauth-authz-req+jwt", "kid": kid],
                payload: payload
            )
            let verified = try await NativeOpenID4VPRequestObjectValidator(resolver: KeyDIDResolver())
                .validate(compactJWT: jwt, at: Date())
            #expect(verified.signingDID == did)
        }
    }

    @Test("Resolved document ID must exactly match the client DID")
    func rejectsWrongDocumentID() async throws {
        let key = P256.Signing.PrivateKey()
        let did = try KeyDIDResolver().derive(publicKeyX963: key.publicKey.x963Representation)
        let document = try await KeyDIDResolver().resolve(did)
        let kid = try #require(document.authentication.first)
        let wrongDocument = DIDDocument(
            id: "did:key:wrong-document",
            verificationMethod: document.verificationMethod,
            authentication: document.authentication,
            assertionMethod: document.assertionMethod
        )
        let jwt = try requestJWT(key: key, kid: kid, clientID: "decentralized_identifier:\(did)")
        await #expect(throws: OpenID4VCBackendError.invalidPresentationChallenge(
            reason: "resolved DID document id did not match client_id"
        )) {
            _ = try await NativeOpenID4VPRequestObjectValidator(resolver: FixedResolver(document: wrongDocument))
                .validate(compactJWT: jwt, at: Date())
        }
    }

    @Test("Relative authentication references are normalized")
    func acceptsRelativeAuthenticationReference() async throws {
        let key = P256.Signing.PrivateKey()
        let did = try KeyDIDResolver().derive(publicKeyX963: key.publicKey.x963Representation)
        let document = try await KeyDIDResolver().resolve(did)
        let kid = try #require(document.authentication.first)
        let relativeAuthentication = String(kid.dropFirst(did.count))
        let relativeDocument = DIDDocument(
            id: did,
            verificationMethod: document.verificationMethod,
            authentication: [relativeAuthentication],
            assertionMethod: document.assertionMethod
        )
        let jwt = try requestJWT(key: key, kid: kid, clientID: "decentralized_identifier:\(did)")
        let verified = try await NativeOpenID4VPRequestObjectValidator(
            resolver: FixedResolver(document: relativeDocument)
        ).validate(compactJWT: jwt, at: Date())
        #expect(verified.signingDID == did)
    }

    @Test("Duplicate verification method IDs are rejected")
    func rejectsDuplicateVerificationMethodIDs() async throws {
        let key = P256.Signing.PrivateKey()
        let did = try KeyDIDResolver().derive(publicKeyX963: key.publicKey.x963Representation)
        let document = try await KeyDIDResolver().resolve(did)
        let kid = try #require(document.authentication.first)
        let method = try #require(document.verificationMethod.first)
        let duplicateDocument = DIDDocument(
            id: did,
            verificationMethod: [method, method],
            authentication: document.authentication,
            assertionMethod: document.assertionMethod
        )
        let jwt = try requestJWT(key: key, kid: kid, clientID: "decentralized_identifier:\(did)")
        await #expect(throws: OpenID4VCBackendError.invalidPresentationChallenge(
            reason: "resolved DID document contained duplicate verification method ids"
        )) {
            _ = try await NativeOpenID4VPRequestObjectValidator(
                resolver: FixedResolver(document: duplicateDocument)
            ).validate(compactJWT: jwt, at: Date())
        }
    }

    @Test("Malformed transaction data is rejected explicitly")
    func rejectsMalformedTransactionData() async throws {
        let key = P256.Signing.PrivateKey()
        let did = try KeyDIDResolver().derive(publicKeyX963: key.publicKey.x963Representation)
        let document = try await KeyDIDResolver().resolve(did)
        let kid = try #require(document.authentication.first)
        // Empty arrays, non-string entries, invalid base64url, and encoded
        // non-object JSON all violate the transaction_data definition.
        for invalid: Any in [
            ["action": "Login"], [], [42], ["not base64url!"], ["e30="], ["WyJhcnJheSJd"],
        ] {
            var payload = requestPayload(clientID: "decentralized_identifier:\(did)")
            payload["transaction_data"] = invalid
            let jwt = try Self.sign(
                key: key,
                header: ["alg": "ES256", "typ": "oauth-authz-req+jwt", "kid": kid],
                payload: payload
            )
            await #expect(throws: OpenID4VCBackendError.invalidPresentationChallenge(reason: "transaction_data was malformed")) {
                _ = try await NativeOpenID4VPRequestObjectValidator(resolver: KeyDIDResolver())
                    .validate(compactJWT: jwt, at: Date())
            }
        }
    }

    @Test("Transaction data exceeding consent display limits is rejected")
    func rejectsOversizedTransactionData() async throws {
        let key = P256.Signing.PrivateKey()
        let did = try KeyDIDResolver().derive(publicKeyX963: key.publicKey.x963Representation)
        let document = try await KeyDIDResolver().resolve(did)
        let kid = try #require(document.authentication.first)
        var payload = requestPayload(clientID: "decentralized_identifier:\(did)")
        let oversized = String(repeating: "x", count: 131_073)
        let encoded = Data("{\"value\":\"\(oversized)\"}".utf8).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        payload["transaction_data"] = [encoded]
        let request = try Self.sign(
            key: key,
            header: ["alg": "ES256", "typ": "oauth-authz-req+jwt", "kid": kid],
            payload: payload
        )

        await #expect(throws: OpenID4VCBackendError.invalidPresentationChallenge(
            reason: "transaction_data was malformed"
        )) {
            try await NativeOpenID4VPRequestObjectValidator(resolver: KeyDIDResolver())
                .validate(compactJWT: request, at: Date())
        }
    }

    @Test("Transaction data objects are decoded for DID-signed requests")
    func decodesTransactionData() async throws {
        let key = P256.Signing.PrivateKey()
        let did = try KeyDIDResolver().derive(publicKeyX963: key.publicKey.x963Representation)
        let document = try await KeyDIDResolver().resolve(did)
        let kid = try #require(document.authentication.first)
        var payload = requestPayload(clientID: "decentralized_identifier:\(did)")
        let object = Data("{\"type\":\"payment\",\"amount\":12.5,\"recurring\":false}".utf8)
            .base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        payload["transaction_data"] = [object]
        let jwt = try Self.sign(
            key: key,
            header: ["alg": "ES256", "typ": "oauth-authz-req+jwt", "kid": kid],
            payload: payload
        )
        let verified = try await NativeOpenID4VPRequestObjectValidator(resolver: KeyDIDResolver())
            .validate(compactJWT: jwt, at: Date())
        #expect(verified.transactionData == [OpenID4VPTransactionData(encoded: object, decoded: [
            "type": .string("payment"),
            "amount": .number(12.5),
            "recurring": .bool(false),
        ])])
    }

    @Test("Nonce and state are bounded URL-safe ASCII")
    func rejectsInvalidNonceAndState() async throws {
        let key = P256.Signing.PrivateKey()
        let did = try KeyDIDResolver().derive(publicKeyX963: key.publicKey.x963Representation)
        let document = try await KeyDIDResolver().resolve(did)
        let kid = try #require(document.authentication.first)
        let invalidValues = ["", "contains space", "é", String(repeating: "a", count: 513)]
        for field in ["nonce", "state"] {
            for value in invalidValues {
                var payload = requestPayload(clientID: "decentralized_identifier:\(did)")
                payload[field] = value
                let jwt = try Self.sign(
                    key: key,
                    header: ["alg": "ES256", "typ": "oauth-authz-req+jwt", "kid": kid],
                    payload: payload
                )
                await #expect(throws: OpenID4VCBackendError.invalidPresentationChallenge(
                    reason: "signed request nonce or state was invalid"
                )) {
                    _ = try await NativeOpenID4VPRequestObjectValidator(resolver: KeyDIDResolver())
                        .validate(compactJWT: jwt, at: Date())
                }
            }
        }
    }

    @Test("Replay store atomically consumes both request digest and nonce")
    func replayStoreRejectsDigestAndNonceReuse() async throws {
        let store = InMemoryOpenID4VPReplayStore(maximumEntries: 4, maximumRetention: 300)
        let now = Date()
        try await store.consume(requestDigest: "digest-1", nonce: "nonce-1", expiresAt: now.addingTimeInterval(60), at: now)
        await #expect(throws: OpenID4VCBackendError.invalidPresentationChallenge(reason: "signed request was replayed")) {
            try await store.consume(requestDigest: "digest-1", nonce: "nonce-2", expiresAt: now.addingTimeInterval(60), at: now)
        }
        await #expect(throws: OpenID4VCBackendError.invalidPresentationChallenge(reason: "signed request was replayed")) {
            try await store.consume(requestDigest: "digest-2", nonce: "nonce-1", expiresAt: now.addingTimeInterval(60), at: now)
        }
    }

    private static func sign(
        key: P256.Signing.PrivateKey,
        header: [String: Any],
        payload: [String: Any]
    ) throws -> String {
        func encode(_ object: [String: Any]) throws -> String {
            try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
                .base64EncodedString()
                .replacingOccurrences(of: "+", with: "-")
                .replacingOccurrences(of: "/", with: "_")
                .replacingOccurrences(of: "=", with: "")
        }
        let encodedHeader = try encode(header)
        let encodedPayload = try encode(payload)
        let input = Data("\(encodedHeader).\(encodedPayload)".utf8)
        let signature = try key.signature(for: input).rawRepresentation.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        return "\(encodedHeader).\(encodedPayload).\(signature)"
    }

    private func requestJWT(key: P256.Signing.PrivateKey, kid: String, clientID: String) throws -> String {
        try Self.sign(
            key: key,
            header: ["alg": "ES256", "typ": "oauth-authz-req+jwt", "kid": kid],
            payload: requestPayload(clientID: clientID)
        )
    }

    private func requestPayload(clientID: String) -> [String: Any] {
        [
            "client_id": clientID,
            "response_mode": "direct_post",
            "nonce": "nonce-value",
            "state": "state-value",
            "exp": Int(Date().timeIntervalSince1970) + 300,
            "dcql_query": ["credentials": [["id": "pid"]]],
        ]
    }
}

private struct FixedResolver: DIDResolver {
    let document: DIDDocument
    func resolve(_ did: String) async throws -> DIDDocument { document }
}
