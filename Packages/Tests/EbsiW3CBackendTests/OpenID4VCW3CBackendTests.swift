import CryptoKit
import EbsiW3CBackend
import Foundation
import IdentityDomain
import Testing
import TrustDomain
import WalletDomain

private extension OpenID4VCW3CBackend {
    init(
        transport: any OpenID4VCHTTPTransport,
        trustEvaluator: any CredentialIssuerServiceTrustEvaluating,
        credentialSignerTrustEvaluator: (any CredentialSignerTrustEvaluating)? = nil,
        keyProvider: any KeyProvider,
        credentialStore: any EbsiCredentialStore,
        credentialValidator: any W3CCredentialValidating,
        profile: EbsiCredentialProfile,
        additionalProfiles: [EbsiCredentialProfile] = [],
        clientSecurity: (any OID4VCIClientSecurity)? = nil,
        transportProfileRegistry: OID4VCITransportProfileRegistry = .finalOnly,
        holderIdentityProvider: (any W3CHolderIdentityProviding)? = nil,
        presentationRequestValidator: (any OpenID4VPRequestObjectValidating)? = nil,
        presentationReplayProtection: any OpenID4VPReplayProtecting = InMemoryOpenID4VPReplayStore(),
        trustEnvironment: EbsiTrustEnvironment = .development,
        now: @escaping @Sendable () -> Date = Date.init
    ) {
        self.init(
            transport: transport,
            trustEvaluator: trustEvaluator,
            credentialSignerTrustEvaluator: credentialSignerTrustEvaluator,
            keyProvider: keyProvider,
            credentialStore: credentialStore,
            credentialValidator: credentialValidator,
            profile: profile,
            clientConfiguration: try! OpenID4VCClientConfiguration(
                clientID: "generic-wallet-client",
                redirectURI: URL(string: "https://wallet.example/callback")!
            ),
            additionalProfiles: additionalProfiles,
            clientSecurity: clientSecurity,
            transportProfileRegistry: transportProfileRegistry,
            holderIdentityProvider: holderIdentityProvider,
            presentationRequestValidator: presentationRequestValidator,
            presentationReplayProtection: presentationReplayProtection,
            trustEnvironment: trustEnvironment,
            now: now
        )
    }
}

private final class DeferredTestClock: @unchecked Sendable {
    private let lock = NSLock()
    private var date: Date

    init(_ date: Date) { self.date = date }

    var value: Date {
        lock.lock()
        defer { lock.unlock() }
        return date
    }

    func advance(by interval: TimeInterval) {
        lock.lock()
        date = date.addingTimeInterval(interval)
        lock.unlock()
    }
}

struct OpenID4VCW3CBackendTests {
    @Test("Wallet redirect configuration accepts the registered HTTPS URI")
    func walletRedirectConfiguration() throws {
        let configuration = try OpenID4VCClientConfiguration(
            clientID: "io.oari.wallet",
            redirectURI: URL(string: "https://wallet.ios.oari.io/oauth/callback")!
        )
        #expect(configuration.redirectURI.absoluteString == "https://wallet.ios.oari.io/oauth/callback")
    }

    @Test("Unsafe native wallet redirects are rejected", arguments: [
        "http://wallet.example/callback",
        "file://authorization",
        "https://wallet.ios.oari.io/oauth/callback?code=injected",
        "https://wallet.ios.oari.io/oauth/callback#fragment",
    ])
    func unsafeNativeWalletRedirectConfiguration(value: String) {
        #expect(throws: OpenID4VCBackendError.unsafeEndpoint) {
            try OpenID4VCClientConfiguration(
                clientID: "io.oari.wallet",
                redirectURI: URL(string: value)!
            )
        }
    }

    @Test("Final response is persisted and restored before local credential commit")
    func finalDeferredIssuance() async throws {
        let transport = FixtureOpenID4VCTransport(deferredInterval: 1)
        let store = FixtureCredentialStore()
        let clock = DeferredTestClock(Date(timeIntervalSince1970: 1_800_000_000))
        let backend = OpenID4VCW3CBackend(
            transport: transport,
            trustEvaluator: TrustedIssuerEvaluator(),
            keyProvider: FixtureKeyProvider(),
            credentialStore: store,
            credentialValidator: FixtureCredentialValidator(),
            profile: try .vcdm2JWTVC(),
            now: { clock.value }
        )
        let offer = try await backend.resolveOffer("https://issuer.example/offer")
        let initial = try await backend.issueOutcome(
            id: offer.id, allowUntrusted: false, transactionCode: "123456"
        )
        guard case let .deferred(deferred) = initial else {
            Issue.record("Expected a deferred outcome")
            return
        }
        await #expect(throws: OpenID4VCBackendError.unknownTransaction) {
            _ = try await backend.issueOutcome(
                id: offer.id, allowUntrusted: false, transactionCode: "123456"
            )
        }
        #expect(deferred.configurationIDs == ["example-vcdm2-jwt-vc"])
        #expect(try await store.credentials().isEmpty)
        let encodedState = try JSONEncoder().encode(deferred)
        let restoredState = try JSONDecoder().decode(DeferredW3CCredential.self, from: encodedState)
        clock.advance(by: 1)
        let restoredBackend = OpenID4VCW3CBackend(
            transport: transport,
            trustEvaluator: TrustedIssuerEvaluator(),
            keyProvider: FixtureKeyProvider(),
            credentialStore: store,
            credentialValidator: FixtureCredentialValidator(),
            profile: try .vcdm2JWTVC(),
            now: { clock.value }
        )
        let finalResponse = try await restoredBackend.retrieveDeferredCredential(restoredState)
        guard case let .deferred(finalCheckpoint) = finalResponse else {
            Issue.record("Expected a final local-completion checkpoint")
            return
        }
        #expect(finalCheckpoint.remoteTransactionIDs.isEmpty)
        #expect(finalCheckpoint.stagedCredentials.count == 1)
        #expect(finalCheckpoint.nextPollAt == clock.value)
        #expect(try await store.credentials().isEmpty)
        #expect(!(await transport.requests).contains { $0.url.path == "/notification" })

        let persistedFinalCheckpoint = try JSONEncoder().encode(finalCheckpoint)
        let restoredFinalCheckpoint = try JSONDecoder().decode(
            DeferredW3CCredential.self, from: persistedFinalCheckpoint
        )
        let completionBackend = OpenID4VCW3CBackend(
            transport: transport,
            trustEvaluator: TrustedIssuerEvaluator(),
            keyProvider: FixtureKeyProvider(),
            credentialStore: store,
            credentialValidator: FixtureCredentialValidator(),
            profile: try .vcdm2JWTVC(),
            now: { clock.value }
        )
        let completed = try await completionBackend.retrieveDeferredCredential(restoredFinalCheckpoint)
        guard case let .issued(credentials) = completed else {
            Issue.record("Expected an issued outcome")
            return
        }
        #expect(credentials.count == 1)
        #expect(try await store.credentials().count == 1)
        #expect((await transport.requests).contains { $0.url.path == "/notification" })
        let request = try #require((await transport.requests).first { $0.url.path == "/deferred" })
        #expect(request.method == "POST")
        #expect(request.headers["Authorization"] == "Bearer access")
        let body = try #require(request.body)
        let object = try #require(JSONSerialization.jsonObject(with: body) as? [String: String])
        #expect(object == ["transaction_id": "transaction-1"])
    }

    @Test("Each retrieval checkpoints one ready transaction before requesting the next")
    func deferredBatchCheckpointsEachTransaction() async throws {
        let transport = FixtureOpenID4VCTransport(
            deferredInterval: 1,
            twoDeferredConfigurations: true,
            secondDeferredFails: true
        )
        let store = FixtureCredentialStore()
        let clock = DeferredTestClock(Date(timeIntervalSince1970: 1_800_000_000))
        let backend = OpenID4VCW3CBackend(
            transport: transport, trustEvaluator: TrustedIssuerEvaluator(),
            keyProvider: FixtureKeyProvider(), credentialStore: store,
            credentialValidator: FixtureCredentialValidator(), profile: try .vcdm2JWTVC(),
            now: { clock.value }
        )
        let offer = try await backend.resolveOffer("https://issuer.example/offer")
        let initial = try await backend.issueOutcome(
            id: offer.id, allowUntrusted: false, transactionCode: "123456"
        )
        guard case let .deferred(state) = initial else {
            Issue.record("Expected two deferred transactions")
            return
        }
        clock.advance(by: 1)
        let firstPoll = try await backend.retrieveDeferredCredential(state)
        guard case let .deferred(checkpoint) = firstPoll else {
            Issue.record("Expected a checkpoint after the first ready credential")
            return
        }
        #expect(checkpoint.remoteTransactionIDs == ["second-vcdm2-jwt-vc": "transaction-2"])
        #expect(checkpoint.stagedCredentials.count == 1)
        #expect(checkpoint.stagedCredentials.first?.issued.configurationID == "example-vcdm2-jwt-vc")
        #expect(try await store.credentials().isEmpty)

        await #expect(throws: OpenID4VCBackendError.remoteHTTPError(status: 500, detail: "second failed")) {
            _ = try await backend.retrieveDeferredCredential(checkpoint)
        }
        await #expect(throws: OpenID4VCBackendError.remoteHTTPError(status: 500, detail: "second failed")) {
            _ = try await backend.retrieveDeferredCredential(checkpoint)
        }
        let deferredBodies = try (await transport.requests)
            .filter { $0.url.path == "/deferred" }
            .map { request -> String in
                let body = try #require(request.body)
                let object = try #require(JSONSerialization.jsonObject(with: body) as? [String: String])
                return try #require(object["transaction_id"])
            }
        #expect(deferredBodies.filter { $0 == "transaction-1" }.count == 1)
        #expect(deferredBodies.filter { $0 == "transaction-2" }.count == 2)
        #expect(try await store.credentials().isEmpty)
    }

    @Test("Deferred retrieval enforces the issuer interval before network access")
    func deferredIntervalEnforced() async throws {
        let transport = FixtureOpenID4VCTransport(deferredInterval: 30)
        let instant = Date(timeIntervalSince1970: 1_800_000_000)
        let backend = OpenID4VCW3CBackend(
            transport: transport,
            trustEvaluator: TrustedIssuerEvaluator(),
            keyProvider: FixtureKeyProvider(),
            credentialStore: FixtureCredentialStore(),
            credentialValidator: FixtureCredentialValidator(),
            profile: try .vcdm2JWTVC(),
            now: { instant }
        )
        let offer = try await backend.resolveOffer("https://issuer.example/offer")
        let outcome = try await backend.issueOutcome(
            id: offer.id, allowUntrusted: false, transactionCode: "123456"
        )
        let deferred = try #require({
            if case let .deferred(value) = outcome { return value }
            return nil
        }())
        await #expect(throws: OpenID4VCBackendError.deferredCredentialNotReady(
            nextPollAt: instant.addingTimeInterval(30)
        )) {
            _ = try await backend.retrieveDeferredCredential(deferred)
        }
        #expect(!(await transport.requests).contains { $0.url.path == "/deferred" })
    }

    @Test("Transaction responses require positive interval and HTTP 202")
    func deferredInitialResponseRequirements() async throws {
        for fixture in [
            FixtureOpenID4VCTransport(deferredInterval: nil, emitsTransaction: true),
            FixtureOpenID4VCTransport(deferredInterval: 0),
            FixtureOpenID4VCTransport(deferredInterval: 10, initialTransactionID: nil),
            FixtureOpenID4VCTransport(deferredInterval: 10, initialTransactionID: ""),
            FixtureOpenID4VCTransport(deferredInterval: 10, initialCredentialStatus: 200),
        ] {
            let backend = OpenID4VCW3CBackend(
                transport: fixture, trustEvaluator: TrustedIssuerEvaluator(),
                keyProvider: FixtureKeyProvider(), credentialStore: FixtureCredentialStore(),
                credentialValidator: FixtureCredentialValidator(), profile: try .vcdm2JWTVC()
            )
            let offer = try await backend.resolveOffer("https://issuer.example/offer")
            await #expect(throws: OpenID4VCBackendError.invalidResponse) {
                _ = try await backend.issueOutcome(
                    id: offer.id, allowUntrusted: false, transactionCode: "123456"
                )
            }
        }
    }

    @Test("Pending transaction must retain its ID, positive interval and HTTP 202")
    func deferredPendingResponseRequirements() async throws {
        for fixture in [
            FixtureOpenID4VCTransport(deferredInterval: 1, pendingTransactionID: "other"),
            FixtureOpenID4VCTransport(deferredInterval: 1, pendingTransactionID: "transaction-1"),
            FixtureOpenID4VCTransport(deferredInterval: 1, pendingTransactionID: "transaction-1", pendingInterval: 0),
            FixtureOpenID4VCTransport(deferredInterval: 1, pendingTransactionID: "transaction-1", pendingInterval: 1, deferredStatus: 200),
            FixtureOpenID4VCTransport(deferredInterval: 1, completedCredentialStatus: 202),
        ] {
            let clock = DeferredTestClock(Date(timeIntervalSince1970: 1_800_000_000))
            let backend = OpenID4VCW3CBackend(
                transport: fixture, trustEvaluator: TrustedIssuerEvaluator(),
                keyProvider: FixtureKeyProvider(), credentialStore: FixtureCredentialStore(),
                credentialValidator: FixtureCredentialValidator(), profile: try .vcdm2JWTVC(),
                now: { clock.value }
            )
            let offer = try await backend.resolveOffer("https://issuer.example/offer")
            let outcome = try await backend.issueOutcome(
                id: offer.id, allowUntrusted: false, transactionCode: "123456"
            )
            guard case let .deferred(state) = outcome else { continue }
            clock.advance(by: 1)
            await #expect(throws: OpenID4VCBackendError.invalidResponse) {
                _ = try await backend.retrieveDeferredCredential(state)
            }
        }
    }

    @Test("Legacy issuance_pending error is not accepted by final deferred retrieval")
    func deferredRejectsLegacyPendingError() async throws {
        let fixture = FixtureOpenID4VCTransport(deferredInterval: 1, legacyPendingError: true)
        let clock = DeferredTestClock(Date(timeIntervalSince1970: 1_800_000_000))
        let backend = OpenID4VCW3CBackend(
            transport: fixture, trustEvaluator: TrustedIssuerEvaluator(),
            keyProvider: FixtureKeyProvider(), credentialStore: FixtureCredentialStore(),
            credentialValidator: FixtureCredentialValidator(), profile: try .vcdm2JWTVC(),
            now: { clock.value }
        )
        let offer = try await backend.resolveOffer("https://issuer.example/offer")
        let outcome = try await backend.issueOutcome(
            id: offer.id, allowUntrusted: false, transactionCode: "123456"
        )
        guard case let .deferred(state) = outcome else { return }
        clock.advance(by: 1)
        await #expect(throws: OpenID4VCBackendError.remoteOAuthError(
            code: "issuance_pending", detail: nil
        )) {
            _ = try await backend.retrieveDeferredCredential(state)
        }
    }

    @Test("Draft 17 QESAC uses token identifier, proofs and response encryption")
    func draft17QESACRequest() async throws {
        let transport = Draft13OpenID4VCTransport(credentialIssuer: "https://issuer.example/service/draft-17")
        let security = RecordingOID4VCIClientSecurity()
        let backend = OpenID4VCW3CBackend(
            transport: transport,
            trustEvaluator: TrustedIssuerEvaluator(),
            keyProvider: FixtureKeyProvider(),
            credentialStore: FixtureCredentialStore(),
            credentialValidator: FixtureCredentialValidator(),
            profile: try .dcSdJWTVC(),
            clientSecurity: security,
            transportProfileRegistry: .developmentDraftCompatibility
        )
        let json = #"{"credential_issuer":"https://issuer.example/service/draft-17","credential_configuration_ids":["pid-config"],"grants":{"urn:ietf:params:oauth:grant-type:pre-authorized_code":{"pre-authorized_code":"pre-code"}}}"#
        let encoded = try #require(json.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed))
        let offer = try await backend.resolveOffer("openid-credential-offer://?credential_offer=\(encoded)")
        _ = try await backend.issue(id: offer.id, allowUntrusted: false, transactionCode: nil)

        let requests = await transport.requests
        let token = try #require(requests.first { $0.url.path.hasSuffix("/token") })
        #expect(token.headers["DPoP"] == nil)
        let credential = try #require(requests.first { $0.url.path.hasSuffix("/credential") })
        let body = try #require(JSONSerialization.jsonObject(with: credential.body ?? Data()) as? [String: Any])
        #expect(body["credential_identifier"] as? String == "authorized-pid")
        #expect(body["credential_configuration_id"] == nil)
        #expect(body["format"] == nil)
        #expect(body["proof"] == nil)
        #expect((body["proofs"] as? [String: Any])?["jwt"] != nil)
        #expect(body["credential_response_encryption"] != nil)
        #expect(credential.headers["Authorization"] == "Bearer access-token")
        #expect(credential.headers["DPoP"] == nil)
        #expect(await security.dpopAccessTokens.isEmpty)
    }

    @Test("Draft issuance uses identifier-only request and encrypted response", arguments: ["draft-13", "draft-18"])
    func draftIssuance(revision: String) async throws {
        let usesLegacyDiscovery = revision == "draft-18"
        let transport = Draft13OpenID4VCTransport(
            legacyWellKnownOnly: usesLegacyDiscovery,
            credentialIssuer: "https://issuer.example/service/\(revision)"
        )
        let security = RecordingOID4VCIClientSecurity()
        let store = FixtureCredentialStore()
        let backend = OpenID4VCW3CBackend(
            transport: transport,
            trustEvaluator: TrustedIssuerEvaluator(),
            keyProvider: FixtureKeyProvider(),
            credentialStore: store,
            credentialValidator: FixtureCredentialValidator(),
            profile: try .dcSdJWTVC(),
            clientSecurity: security,
            transportProfileRegistry: .developmentDraftCompatibility,
            now: { Date(timeIntervalSince1970: 1_800_000_000) }
        )
        let offerJSON = """
        {"credential_issuer":"https://issuer.example/service/\(revision)","credential_configuration_ids":["pid-config"],"grants":{"urn:ietf:params:oauth:grant-type:pre-authorized_code":{"pre-authorized_code":"pre-code","tx_code":{"input_mode":"numeric","length":4}}}}
        """
        let encoded = offerJSON.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed)!
        let offer = try await backend.resolveOffer("openid-credential-offer://?credential_offer=\(encoded)")
        let issued = try await backend.issue(id: offer.id, allowUntrusted: false, transactionCode: "1234")

        #expect(issued.count == 1)
        #expect(issued.first?.profileID == "ietf-dc-sd-jwt-vc")
        #expect(try await store.credentials().count == 1)
        let requests = await transport.requests
        let token = try #require(requests.first { $0.url.path.hasSuffix("/token") })
        #expect(token.headers["DPoP"] == nil)
        #expect(token.headers["OAuth-Client-Attestation"] == nil)
        let credential = try #require(requests.first { $0.url.path.hasSuffix("/credential") })
        #expect(credential.headers["Authorization"] == "Bearer access-token")
        #expect(credential.headers["DPoP"] == nil)
        let credentialBody = try #require(credential.body)
        let body = try #require(
            JSONSerialization.jsonObject(with: credentialBody) as? [String: Any]
        )
        #expect(body["credential_identifier"] as? String == "authorized-pid")
        #expect(body["credential_configuration_id"] == nil)
        #expect(body["format"] == nil)
        #expect(body["proofs"] == nil)
        let proof = try #require(body["proof"] as? [String: Any])
        #expect(proof["proof_type"] as? String == "jwt")
        let proofPayload = try Self.jwtPayload(try #require(proof["jwt"] as? String))
        #expect(proofPayload["iat"] as? Int == 1_800_000_000)
        #expect(proofPayload["exp"] as? Int == 1_800_000_300)
        #expect(proofPayload["nonce"] as? String == "credential-nonce")
        #expect(body["credential_response_encryption"] != nil)
        #expect(await security.dpopAccessTokens.isEmpty)
        #expect(await security.decryptionCalls == 1)
        let issuerMetadataPath = usesLegacyDiscovery
            ? "/service/\(revision)/.well-known/openid-credential-issuer"
            : "/.well-known/openid-credential-issuer/service/\(revision)"
        let authorizationMetadataPath = usesLegacyDiscovery
            ? "/service/draft-13/.well-known/oauth-authorization-server"
            : "/.well-known/oauth-authorization-server/service/draft-13"
        #expect(requests.contains { $0.url.path == issuerMetadataPath })
        #expect(requests.contains { $0.url.path == authorizationMetadataPath })
        #expect(requests.contains { $0.url.path.hasSuffix("/notification") && $0.method == "POST" })
    }

    @Test("Draft issuance signs a proof without nonce when token omits c_nonce")
    func draftMissingNonce() async throws {
        let response = #"{"access_token":"access-token","token_type":"Bearer","authorization_details":[{"credential_configuration_id":"pid-config","credential_identifiers":["authorized-pid"]}]}"#
        let transport = Draft13OpenID4VCTransport(tokenResponse: response)
        let backend = OpenID4VCW3CBackend(
            transport: transport,
            trustEvaluator: TrustedIssuerEvaluator(),
            keyProvider: FixtureKeyProvider(),
            credentialStore: FixtureCredentialStore(),
            credentialValidator: FixtureCredentialValidator(),
            profile: try .dcSdJWTVC(),
            clientSecurity: RecordingOID4VCIClientSecurity(),
            transportProfileRegistry: .developmentDraftCompatibility
        )
        let offer = try await backend.resolveOffer(try Self.draftOffer())
        #expect(try await backend.issue(id: offer.id, allowUntrusted: false, transactionCode: "1234").count == 1)
        let request = try #require((await transport.requests).first { $0.url.path.hasSuffix("/credential") })
        let requestBody = try #require(request.body)
        let body = try #require(JSONSerialization.jsonObject(with: requestBody) as? [String: Any])
        let proof = try #require(body["proof"] as? [String: Any])
        let payload = try Self.jwtPayload(try #require(proof["jwt"] as? String))
        #expect(payload["nonce"] == nil)
    }

    @Test("Draft issuance rejects an unexpected DPoP token when Bearer was negotiated")
    func draftRejectsUnexpectedDPoPTokenType() async throws {
        let transport = Draft13OpenID4VCTransport(tokenResponse: #"{"access_token":"access-token","token_type":"DPoP"}"#)
        let backend = OpenID4VCW3CBackend(
            transport: transport,
            trustEvaluator: TrustedIssuerEvaluator(),
            keyProvider: FixtureKeyProvider(),
            credentialStore: FixtureCredentialStore(),
            credentialValidator: FixtureCredentialValidator(),
            profile: try .dcSdJWTVC(),
            clientSecurity: RecordingOID4VCIClientSecurity(),
            transportProfileRegistry: .developmentDraftCompatibility
        )
        let offer = try await backend.resolveOffer(try Self.draftOffer())
        await #expect(throws: OpenID4VCBackendError.invalidTokenType(expected: "Bearer", actual: "DPoP")) {
            _ = try await backend.issue(id: offer.id, allowUntrusted: false, transactionCode: "1234")
        }
        #expect(!(await transport.requests).contains { $0.url.path.hasSuffix("/credential") })
    }

    @Test("Draft issuer without DPoP metadata uses a Bearer token")
    func draftAcceptsBearerWithoutDPoPMetadata() async throws {
        let transport = Draft13OpenID4VCTransport(
            tokenResponse: #"{"access_token":"access-token","token_type":"Bearer","c_nonce":"credential-nonce","authorization_details":[{"credential_configuration_id":"pid-config","credential_identifiers":["authorized-pid"]}]}"#,
            advertisesDPoP: false
        )
        let security = RecordingOID4VCIClientSecurity()
        let backend = OpenID4VCW3CBackend(
            transport: transport,
            trustEvaluator: TrustedIssuerEvaluator(),
            keyProvider: FixtureKeyProvider(),
            credentialStore: FixtureCredentialStore(),
            credentialValidator: FixtureCredentialValidator(),
            profile: try .dcSdJWTVC(),
            clientSecurity: security,
            transportProfileRegistry: .productionInteroperability
        )
        let offer = try await backend.resolveOffer(try Self.draftOffer())
        #expect(try await backend.issue(id: offer.id, allowUntrusted: false, transactionCode: "1234").count == 1)
        let requests = await transport.requests
        let token = try #require(requests.first { $0.url.path.hasSuffix("/token") })
        #expect(token.headers["DPoP"] == nil)
        let credential = try #require(requests.first { $0.url.path.hasSuffix("/credential") })
        #expect(credential.headers["Authorization"] == "Bearer access-token")
        #expect(credential.headers["DPoP"] == nil)
        #expect(await security.dpopAccessTokens.isEmpty)
    }

    @Test("Draft issuance rejects a plaintext response when encryption was requested")
    func draftRejectsPlaintextCredentialResponse() async throws {
        let transport = Draft13OpenID4VCTransport(plaintextCredentialResponse: true)
        let backend = OpenID4VCW3CBackend(
            transport: transport,
            trustEvaluator: TrustedIssuerEvaluator(),
            keyProvider: FixtureKeyProvider(),
            credentialStore: FixtureCredentialStore(),
            credentialValidator: FixtureCredentialValidator(),
            profile: try .dcSdJWTVC(),
            clientSecurity: RecordingOID4VCIClientSecurity(),
            transportProfileRegistry: .developmentDraftCompatibility
        )
        let offer = try await backend.resolveOffer(try Self.draftOffer())
        await #expect(throws: OpenID4VCBackendError.invalidResponse) {
            _ = try await backend.issue(id: offer.id, allowUntrusted: false, transactionCode: "1234")
        }
    }

    @Test("Draft issuance reports the stage and coding path for malformed token JSON")
    func draftMalformedTokenValue() async throws {
        let response = #"{"access_token":"access-token","token_type":"Bearer","c_nonce":123}"#
        try await assertRejectedDraftToken(
            response,
            expected: .decodingFailed(
                stage: "token response",
                path: "$.c_nonce",
                reason: "expected String"
            )
        )
    }

    @Test("Draft issuance rejects a token authorization for another configuration")
    func draftMismatchedAuthorization() async throws {
        let response = #"{"access_token":"access-token","token_type":"Bearer","c_nonce":"credential-nonce","authorization_details":[{"credential_configuration_id":"other-config","credential_identifiers":["unauthorized-pid","authorized-fallback"]}]}"#
        let transport = Draft13OpenID4VCTransport(
            tokenResponse: response,
            rejectedCredentialIdentifier: "unauthorized-pid"
        )
        let backend = OpenID4VCW3CBackend(
            transport: transport,
            trustEvaluator: TrustedIssuerEvaluator(),
            keyProvider: FixtureKeyProvider(),
            credentialStore: FixtureCredentialStore(),
            credentialValidator: FixtureCredentialValidator(),
            profile: try .dcSdJWTVC(),
            clientSecurity: RecordingOID4VCIClientSecurity(),
            transportProfileRegistry: .developmentDraftCompatibility
        )
        let offer = try await backend.resolveOffer(try Self.draftOffer())
        await #expect(throws: OpenID4VCBackendError.credentialAuthorizationMismatch(
            offered: "pid-config",
            authorized: ["other-config", "unauthorized-pid", "authorized-fallback"]
        )) {
            _ = try await backend.issue(id: offer.id, allowUntrusted: false, transactionCode: "1234")
        }
        let credentialRequests = (await transport.requests).filter { $0.url.path.hasSuffix("/credential") }
        #expect(credentialRequests.isEmpty)
    }

    @Test("Draft issuance accepts one metadata-proven configuration alias")
    func draftEquivalentConfigurationAlias() async throws {
        let response = #"{"access_token":"access-token","token_type":"Bearer","c_nonce":"credential-nonce","authorization_details":[{"credential_configuration_id":"pid-alias","credential_identifiers":["authorized-alias"]}]}"#
        let transport = Draft13OpenID4VCTransport(tokenResponse: response)
        let backend = OpenID4VCW3CBackend(
            transport: transport,
            trustEvaluator: TrustedIssuerEvaluator(),
            keyProvider: FixtureKeyProvider(),
            credentialStore: FixtureCredentialStore(),
            credentialValidator: FixtureCredentialValidator(),
            profile: try .dcSdJWTVC(),
            clientSecurity: RecordingOID4VCIClientSecurity(),
            transportProfileRegistry: .developmentDraftCompatibility
        )
        let offer = try await backend.resolveOffer(try Self.draftOffer())
        let issued = try await backend.issue(id: offer.id, allowUntrusted: false, transactionCode: "1234")
        let request = try #require((await transport.requests).first { $0.url.path.hasSuffix("/credential") })
        let data = try #require(request.body)
        let body = try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])
        #expect(body["credential_identifier"] as? String == "authorized-alias")
        #expect(issued.first?.configurationID == "pid-config")
    }

    @Test("Draft issuance matches an offered credential identifier when configuration ID is absent")
    func draftIdentifierWithoutConfigurationID() async throws {
        let response = #"{"access_token":"access-token","token_type":"Bearer","c_nonce":"credential-nonce","authorization_details":[{"credential_identifiers":["pid-config"]}]}"#
        let transport = Draft13OpenID4VCTransport(tokenResponse: response)
        let backend = OpenID4VCW3CBackend(
            transport: transport,
            trustEvaluator: TrustedIssuerEvaluator(),
            keyProvider: FixtureKeyProvider(),
            credentialStore: FixtureCredentialStore(),
            credentialValidator: FixtureCredentialValidator(),
            profile: try .dcSdJWTVC(),
            clientSecurity: RecordingOID4VCIClientSecurity(),
            transportProfileRegistry: .developmentDraftCompatibility
        )
        let offer = try await backend.resolveOffer(try Self.draftOffer())
        _ = try await backend.issue(id: offer.id, allowUntrusted: false, transactionCode: "1234")
        let request = try #require((await transport.requests).first { $0.url.path.hasSuffix("/credential") })
        let data = try #require(request.body)
        let body = try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])
        #expect(body["credential_identifier"] as? String == "pid-config")
    }

    @Test("Draft issuance prefers exact authorization and ignores additional aliases")
    func draftExactConfigurationWithAdditionalAliases() async throws {
        let response = #"{"access_token":"access-token","token_type":"Bearer","c_nonce":"credential-nonce","authorization_details":[{"credential_configuration_id":"pid-config","credential_identifiers":["exact"]},{"credential_configuration_id":"pid-alias","credential_identifiers":["alias"]},{"credential_configuration_id":"other-config","credential_identifiers":["other"]}]}"#
        let transport = Draft13OpenID4VCTransport(tokenResponse: response)
        let backend = OpenID4VCW3CBackend(
            transport: transport,
            trustEvaluator: TrustedIssuerEvaluator(),
            keyProvider: FixtureKeyProvider(),
            credentialStore: FixtureCredentialStore(),
            credentialValidator: FixtureCredentialValidator(),
            profile: try .dcSdJWTVC(),
            clientSecurity: RecordingOID4VCIClientSecurity(),
            transportProfileRegistry: .developmentDraftCompatibility
        )
        let offer = try await backend.resolveOffer(try Self.draftOffer())
        _ = try await backend.issue(id: offer.id, allowUntrusted: false, transactionCode: "1234")
        let request = try #require((await transport.requests).first { $0.url.path.hasSuffix("/credential") })
        let data = try #require(request.body)
        let body = try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])
        #expect(body["credential_identifier"] as? String == "exact")
    }

    @Test("Draft issuance rejects multiple aliases when no exact authorization exists")
    func draftAmbiguousConfigurationAliases() async throws {
        let response = #"{"access_token":"access-token","token_type":"Bearer","c_nonce":"credential-nonce","authorization_details":[{"credential_configuration_id":"pid-alias","credential_identifiers":["alias-one"]},{"credential_configuration_id":"pid-alias-two","credential_identifiers":["alias-two"]}]}"#
        try await assertRejectedDraftToken(
            response,
            expected: .credentialAuthorizationMismatch(
                offered: "pid-config",
                authorized: ["pid-alias", "alias-one", "pid-alias-two", "alias-two"]
            )
        )
    }

    @Test("Draft issuance rejects explicitly empty authorization details")
    func draftEmptyAuthorizationDetails() async throws {
        let response = #"{"access_token":"access-token","token_type":"Bearer","c_nonce":"credential-nonce","authorization_details":[]}"#
        try await assertRejectedDraftToken(response, expected: .missingCredentialAuthorization)
    }

    @Test("Draft issuance falls back to offered identifier only when authorization details are absent")
    func draftAbsentAuthorizationDetailsFallback() async throws {
        let response = #"{"access_token":"access-token","token_type":"Bearer","c_nonce":"credential-nonce"}"#
        let transport = Draft13OpenID4VCTransport(tokenResponse: response)
        let backend = OpenID4VCW3CBackend(
            transport: transport,
            trustEvaluator: TrustedIssuerEvaluator(),
            keyProvider: FixtureKeyProvider(),
            credentialStore: FixtureCredentialStore(),
            credentialValidator: FixtureCredentialValidator(),
            profile: try .dcSdJWTVC(),
            clientSecurity: RecordingOID4VCIClientSecurity(),
            transportProfileRegistry: .developmentDraftCompatibility
        )
        let offer = try await backend.resolveOffer(try Self.draftOffer())
        _ = try await backend.issue(id: offer.id, allowUntrusted: false, transactionCode: "1234")
        let request = try #require((await transport.requests).first { $0.url.path.hasSuffix("/credential") })
        let data = try #require(request.body)
        let body = try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])
        #expect(body["credential_identifier"] as? String == "pid-config")
    }

    @Test("Attestation-only draft fails before token request when attestation is unavailable")
    func unavailableClientAttestation() async throws {
        let transport = Draft13OpenID4VCTransport(allowsAnonymousAuthentication: false)
        let security = RecordingOID4VCIClientSecurity(attestationHeaders: [:])
        let backend = OpenID4VCW3CBackend(
            transport: transport,
            trustEvaluator: TrustedIssuerEvaluator(),
            keyProvider: FixtureKeyProvider(),
            credentialStore: FixtureCredentialStore(),
            credentialValidator: FixtureCredentialValidator(),
            profile: try .dcSdJWTVC(),
            clientSecurity: security,
            transportProfileRegistry: .developmentDraftCompatibility
        )
        let offer = try await backend.resolveOffer(try Self.draftOffer())
        await #expect(throws: OpenID4VCBackendError.clientSecurityUnavailable) {
            _ = try await backend.issue(id: offer.id, allowUntrusted: false, transactionCode: "1234")
        }
        #expect(!(await transport.requests).contains { $0.url.path.hasSuffix("/token") })
    }

    @Test("Unsupported required token authentication fails before token request")
    func unsupportedTokenAuthentication() async throws {
        let transport = Draft13OpenID4VCTransport(
            allowsAnonymousAuthentication: false,
            supportsES256Attestation: false
        )
        let backend = OpenID4VCW3CBackend(
            transport: transport,
            trustEvaluator: TrustedIssuerEvaluator(),
            keyProvider: FixtureKeyProvider(),
            credentialStore: FixtureCredentialStore(),
            credentialValidator: FixtureCredentialValidator(),
            profile: try .dcSdJWTVC(),
            clientSecurity: RecordingOID4VCIClientSecurity(),
            transportProfileRegistry: .developmentDraftCompatibility
        )
        let offer = try await backend.resolveOffer(try Self.draftOffer())
        await #expect(throws: OpenID4VCBackendError.clientSecurityUnavailable) {
            _ = try await backend.issue(id: offer.id, allowUntrusted: false, transactionCode: "1234")
        }
        #expect(!(await transport.requests).contains { $0.url.path.hasSuffix("/token") })
    }

    @Test("VCDM2 credential context overrides a legacy jwt_vc_json metadata label")
    func vcdm2ContextSelection() async throws {
        let credential = try Self.compactJWT(payload: [
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential", "LegalPersonIdentificationData"],
            "issuer": "did:key:issuer",
            "credentialSubject": ["id": "did:key:holder"],
        ])
        let backend = OpenID4VCW3CBackend(
            transport: FixtureOpenID4VCTransport(
                credentialFormat: "jwt_vc_json",
                credentialResponse: credential
            ),
            trustEvaluator: TrustedIssuerEvaluator(),
            keyProvider: FixtureKeyProvider(),
            credentialStore: FixtureCredentialStore(),
            credentialValidator: FixtureCredentialValidator(),
            profile: try .vcdm2JWTVC(),
            additionalProfiles: [try .vcdm11Jwt()]
        )
        let offer = try await backend.resolveOffer("https://issuer.example/offer")
        let issued = try await backend.issue(
            id: offer.id,
            allowUntrusted: false,
            transactionCode: "123456"
        )
        #expect(issued.first?.profileID == "ebsi-vcdm2-jwt-vc")
        #expect(issued.first?.representation == .vcdm2Jwt)
    }

    @Test("Nested VCDM1.1 context selects the legacy profile for jwt_vc_json")
    func vcdm11ContextSelection() async throws {
        let credential = try Self.compactJWT(typ: "JWT", payload: [
            "iss": "did:key:issuer",
            "vc": [
                "@context": ["https://www.w3.org/2018/credentials/v1"],
                "type": ["VerifiableCredential", "ExampleCredential"],
                "issuer": "did:key:issuer",
                "issuanceDate": "2026-01-01T00:00:00Z",
                "credentialSubject": ["id": "did:key:holder"],
            ],
        ])
        let backend = OpenID4VCW3CBackend(
            transport: FixtureOpenID4VCTransport(
                credentialFormat: "jwt_vc_json",
                credentialResponse: credential
            ),
            trustEvaluator: TrustedIssuerEvaluator(),
            keyProvider: FixtureKeyProvider(),
            credentialStore: FixtureCredentialStore(),
            credentialValidator: FixtureCredentialValidator(),
            profile: try .vcdm2JWTVC(),
            additionalProfiles: [try .vcdm11Jwt()]
        )
        let offer = try await backend.resolveOffer("https://issuer.example/offer")
        let issued = try await backend.issue(
            id: offer.id,
            allowUntrusted: false,
            transactionCode: "123456"
        )
        #expect(issued.first?.profileID == "ebsi-vcdm11-jwt-vc")
        #expect(issued.first?.representation == .jwtVcJson)
    }

    @Test("Credential metadata paths normalize wildcard and array index components")
    func credentialMetadataPathComponents() throws {
        let claim = try JSONDecoder().decode(
            CredentialConfigurationClaim.self,
            from: Data(#"{"path":["credentialSubject","items",null,2,"name"],"name":"Item name"}"#.utf8)
        )
        #expect(claim.path == ["credentialSubject", "items", "*", "[2]", "name"])
        #expect(claim.id == "credentialSubject.items.*.[2].name")
    }

    @Test("Complete issuer metadata tolerates unrelated Portable Document wildcard paths")
    func portableDocumentWildcardMetadata() async throws {
        let backend = OpenID4VCW3CBackend(
            transport: WildcardIssuerMetadataTransport(),
            trustEvaluator: TrustedIssuerEvaluator(),
            keyProvider: FixtureKeyProvider(),
            credentialStore: FixtureCredentialStore(),
            credentialValidator: FixtureCredentialValidator(),
            profile: try .dcSdJWTVC()
        )
        let offerJSON = #"{"credential_issuer":"https://issuer.example","credential_configuration_ids":["selected"],"grants":{"urn:ietf:params:oauth:grant-type:pre-authorized_code":{"pre-authorized_code":"code"}}}"#
        let encoded = try #require(offerJSON.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed))
        let offer = try await backend.resolveOffer("openid-credential-offer://?credential_offer=\(encoded)")
        #expect(offer.configurationIDs == ["selected"])
        #expect(offer.representations == ["dc+sd-jwt"])
    }

    @Test("HTTPS service trust is origin-bound and issuance reaches the credential response")
    func preauthorizedIssuance() async throws {
        let transport = FixtureOpenID4VCTransport(advertisesNonceEndpoint: true)
        let keys = FixtureKeyProvider()
        let store = FixtureCredentialStore()
        let validator = FixtureCredentialValidator()
        let backend = OpenID4VCW3CBackend(
            transport: transport,
            trustEvaluator: UntrustedIssuerEvaluator(),
            keyProvider: keys,
            credentialStore: store,
            credentialValidator: validator,
            profile: try .vcdm2JWTVC(),
            now: { Date(timeIntervalSince1970: 1_800_000_000) }
        )
        let offerJSON = """
        {"credential_issuer":"https://issuer.example","credential_configuration_ids":["example-vcdm2-jwt-vc"],"grants":{"urn:ietf:params:oauth:grant-type:pre-authorized_code":{"pre-authorized_code":"pre-code","tx_code":{"input_mode":"numeric","length":6}}}}
        """
        let encoded = offerJSON.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed)!
        let offer = try await backend.resolveOffer(
            "openid-credential-offer://?credential_offer=\(encoded)"
        )
        #expect(offer.trustOutcome == .allow)
        await #expect(throws: OpenID4VCBackendError.invalidTransactionCode) {
            _ = try await backend.issue(id: offer.id, allowUntrusted: true, transactionCode: "12ab56")
        }

        let second = try await backend.resolveOffer(
            "openid-credential-offer://?credential_offer=\(encoded)"
        )
        let issued = try await backend.issue(
            id: second.id,
            allowUntrusted: true,
            transactionCode: "123456"
        )
        #expect(issued.count == 1)
        #expect(issued.first?.configurationID == "example-vcdm2-jwt-vc")
        #expect(issued.first?.displayName == "Legal Person ID")
        #expect(issued.first?.display?.backgroundColor == "#003366")
        #expect(issued.first?.display?.textColor == "#ffffff")
        #expect(issued.first?.display?.logo?.alternativeText == "Issuer mark")
        #expect(issued.first?.display?.logo?.data == FixtureOpenID4VCTransport.png)
        #expect(issued.first?.display?.backgroundImage?.data == FixtureOpenID4VCTransport.png)
        #expect(try await store.credentials().count == 1)
        #expect(await validator.calls == 1)
        let requests = await transport.requests
        #expect(requests.contains { $0.url.path == "/token" && String(decoding: $0.body ?? Data(), as: UTF8.self).contains("tx_code=123456") })
        #expect(requests.contains { $0.url.path == "/nonce" && $0.method == "POST" })
        let credentialRequest = try #require(requests.last { $0.url.path == "/credential" })
        let credentialRequestBody = try #require(credentialRequest.body)
        let body = try #require(
            JSONSerialization.jsonObject(with: credentialRequestBody) as? [String: Any]
        )
        #expect(body["credential_configuration_id"] as? String == "example-vcdm2-jwt-vc")
        #expect(body["format"] == nil)
        let proofs = try #require(body["proofs"] as? [String: [String]])
        let proof = try #require(proofs["jwt"]?.first)
        #expect(try Self.jwtPayload(proof)["nonce"] as? String == "nonce-from-endpoint")
    }

    @Test("Final issuance uses the credential identifier authorized by the token response")
    func finalCredentialIdentifier() async throws {
        let transport = FixtureOpenID4VCTransport(tokenResponse: #"{"access_token":"access","token_type":"Bearer","authorization_details":[{"credential_configuration_id":"example-vcdm2-jwt-vc","credential_identifiers":["authorized-dataset"]}]}"#)
        let backend = OpenID4VCW3CBackend(
            transport: transport,
            trustEvaluator: TrustedIssuerEvaluator(),
            keyProvider: FixtureKeyProvider(),
            credentialStore: FixtureCredentialStore(),
            credentialValidator: FixtureCredentialValidator(),
            profile: try .vcdm2JWTVC()
        )
        let offer = try await backend.resolveOffer("https://issuer.example/offer")
        _ = try await backend.issue(id: offer.id, allowUntrusted: false, transactionCode: "123456")

        let request = try #require((await transport.requests).last { $0.url.path == "/credential" })
        let requestBody = try #require(request.body)
        let body = try #require(JSONSerialization.jsonObject(with: requestBody) as? [String: Any])
        #expect(body["credential_identifier"] as? String == "authorized-dataset")
        #expect(body["credential_configuration_id"] == nil)
    }

    @Test("Credential issuer metadata must exactly match the offer issuer")
    func credentialIssuerMetadataIdentity() async throws {
        let backend = OpenID4VCW3CBackend(
            transport: FixtureOpenID4VCTransport(credentialIssuerMetadata: "https://issuer.example/other"),
            trustEvaluator: TrustedIssuerEvaluator(),
            keyProvider: FixtureKeyProvider(),
            credentialStore: FixtureCredentialStore(),
            credentialValidator: FixtureCredentialValidator(),
            profile: try .vcdm2JWTVC()
        )
        await #expect(throws: OpenID4VCBackendError.invalidResponse) {
            _ = try await backend.resolveOffer("https://issuer.example/offer")
        }
    }

    @Test("Production does not send an HTTPS credential_issuer service identity to signer trust")
    func productionAcceptsOriginValidatedServiceIdentity() async throws {
        let backend = OpenID4VCW3CBackend(
            transport: FixtureOpenID4VCTransport(),
            trustEvaluator: UntrustedIssuerEvaluator(),
            keyProvider: FixtureKeyProvider(),
            credentialStore: FixtureCredentialStore(),
            credentialValidator: FixtureCredentialValidator(),
            profile: try .vcdm2JWTVC(),
            trustEnvironment: .production
        )
        let offerJSON = #"{"credential_issuer":"https://issuer.example","credential_configuration_ids":["example-vcdm2-jwt-vc"],"grants":{"urn:ietf:params:oauth:grant-type:pre-authorized_code":{"pre-authorized_code":"pre-code","tx_code":{"input_mode":"numeric","length":6}}}}"#
        let encoded = try #require(offerJSON.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed))
        let offer = try await backend.resolveOffer("openid-credential-offer://?credential_offer=\(encoded)")
        #expect(offer.trustOutcome == .allow)
        #expect(try await backend.issue(id: offer.id, allowUntrusted: false, transactionCode: "123456").count == 1)
    }

    @Test("Production warns for a validated did:key signer before storage and Continue does not repeat requests")
    func productionSignerWarningStagesCredential() async throws {
        let transport = FixtureOpenID4VCTransport()
        let store = FixtureCredentialStore()
        let backend = OpenID4VCW3CBackend(
            transport: transport,
            trustEvaluator: TrustedIssuerEvaluator(),
            credentialSignerTrustEvaluator: UntrustedSignerEvaluator(),
            keyProvider: FixtureKeyProvider(),
            credentialStore: store,
            credentialValidator: FixtureCredentialValidator(signedIssuer: "did:key:zValidatedSigner"),
            profile: try .vcdm2JWTVC(),
            trustEnvironment: .production
        )
        let offerJSON = #"{"credential_issuer":"https://issuer.example","credential_configuration_ids":["example-vcdm2-jwt-vc"],"grants":{"urn:ietf:params:oauth:grant-type:pre-authorized_code":{"pre-authorized_code":"pre-code","tx_code":{"input_mode":"numeric","length":6}}}}"#
        let encoded = try #require(offerJSON.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed))
        let offer = try await backend.resolveOffer("openid-credential-offer://?credential_offer=\(encoded)")

        do {
            _ = try await backend.issue(id: offer.id, allowUntrusted: false, transactionCode: "123456")
            Issue.record("Expected post-validation signer warning")
        } catch OpenID4VCBackendError.credentialSignerTrustWarning(let warning) {
            #expect(warning.counterpartyIdentifier == "did:key:zValidatedSigner")
        }
        #expect(try await store.credentials().isEmpty)
        let requestsBeforeContinue = await transport.requests.count
        #expect(try await backend.issue(id: offer.id, allowUntrusted: true, transactionCode: nil).count == 1)
        #expect(try await store.credentials().count == 1)
        #expect(await transport.requests.count == requestsBeforeContinue)
    }

    @Test("Referenced offer and cancellation are bounded")
    func referencedAndCancel() async throws {
        let backend = OpenID4VCW3CBackend(
            transport: FixtureOpenID4VCTransport(),
            trustEvaluator: TrustedIssuerEvaluator(),
            keyProvider: FixtureKeyProvider(),
            credentialStore: FixtureCredentialStore(),
            credentialValidator: FixtureCredentialValidator(),
            profile: try .vcdm2JWTVC(),
            presentationRequestValidator: FixturePresentationRequestValidator()
        )
        let offer = try await backend.resolveOffer(
            "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fissuer.example%2Foffer"
        )
        await backend.cancel(id: offer.id)
        await #expect(throws: OpenID4VCBackendError.unknownTransaction) {
            _ = try await backend.issue(id: offer.id, allowUntrusted: false, transactionCode: "123456")
        }
    }

    @Test("Authorization-code offer completes final PID presentation challenge")
    func authorizationPresentation() async throws {
        let transport = FixtureOpenID4VCTransport(omitAuthorizationResponseState: true)
        let backend = OpenID4VCW3CBackend(
            transport: transport,
            trustEvaluator: TrustedIssuerEvaluator(),
            keyProvider: FixtureKeyProvider(),
            credentialStore: FixtureCredentialStore(),
            credentialValidator: FixtureCredentialValidator(),
            profile: try .vcdm2JWTVC(),
            presentationRequestValidator: FixturePresentationRequestValidator()
        )
        let json = #"{"credential_issuer":"https://issuer.example","credential_configuration_ids":["example-vcdm2-jwt-vc"],"grants":{"authorization_code":{"issuer_state":"issuer-state"}}}"#
        let encoded = json.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed)!
        let offer = try await backend.resolveOffer("openid-credential-offer://?credential_offer=\(encoded)")
        #expect(offer.authorizationRequired)
        let interaction = try await backend.beginPresentationRequired(
            id: offer.id,
            allowUntrusted: false
        )
        guard case let .presentation(challenge) = interaction else {
            Issue.record("Expected presentation interaction")
            return
        }
        #expect(challenge.responseMode == "ia_post")
        #expect(challenge.dcqlQuery["credentials"] != nil)
        let initial = try #require((await transport.requests).first { request in
            request.url.path == "/authorize-challenge" &&
                String(decoding: request.body ?? Data(), as: UTF8.self).contains("issuer_state=")
        })
        let initialBody = String(decoding: try #require(initial.body), as: UTF8.self)
        let initialFields = Dictionary(uniqueKeysWithValues: try #require(
            URLComponents(string: "?\(initialBody)")?.queryItems
        ).compactMap { item in item.value.map { (item.name, $0) } })
        #expect(initialFields["interaction_types_supported"] == "urn:openid:dcp:ia:openid4vp_presentation,urn:openid:dcp:ia:auth_via_web")
        #expect(initialFields["client_id"] == "generic-wallet-client")
        #expect(initialFields["redirect_uri"] == "https://wallet.ios.oari.io/oauth/callback")
        #expect(initialFields["state"] == nil)
        #expect(initialFields["auth_session"] == nil)
        #expect(try await backend.submitPresentation(
            id: offer.id,
            vpToken: #"{"pid":["valid.pid.vp"]}"#
        ) == .authorizationCode("auth-code"))
        let post = try #require((await transport.requests).last { request in
            request.url.path == "/authorize-challenge" &&
                String(decoding: request.body ?? Data(), as: UTF8.self).contains("openid4vp_response=")
        })
        let formBody = String(decoding: try #require(post.body), as: UTF8.self)
        let fields = Dictionary(uniqueKeysWithValues: try #require(
            URLComponents(string: "?\(formBody)")?.queryItems
        ).compactMap { item in item.value.map { (item.name, $0) } })
        let wrapped = try #require(fields["openid4vp_response"])
        let response = try #require(JSONSerialization.jsonObject(with: Data(wrapped.utf8)) as? [String: Any])
        let vpToken = try #require(response["vp_token"] as? [String: [String]])
        #expect(vpToken == ["pid": ["valid.pid.vp"]])
        #expect(response["state"] as? String == "vp-state")
        #expect(fields["auth_session"] == "auth-session")
        #expect(fields["vp_token"] == nil)
        #expect(fields["openid4vp_presentation"] == nil)
        #expect(Set(fields.keys) == ["auth_session", "openid4vp_response"])
        #expect(try await backend.issue(id: offer.id, allowUntrusted: false, transactionCode: nil).count == 1)
    }

    @Test("Interactive authorization continues from VP through request_uri web authorization")
    func authorizationPresentationThenWeb() async throws {
        let transport = VPThenWebTransport()
        let backend = OpenID4VCW3CBackend(
            transport: transport,
            trustEvaluator: TrustedIssuerEvaluator(),
            keyProvider: FixtureKeyProvider(),
            credentialStore: FixtureCredentialStore(),
            credentialValidator: FixtureCredentialValidator(),
            profile: try .vcdm2JWTVC()
        )
        let offer = try await Self.authorizationOffer(backend)
        let initial = try await backend.beginPresentationRequired(id: offer.id, allowUntrusted: false)
        guard case .presentation = initial else {
            Issue.record("Expected presentation interaction")
            return
        }

        let submitted = try await backend.submitPresentation(
            id: offer.id, vpToken: #"{"pid":["valid.pid.vp"]}"#
        )
        guard case let .interaction(.web(web)) = submitted else {
            Issue.record("Expected web interaction")
            return
        }
        #expect(web.authorizationURL == URL(string: "https://issuer.example/browser-authorize?client_id=generic-wallet-client&request_uri=urn:ietf:params:oauth:request_uri:web-session-1"))
        #expect(web.authorizationChallengeEndpoint == URL(string: "https://issuer.example/authorize-challenge"))
        #expect(web.authSession == nil)
        #expect(web.expiresIn == 60)

        #expect(try await backend.continueWebAuthorization(
            id: offer.id,
            authSession: "continued-session"
        ) == .authorizationCode("web-code"))
        let continuationBody = try #require(await transport.continuationBody)
        #expect(continuationBody.contains("auth_session=continued-session"))
        #expect(continuationBody.contains("code_verifier="))
        #expect(await transport.authorizationMetadataRequestCount == 1)

        await #expect(throws: OpenID4VCBackendError.unknownTransaction) {
            try await backend.acceptAuthorizationCode(id: offer.id, code: "replayed-code")
        }
    }

    @Test("Interactive authorization can start with request_uri web authorization")
    func authorizationStartsWithWeb() async throws {
        let transport = VPThenWebTransport(initialWeb: true)
        let backend = OpenID4VCW3CBackend(
            transport: transport,
            trustEvaluator: TrustedIssuerEvaluator(),
            keyProvider: FixtureKeyProvider(),
            credentialStore: FixtureCredentialStore(),
            credentialValidator: FixtureCredentialValidator(),
            profile: try .vcdm2JWTVC()
        )
        let offer = try await Self.authorizationOffer(backend)
        let initial = try await backend.beginPresentationRequired(id: offer.id, allowUntrusted: false)
        guard case let .web(web) = initial else {
            Issue.record("Expected web interaction")
            return
        }
        #expect(web.authorizationURL == URL(string: "https://issuer.example/browser-authorize?client_id=generic-wallet-client&request_uri=urn:ietf:params:oauth:request_uri:web-session-1"))
        #expect(web.authSession == nil)
        #expect(web.expiresIn == 60)
    }

    @Test("Interactive authorization rejects a mismatched response state")
    func authorizationPresentationRejectsMismatchedState() async throws {
        let transport = FixtureOpenID4VCTransport(authorizationResponseStateOverride: "wrong-state")
        let backend = OpenID4VCW3CBackend(
            transport: transport,
            trustEvaluator: TrustedIssuerEvaluator(),
            keyProvider: FixtureKeyProvider(),
            credentialStore: FixtureCredentialStore(),
            credentialValidator: FixtureCredentialValidator(),
            profile: try .vcdm2JWTVC(),
            presentationRequestValidator: FixturePresentationRequestValidator()
        )
        let offer = try await Self.authorizationOffer(backend)
        _ = try await backend.beginPresentationRequired(id: offer.id, allowUntrusted: false)

        await #expect(throws: OpenID4VCBackendError.authorizationFailed) {
            _ = try await backend.submitPresentation(
                id: offer.id,
                vpToken: #"{"pid":["valid.pid.vp"]}"#
            )
        }
    }

    @Test("Interactive authorization challenge creation is single-flight")
    func presentationChallengeSingleFlight() async throws {
        let transport = FixtureOpenID4VCTransport()
        let backend = OpenID4VCW3CBackend(
            transport: transport,
            trustEvaluator: TrustedIssuerEvaluator(),
            keyProvider: FixtureKeyProvider(),
            credentialStore: FixtureCredentialStore(),
            credentialValidator: FixtureCredentialValidator(),
            profile: try .vcdm2JWTVC(),
            presentationRequestValidator: FixturePresentationRequestValidator()
        )
        let offer = try await Self.authorizationOffer(backend)
        async let first = backend.beginPresentationRequired(id: offer.id, allowUntrusted: false)
        async let second = backend.beginPresentationRequired(id: offer.id, allowUntrusted: false)
        let (firstChallenge, secondChallenge) = try await (first, second)
        #expect(firstChallenge == secondChallenge)
        let requests = (await transport.requests).filter { request in
            request.url.path == "/authorize-challenge" &&
                String(decoding: request.body ?? Data(), as: UTF8.self).contains("issuer_state=")
        }
        #expect(requests.count == 1)
    }

    @Test("Authorization-code offer resolves signed draft PID presentation challenge")
    func authorizationDraftPresentation() async throws {
        let transport = FixtureOpenID4VCTransport()
        let backend = OpenID4VCW3CBackend(
            transport: transport,
            trustEvaluator: TrustedIssuerEvaluator(),
            keyProvider: FixtureKeyProvider(),
            credentialStore: FixtureCredentialStore(),
            credentialValidator: FixtureCredentialValidator(),
            profile: try .vcdm2JWTVC(),
            presentationRequestValidator: FixturePresentationRequestValidator()
        )
        let json = #"{"credential_issuer":"https://issuer.example","credential_configuration_ids":["example-vcdm2-jwt-vc"],"grants":{"authorization_code":{"issuer_state":"issuer-state"}}}"#
        let encoded = json.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed)!
        let offer = try await backend.resolveOffer("openid-credential-offer://?credential_offer=\(encoded)")
        let interaction = try await backend.beginPresentationRequired(
            id: offer.id,
            allowUntrusted: false,
            interactionTypes: ["openid4vp_presentation"]
        )
        guard case let .presentation(challenge) = interaction else {
            Issue.record("Expected presentation interaction")
            return
        }
        #expect(challenge.responseMode == "direct_post")
        #expect(challenge.responseURI == URL(string: "https://issuer.example/authorize"))
        #expect(challenge.signedRequest != nil)
        #expect(challenge.dcqlQuery["credentials"] != nil)
        _ = try await backend.submitPresentation(
            id: offer.id,
            vpToken: #"{"pid":["presentation"]}"#
        )
        let post = try #require((await transport.requests).last { request in
            request.url.path == "/authorize" &&
                String(decoding: request.body ?? Data(), as: UTF8.self).contains("vp_token=")
        })
        let body = String(decoding: try #require(post.body), as: UTF8.self)
        #expect(body.contains("vp_token="))
        #expect(!body.contains("openid4vp_response="))
        #expect(!body.contains("auth_session="))
        let fields = Dictionary(uniqueKeysWithValues: try #require(
            URLComponents(string: "?\(body)")?.queryItems
        ).compactMap { item in item.value.map { (item.name, $0) } })
        #expect(fields == [
            "state": "auth-session",
            "vp_token": #"{"pid":["presentation"]}"#,
        ])
    }

    @Test("IAR compact signed request rejects malformed DCQL identifier")
    func iGrantCompactChallenge() async throws {
        let transport = FixtureOpenID4VCTransport(iGrantCompactPresentation: true)
        let backend = OpenID4VCW3CBackend(
            transport: transport,
            trustEvaluator: TrustedIssuerEvaluator(),
            keyProvider: FixtureKeyProvider(),
            credentialStore: FixtureCredentialStore(),
            credentialValidator: FixtureCredentialValidator(),
            profile: try .dcSdJWTVC(),
            transportProfileRegistry: .developmentDraftCompatibility,
            presentationRequestValidator: FixturePresentationRequestValidator()
        )
        let offer = try await Self.authorizationOffer(backend)
        await #expect(throws: OpenID4VPDCQLError.invalidID(
            value: "Presentation Definition 1", context: "credential 0"
        )) {
            _ = try await backend.beginPresentationRequired(
                id: offer.id,
                allowUntrusted: false,
                interactionTypes: ["openid4vp_presentation"]
            )
        }
    }

    @Test("Draft authorization uses published GET endpoint and never guesses IAR")
    func draftAuthorizationEndpoint() async throws {
        let transport = DraftIARFallbackTransport()
        let backend = OpenID4VCW3CBackend(
            transport: transport,
            trustEvaluator: TrustedIssuerEvaluator(),
            keyProvider: FixtureKeyProvider(),
            credentialStore: FixtureCredentialStore(),
            credentialValidator: FixtureCredentialValidator(),
            profile: try .dcSdJWTVC(),
            transportProfileRegistry: .developmentDraftCompatibility,
            presentationRequestValidator: FixturePresentationRequestValidator()
        )
        let json = #"{"credential_issuer":"https://issuer.example/service/draft-13","credential_configuration_ids":["pid"],"grants":{"authorization_code":{"issuer_state":"issuer-state"}}}"#
        let encoded = json.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed)!
        let offer = try await backend.resolveOffer("openid-credential-offer://?credential_offer=\(encoded)")
        let interaction = try await backend.beginPresentationRequired(
            id: offer.id,
            allowUntrusted: false,
            interactionTypes: ["openid4vp_presentation"]
        )
        guard case let .presentation(challenge) = interaction else {
            Issue.record("Expected presentation interaction")
            return
        }
        #expect(challenge.authorizationChallengeEndpoint.path == "/service/draft-13/authorize")
        #expect(challenge.responseMode == "iar-post")
        let requests = await transport.requests
        let authorization = try #require(requests.first { $0.url.path == "/service/draft-13/authorize" })
        #expect(authorization.method == "GET")
        let query = URLComponents(url: authorization.url, resolvingAgainstBaseURL: false)?.queryItems ?? []
        #expect(query.contains { $0.name == "response_type" && $0.value == "code" })
        #expect(query.contains { $0.name == "code_challenge" && !($0.value ?? "").isEmpty })
        #expect(query.contains { $0.name == "authorization_details" })
        #expect(!requests.contains { $0.url.path == "/service/iar" })
    }

    @Test("Stored W3C SD-JWT PID creates a selective DCQL key-bound presentation")
    func storedSDJWTPresentation() async throws {
        let transport = FixtureOpenID4VCTransport()
        let keys = FixtureKeyProvider()
        let key = try await keys.createKey(
            purpose: .credentialBinding,
            algorithm: .es256,
            requiresUserPresence: false,
            protection: .keychainSoftware
        )
        let disclosures = try [
            Self.disclosure(name: "given_name", value: "Ada"),
            Self.disclosure(name: "family_name", value: "Lovelace"),
            Self.disclosure(name: "email", value: "ada@example.test"),
        ]
        let issuer = try Self.compactJWT(payload: [
            "iss": "did:key:issuer",
            "issuer": "did:key:issuer",
            "vct": "urn:eu.europa.ec.eudi:pid:1",
            "cnf": ["jwk": ["kty": "EC"]],
            "_sd": disclosures.map {
                Data(SHA256.hash(data: Data($0.utf8))).base64EncodedString()
                    .replacingOccurrences(of: "+", with: "-")
                    .replacingOccurrences(of: "/", with: "_")
                    .replacingOccurrences(of: "=", with: "")
            },
        ])
        let stored = StoredEbsiCredential(
            profileID: "ietf-dc-sd-jwt-vc",
            representation: .dcSdJwt,
            rawCredential: Data((issuer + "~" + disclosures.joined(separator: "~") + "~").utf8),
            holderKeyReference: key.id.rawValue.uuidString
        )
        let backend = OpenID4VCW3CBackend(
            transport: transport,
            trustEvaluator: TrustedIssuerEvaluator(),
            keyProvider: keys,
            credentialStore: FixtureCredentialStore(values: [stored]),
            credentialValidator: FixtureCredentialValidator(),
            profile: try .dcSdJWTVC()
        )
        let offer = try await Self.authorizationOffer(backend)
        _ = try await backend.beginPresentationRequired(
            id: offer.id,
            allowUntrusted: false,
            interactionTypes: ["urn:openid:dcp:ia:openid4vp_presentation"]
        )
        let request = try await backend.prepareStoredPIDPresentation(id: offer.id)
        #expect(request.claims.count == 3)
        let token = try await backend.storedPIDPresentationToken(
            id: offer.id,
            selectedClaimIDs: Set(request.claims.map(\.id))
        )
        let object = try #require(JSONSerialization.jsonObject(with: Data(token.utf8)) as? [String: [String]])
        let presentation = try #require(object["pid"]?.first)
        let components = presentation.split(separator: "~", omittingEmptySubsequences: false)
        #expect(components.count == 5)
        let keyBinding = String(components[4])
        let keyBindingPayload = try Self.jwtPayload(keyBinding)
        #expect(keyBindingPayload["nonce"] as? String == "vp-nonce")
        #expect(keyBindingPayload["aud"] as? String == "ia:https://issuer.example")
        let withoutKeyBinding = components.dropLast().joined(separator: "~") + "~"
        let expectedHash = Data(SHA256.hash(data: Data(withoutKeyBinding.utf8))).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        #expect(keyBindingPayload["sd_hash"] as? String == expectedHash)
        _ = try await backend.submitPresentation(id: offer.id, vpToken: token)
        let post = try #require((await transport.requests).last { request in
            String(decoding: request.body ?? Data(), as: UTF8.self).contains("openid4vp_response=")
        })
        let form = String(decoding: try #require(post.body), as: UTF8.self)
        let fields = Dictionary(uniqueKeysWithValues: try #require(
            URLComponents(string: "?\(form)")?.queryItems
        ).compactMap { item in item.value.map { (item.name, $0) } })
        let wrapped = try #require(fields["openid4vp_response"])
        let response = try #require(JSONSerialization.jsonObject(with: Data(wrapped.utf8)) as? [String: Any])
        let vpToken = try #require(response["vp_token"] as? [String: [String]])
        #expect(vpToken["pid"]?.first == presentation)
    }

    @Test("Stored jwt_vc_json credential creates a holder-signed JWT VP")
    func storedJWTVCPresentation() async throws {
        let transport = FixtureOpenID4VCTransport(presentationFormat: "jwt_vc_json")
        let keys = FixtureKeyProvider()
        let key = try await keys.createKey(
            purpose: .credentialBinding,
            algorithm: .es256,
            requiresUserPresence: false,
            protection: .keychainSoftware
        )
        let holder = try KeyDIDResolver().derive(
            publicKeyX963: try await keys.publicKey(id: key.id).x963Representation
        )
        let credential = try Self.compactJWT(typ: "JWT", payload: [
            "iss": "did:key:issuer",
            "sub": holder,
            "vc": [
                "@context": ["https://www.w3.org/2018/credentials/v1"],
                "type": ["VerifiableCredential", "PersonIdentificationData"],
                "issuer": "did:key:issuer",
                "issuanceDate": "2026-01-01T00:00:00Z",
                "credentialSubject": [
                    "id": holder,
                    "given_name": "Ada",
                    "family_name": "Lovelace",
                ],
            ],
        ])
        let stored = StoredEbsiCredential(
            profileID: "ebsi-vcdm11-jwt-vc",
            representation: .jwtVcJson,
            rawCredential: Data(credential.utf8),
            holderKeyReference: key.id.rawValue.uuidString
        )
        let backend = OpenID4VCW3CBackend(
            transport: transport,
            trustEvaluator: TrustedIssuerEvaluator(),
            keyProvider: keys,
            credentialStore: FixtureCredentialStore(values: [stored]),
            credentialValidator: FixtureCredentialValidator(),
            profile: try .vcdm11Jwt()
        )
        let offer = try await Self.authorizationOffer(backend)
        _ = try await backend.beginPresentationRequired(
            id: offer.id,
            allowUntrusted: false
        )
        let request = try await backend.prepareStoredPIDPresentation(id: offer.id)
        let token = try await backend.storedPIDPresentationToken(
            id: offer.id,
            selectedClaimIDs: Set(request.claims.map(\.id))
        )
        let object = try #require(JSONSerialization.jsonObject(with: Data(token.utf8)) as? [String: [String]])
        let vpJWT = try #require(object["pid"]?.first)
        let payload = try Self.jwtPayload(vpJWT)
        #expect(payload["nonce"] as? String == "vp-nonce")
        #expect(payload["aud"] as? String == "ia:https://issuer.example")
        let vp = try #require(payload["vp"] as? [String: Any])
        #expect(vp["@context"] as? [String] == ["https://www.w3.org/2018/credentials/v1"])
        let presentedCredentials = try #require(vp["verifiableCredential"] as? [String])
        #expect(presentedCredentials == [credential])
        _ = try await backend.submitPresentation(id: offer.id, vpToken: token)
        let post = try #require((await transport.requests).last { request in
            String(decoding: request.body ?? Data(), as: UTF8.self).contains("openid4vp_response=")
        })
        let form = String(decoding: try #require(post.body), as: UTF8.self)
        let fields = Dictionary(uniqueKeysWithValues: try #require(
            URLComponents(string: "?\(form)")?.queryItems
        ).compactMap { item in item.value.map { (item.name, $0) } })
        let wrapped = try #require(fields["openid4vp_response"])
        let response = try #require(JSONSerialization.jsonObject(with: Data(wrapped.utf8)) as? [String: Any])
        let submitted = try #require(response["vp_token"] as? [String: [String]])
        let submittedJWT = try #require(submitted["pid"]?.first)
        #expect(try Self.jwtPayload(submittedJWT)["nonce"] as? String == "vp-nonce")
    }

    @Test("Standalone OpenID4VP 1.0 and 1.1 request presents a stored jwt_vc_json credential")
    func standaloneOpenID4VPPresentation() async throws {
        let transport = FixtureOpenID4VCTransport(presentationFormat: "jwt_vc_json")
        let keys = FixtureKeyProvider()
        let key = try await keys.createKey(
            purpose: .credentialBinding,
            algorithm: .es256,
            requiresUserPresence: false,
            protection: .keychainSoftware
        )
        let holder = try KeyDIDResolver().derive(
            publicKeyX963: try await keys.publicKey(id: key.id).x963Representation
        )
        let credential = try Self.compactJWT(payload: [
            "iss": "did:key:issuer",
            "issuer": "did:key:issuer",
            "sub": holder,
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential", "PersonIdentificationData"],
            "credentialSubject": ["id": holder, "given_name": "Ada", "family_name": "Lovelace"],
        ])
        let stored = StoredEbsiCredential(
            profileID: "ebsi-vcdm2-jwt-vc",
            representation: .vcdm2Jwt,
            rawCredential: Data(credential.utf8),
            holderKeyReference: key.id.rawValue.uuidString
        )
        let backend = OpenID4VCW3CBackend(
            transport: transport,
            trustEvaluator: TrustedIssuerEvaluator(),
            keyProvider: keys,
            credentialStore: FixtureCredentialStore(values: [stored]),
            credentialValidator: FixtureCredentialValidator(),
            profile: try .vcdm2JWTVC(),
            presentationRequestValidator: FixturePresentationRequestValidator()
        )
        let clientID = "decentralized_identifier:did:key:verifier"
        let deepLink = "openid4vp://?client_id=\(clientID)&request_uri=https%3A%2F%2Fissuer.example%2Fopenid4vp%2Frequest"
        let request = try await backend.beginStoredOpenID4VPPresentation(uri: deepLink)
        let redirectURI = try await backend.completeStoredOpenID4VPPresentation(
            id: request.id,
            selectedClaimIDs: Set(request.claims.map(\.id)),
            userAccepted: true
        )
        #expect(redirectURI == URL(string: "https://verifier.example/done"))
        let post = try #require((await transport.requests).last { $0.url.path == "/openid4vp/response" })
        let fields = Dictionary(uniqueKeysWithValues: try #require(
            URLComponents(string: "?\(String(decoding: post.body ?? Data(), as: UTF8.self))")?.queryItems
        ).compactMap { item in item.value.map { (item.name, $0) } })
        #expect(fields["state"] == "vp-state")
        let token = try #require(fields["vp_token"])
        let object = try #require(JSONSerialization.jsonObject(with: Data(token.utf8)) as? [String: [String]])
        let vpJWT = try #require(object["pid"]?.first)
        let header = try Self.jwtHeader(vpJWT)
        #expect(header["typ"] as? String == "vp+jwt")
        #expect(header["cty"] as? String == "vp")
        #expect((header["kid"] as? String)?.hasPrefix("\(holder)#") == true)
        let payload = try Self.jwtPayload(vpJWT)
        #expect(payload["aud"] as? String == clientID)
        #expect(payload["nonce"] as? String == "vp-nonce")
        #expect(payload["vp"] == nil)
        #expect(payload["@context"] as? [String] == ["https://www.w3.org/ns/credentials/v2"])
        #expect(payload["type"] as? [String] == ["VerifiablePresentation"])
        let enveloped = try #require((payload["verifiableCredential"] as? [[String: Any]])?.first)
        #expect(enveloped["@context"] as? [String] == ["https://www.w3.org/ns/credentials/v2"])
        #expect(enveloped["type"] as? [String] == ["EnvelopedVerifiableCredential"])
        #expect(enveloped["id"] as? String == "data:application/vc+jwt,\(credential)")

        let rejectingBackend = OpenID4VCW3CBackend(
            transport: transport,
            trustEvaluator: TrustedIssuerEvaluator(),
            keyProvider: keys,
            credentialStore: FixtureCredentialStore(values: [stored]),
            credentialValidator: FixtureCredentialValidator(),
            profile: try .vcdm2JWTVC(),
            presentationRequestValidator: FixturePresentationRequestValidator()
        )
        let rejectedRequest = try await rejectingBackend.beginStoredOpenID4VPPresentation(uri: deepLink)
        let rejectionRedirect = try await rejectingBackend.completeStoredOpenID4VPPresentation(
            id: rejectedRequest.id, selectedClaimIDs: [], userAccepted: false
        )
        #expect(rejectionRedirect == URL(string: "https://verifier.example/done"))
        let rejection = try #require((await transport.requests).last { $0.url.path == "/openid4vp/response" })
        let rejectionFields = Dictionary(uniqueKeysWithValues: try #require(
            URLComponents(string: "?\(String(decoding: rejection.body ?? Data(), as: UTF8.self))")?.queryItems
        ).compactMap { item in item.value.map { (item.name, $0) } })
        #expect(rejectionFields == ["error": "access_denied", "state": "vp-state"])
        await #expect(throws: OpenID4VCBackendError.unknownTransaction) {
            _ = try await rejectingBackend.completeStoredOpenID4VPPresentation(
                id: rejectedRequest.id, selectedClaimIDs: [], userAccepted: false
            )
        }
    }

    @Test("Standalone redirect_uri JAR request presents a stored jwt_vc_json credential")
    func standaloneRedirectURIJARPresentation() async throws {
        let keys = FixtureKeyProvider()
        let key = try await keys.createKey(
            purpose: .credentialBinding,
            algorithm: .es256,
            requiresUserPresence: false,
            protection: .keychainSoftware
        )
        let holder = try KeyDIDResolver().derive(
            publicKeyX963: try await keys.publicKey(id: key.id).x963Representation
        )
        let credential = try Self.compactJWT(payload: [
            "iss": "did:key:issuer",
            "issuer": "did:key:issuer",
            "sub": holder,
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential", "PersonIdentificationData"],
            "credentialSubject": ["id": holder, "given_name": "Ada", "family_name": "Lovelace"],
        ])
        let stored = StoredEbsiCredential(
            profileID: "ebsi-vcdm2-jwt-vc",
            representation: .vcdm2Jwt,
            rawCredential: Data(credential.utf8),
            holderKeyReference: key.id.rawValue.uuidString
        )
        let transport = RedirectURIStandaloneTransport()
        let backend = OpenID4VCW3CBackend(
            transport: transport,
            trustEvaluator: TrustedIssuerEvaluator(),
            keyProvider: keys,
            credentialStore: FixtureCredentialStore(values: [stored]),
            credentialValidator: FixtureCredentialValidator(),
            profile: try .vcdm2JWTVC(),
            presentationRequestValidator: FixturePresentationRequestValidator()
        )
        let deepLink = "openid4vp://?client_id=redirect_uri%3Ahttps%3A%2F%2Fwallet.dev.oari.io"
            + "%2Fopenid%2Fvp%2F7ecf09ec-162a-4792-a097-a0cae714fdcb"
            + "&request_uri=https%3A%2F%2Fwallet.dev.oari.io%2Fopenid%2Fvp%2F7ecf09ec-162a-4792-a097-a0cae714fdcb"
        let request = try await backend.beginStoredOpenID4VPPresentation(uri: deepLink)
        #expect(request.verifierName == RedirectURIStandaloneTransport.clientID)
        let redirectURI = try await backend.completeStoredOpenID4VPPresentation(
            id: request.id,
            selectedClaimIDs: Set(request.claims.map(\.id)),
            userAccepted: true
        )
        #expect(redirectURI == URL(string: "https://verifier.example/done"))
        let fetch = try #require((await transport.requests).first)
        #expect(fetch.method == "GET")
        #expect(fetch.headers["Accept"] == "application/oauth-authz-req+jwt")
        let post = try #require((await transport.requests).last { $0.method == "POST" })
        #expect(post.url == URL(string: RedirectURIStandaloneTransport.endpoint))
        let fields = Dictionary(uniqueKeysWithValues: try #require(
            URLComponents(string: "?\(String(decoding: post.body ?? Data(), as: UTF8.self))")?.queryItems
        ).compactMap { item in item.value.map { (item.name, $0) } })
        let token = try #require(fields["vp_token"])
        let object = try #require(JSONSerialization.jsonObject(with: Data(token.utf8)) as? [String: [String]])
        let vpJWT = try #require(object["user"]?.first)
        let payload = try Self.jwtPayload(vpJWT)
        #expect(payload["aud"] as? String == RedirectURIStandaloneTransport.clientID)
        #expect(payload["nonce"] as? String == "vp-nonce")
    }

    @Test("Standalone redirect_uri client_id must exactly match the signed response_uri")
    func standaloneRedirectURIRequiresMatchingResponseURI() async throws {
        let backend = try Self.standaloneEnvelopeBackend(
            transport: StandaloneEnvelopeTransport(response: .init(statusCode: 500, body: Data()))
        )
        let jwt = try Self.standaloneRequestJWT(
            clientID: "redirect_uri:https://verifier.example/expected",
            responseURI: "https://verifier.example/other"
        )
        let encoded = try #require(jwt.addingPercentEncoding(withAllowedCharacters: .alphanumerics))
        await #expect(throws: OpenID4VCBackendError.invalidPresentationChallenge(
            reason: "redirect_uri client_id did not match the response_uri"
        )) {
            _ = try await backend.beginStoredOpenID4VPPresentation(
                uri: "openid4vp://?client_id=redirect_uri%3Ahttps%3A%2F%2Fverifier.example%2Fexpected&request=\(encoded)"
            )
        }
    }

    @Test("Standalone redirect_uri request_uri must share the client_id origin")
    func standaloneRedirectURIRequiresMatchingRequestURIOrigin() async throws {
        let jwt = try Self.standaloneRequestJWT(
            clientID: "redirect_uri:https://verifier.example/openid/vp/1",
            responseURI: "https://verifier.example/openid/vp/1"
        )
        let backend = try Self.standaloneEnvelopeBackend(
            transport: StandaloneEnvelopeTransport(response: .init(
                statusCode: 200,
                body: Data(jwt.utf8),
                headers: ["Content-Type": "application/oauth-authz-req+jwt"]
            ))
        )
        await #expect(throws: OpenID4VCBackendError.invalidPresentationChallenge(
            reason: "request_uri origin did not match the redirect_uri client_id"
        )) {
            _ = try await backend.beginStoredOpenID4VPPresentation(
                uri: "openid4vp://?client_id=redirect_uri%3Ahttps%3A%2F%2Fverifier.example%2Fopenid%2Fvp%2F1"
                    + "&request_uri=https%3A%2F%2Fattacker.example%2Frequest"
            )
        }
    }

    @Test("Standalone audience accepts self-issued or a matching iss and rejects others")
    func standaloneAudienceRules() async throws {
        let clientID = "redirect_uri:https://verifier.example/openid/vp/1"
        let envelope = "openid4vp://?client_id=redirect_uri%3Ahttps%3A%2F%2Fverifier.example%2Fopenid%2Fvp%2F1&request="
        let accepted = try Self.standaloneRequestJWT(
            clientID: clientID,
            responseURI: "https://verifier.example/openid/vp/1",
            audience: "did:ebsi:zVerifier",
            issuer: "did:ebsi:zVerifier"
        )
        let acceptedBackend = try Self.standaloneEnvelopeBackend(
            transport: StandaloneEnvelopeTransport(response: .init(statusCode: 500, body: Data()))
        )
        let encodedAccepted = try #require(accepted.addingPercentEncoding(withAllowedCharacters: .alphanumerics))
        await #expect(throws: OpenID4VCBackendError.presentationCredentialUnavailable) {
            _ = try await acceptedBackend.beginStoredOpenID4VPPresentation(uri: envelope + encodedAccepted)
        }
        for (audience, issuer) in [("did:ebsi:zVerifier", "did:ebsi:zSomeoneElse"), ("did:ebsi:zVerifier", nil)] {
            let jwt = try Self.standaloneRequestJWT(
                clientID: clientID,
                responseURI: "https://verifier.example/openid/vp/1",
                audience: audience,
                issuer: issuer
            )
            let backend = try Self.standaloneEnvelopeBackend(
                transport: StandaloneEnvelopeTransport(response: .init(statusCode: 500, body: Data()))
            )
            let encoded = try #require(jwt.addingPercentEncoding(withAllowedCharacters: .alphanumerics))
            await #expect(throws: OpenID4VCBackendError.invalidPresentationChallenge(
                reason: "unsupported standalone response mode or response URI"
            )) {
                _ = try await backend.beginStoredOpenID4VPPresentation(uri: envelope + encoded)
            }
        }
    }

    @Test("Standalone envelope enforces request source and request_uri_method singletons")
    func standaloneEnvelopeValidation() async throws {
        let transport = StandaloneEnvelopeTransport(response: .init(statusCode: 500, body: Data()))
        let backend = try Self.standaloneEnvelopeBackend(transport: transport)
        let base = "openid4vp://?client_id=decentralized_identifier:did:key:verifier"

        await #expect(throws: OpenID4VCBackendError.invalidPresentationChallenge(
            reason: "OpenID4VP envelope must contain exactly one of request or request_uri"
        )) {
            _ = try await backend.beginStoredOpenID4VPPresentation(uri: base)
        }
        await #expect(throws: OpenID4VCBackendError.invalidPresentationChallenge(
            reason: "duplicate request_uri parameter"
        )) {
            _ = try await backend.beginStoredOpenID4VPPresentation(
                uri: base + "&request_uri=https://issuer.example/a&request_uri=https://issuer.example/b"
            )
        }
        await #expect(throws: OpenID4VCBackendError.invalidPresentationChallenge(
            reason: "request_uri_method requires request_uri"
        )) {
            _ = try await backend.beginStoredOpenID4VPPresentation(uri: base + "&request=x.y.z&request_uri_method=get")
        }
        for valuelessMethod in ["&request_uri_method", "&request_uri_method="] {
            await #expect(throws: OpenID4VCBackendError.invalidPresentationChallenge(
                reason: "request_uri_method was empty"
            )) {
                _ = try await backend.beginStoredOpenID4VPPresentation(
                    uri: base + "&request_uri=https://issuer.example/request" + valuelessMethod
                )
            }
        }
        await #expect(throws: OpenID4VCBackendError.invalidPresentationChallenge(
            reason: "request_uri_method post is not supported"
        )) {
            _ = try await backend.beginStoredOpenID4VPPresentation(
                uri: base + "&request_uri=https://issuer.example/request&request_uri_method=post"
            )
        }
        await #expect(throws: OpenID4VCBackendError.invalidPresentationChallenge(
            reason: "unsupported request_uri_method put"
        )) {
            _ = try await backend.beginStoredOpenID4VPPresentation(
                uri: base + "&request_uri=https://issuer.example/request&request_uri_method=put"
            )
        }
        #expect(await transport.requestCount == 0)
    }

    @Test("request_uri requires its JWT media type while inline request bypasses fetch")
    func standaloneRequestRetrievalContract() async throws {
        let jwt = try Self.standaloneRequestJWT()
        let wrongType = StandaloneEnvelopeTransport(response: .init(
            statusCode: 200, body: Data(jwt.utf8), headers: ["Content-Type": "application/jwt"]
        ))
        let fetchedBackend = try Self.standaloneEnvelopeBackend(transport: wrongType)
        await #expect(throws: OpenID4VCBackendError.invalidPresentationChallenge(
            reason: "request_uri response Content-Type was not application/oauth-authz-req+jwt"
        )) {
            _ = try await fetchedBackend.beginStoredOpenID4VPPresentation(
                uri: "openid4vp://?client_id=decentralized_identifier:did:key:verifier&request_uri=https://issuer.example/request"
            )
        }

        let upperBoundary = StandaloneEnvelopeTransport(response: .init(
            statusCode: 299,
            body: Data(jwt.utf8),
            headers: ["cOnTeNt-TyPe": "Application/OAuth-Authz-Req+JWT; charset=UTF-8"]
        ))
        let upperBoundaryBackend = try Self.standaloneEnvelopeBackend(transport: upperBoundary)
        await #expect(throws: OpenID4VCBackendError.presentationCredentialUnavailable) {
            _ = try await upperBoundaryBackend.beginStoredOpenID4VPPresentation(
                uri: "openid4vp://?client_id=decentralized_identifier:did:key:verifier&request_uri=https://issuer.example/request&request_uri_method=get"
            )
        }

        let neverFetch = StandaloneEnvelopeTransport(response: .init(statusCode: 500, body: Data()))
        let inlineBackend = try Self.standaloneEnvelopeBackend(transport: neverFetch)
        let encoded = try #require(jwt.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed))
        await #expect(throws: OpenID4VCBackendError.presentationCredentialUnavailable) {
            _ = try await inlineBackend.beginStoredOpenID4VPPresentation(
                uri: "openid4vp://?client_id=decentralized_identifier:did:key:verifier&request=\(encoded)"
            )
        }
        #expect(await neverFetch.requestCount == 0)
    }

    @Test("Standalone decentralized_identifier requests require matching ES256 verifier metadata before preparation")
    func standaloneRequiresVerifierMetadata() async throws {
        let cases: [(metadata: [String: Any]?, reason: String)] = [
            (nil, "verifier metadata did not support ES256 for the requested presentation format"),
            (["vp_formats_supported": [:]], "verifier metadata did not support ES256 for the requested presentation format"),
            (["vp_formats_supported": ["jwt_vc_json": ["alg_values": ["ES384"]]]], "verifier metadata did not support ES256 for the requested presentation format"),
        ]
        for test in cases {
            let backend = try Self.standaloneEnvelopeBackend(
                transport: StandaloneEnvelopeTransport(response: .init(statusCode: 500, body: Data()))
            )
            let jwt = try Self.standaloneRequestJWT(clientMetadata: test.metadata)
            let encoded = try #require(jwt.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed))
            await #expect(throws: OpenID4VCBackendError.invalidPresentationChallenge(reason: test.reason)) {
                _ = try await backend.beginStoredOpenID4VPPresentation(
                    uri: "openid4vp://?client_id=decentralized_identifier:did:key:verifier&request=\(encoded)"
                )
            }
        }
    }

    @Test("Standalone signed response_uri must be strict HTTPS before replay or preparation")
    func standaloneRejectsUnsafeSignedResponseURI() async throws {
        for responseURI in [
            "https://user@issuer.example/response", "https://issuer.example/response#fragment",
            "https:///response",
        ] {
            let backend = try Self.standaloneEnvelopeBackend(
                transport: StandaloneEnvelopeTransport(response: .init(statusCode: 500, body: Data()))
            )
            let jwt = try Self.standaloneRequestJWT(responseURI: responseURI)
            let encoded = try #require(jwt.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed))
            await #expect(throws: OpenID4VCBackendError.invalidPresentationChallenge(
                reason: "unsupported standalone response mode or response URI"
            )) {
                _ = try await backend.beginStoredOpenID4VPPresentation(
                    uri: "openid4vp://?client_id=decentralized_identifier:did:key:verifier&request=\(encoded)"
                )
            }
        }
    }

    @Test("Stored W3C credential deletion is idempotent")
    func storedCredentialDeletion() async throws {
        let credential = StoredEbsiCredential(
            profileID: "ebsi-vcdm2-jwt-vc",
            representation: .vcdm2Jwt,
            rawCredential: Data("credential".utf8),
            holderKeyReference: UUID().uuidString
        )
        let store = FixtureCredentialStore(values: [credential])
        let backend = OpenID4VCW3CBackend(
            transport: FixtureOpenID4VCTransport(),
            trustEvaluator: TrustedIssuerEvaluator(),
            keyProvider: FixtureKeyProvider(),
            credentialStore: store,
            credentialValidator: FixtureCredentialValidator(),
            profile: try .vcdm2JWTVC()
        )
        try await backend.deleteStoredCredential(id: credential.id)
        try await backend.deleteStoredCredential(id: credential.id)
        #expect(try await store.credentials().isEmpty)
    }

    private static func jwtPayload(_ compact: String) throws -> [String: Any] {
        try jwtSegment(compact, index: 1)
    }

    private static func standaloneRequestJWT(
        clientID: String = "decentralized_identifier:did:key:verifier",
        clientMetadata: [String: Any]? = ["vp_formats_supported": [
            "jwt_vc_json": ["alg_values": ["ES256"]],
        ]],
        responseURI: String = "https://issuer.example/response",
        audience: String = "https://self-issued.me/v2",
        issuer: String? = nil
    ) throws -> String {
        let issuedAt = Int(Date().timeIntervalSince1970)
        var payload: [String: Any] = [
            "aud": audience,
            "client_id": clientID,
            "response_type": "vp_token",
            "response_mode": "direct_post",
            "response_uri": responseURI,
            "nonce": UUID().uuidString,
            "iat": issuedAt,
            "exp": issuedAt + 300,
            "dcql_query": ["credentials": [[
                "id": "pid", "format": "jwt_vc_json",
                "meta": ["type_values": [["VerifiableCredential"]]],
            ]]],
        ]
        payload["client_metadata"] = clientMetadata
        payload["iss"] = issuer
        return try compactJWT(payload: payload)
    }

    private static func standaloneEnvelopeBackend(
        transport: any OpenID4VCHTTPTransport
    ) throws -> OpenID4VCW3CBackend {
        OpenID4VCW3CBackend(
            transport: transport,
            trustEvaluator: TrustedIssuerEvaluator(),
            keyProvider: FixtureKeyProvider(),
            credentialStore: FixtureCredentialStore(),
            credentialValidator: FixtureCredentialValidator(),
            profile: try .vcdm11Jwt(),
            presentationRequestValidator: FixturePresentationRequestValidator()
        )
    }

    private static func jwtHeader(_ compact: String) throws -> [String: Any] {
        try jwtSegment(compact, index: 0)
    }

    private static func jwtSegment(_ compact: String, index: Int) throws -> [String: Any] {
        let parts = compact.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 3 else { throw OpenID4VCBackendError.invalidResponse }
        var base64 = String(parts[index]).replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        base64 += String(repeating: "=", count: (4 - base64.count % 4) % 4)
        let data = try #require(Data(base64Encoded: base64))
        return try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])
    }

    private static func authorizationOffer(
        _ backend: OpenID4VCW3CBackend
    ) async throws -> ResolvedOpenID4VCCredentialOffer {
        let json = #"{"credential_issuer":"https://issuer.example","credential_configuration_ids":["example-vcdm2-jwt-vc"],"grants":{"authorization_code":{"issuer_state":"issuer-state"}}}"#
        let encoded = try #require(json.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed))
        return try await backend.resolveOffer("openid-credential-offer://?credential_offer=\(encoded)")
    }

    private static func compactJWT(typ: String = "vc+jwt", payload: [String: Any]) throws -> String {
        func encode(_ object: Any) throws -> String {
            try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
                .base64EncodedString().replacingOccurrences(of: "+", with: "-")
                .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
        }
        return try "\(encode(["alg": "ES256", "typ": typ])).\(encode(payload)).signature"
    }

    private static func disclosure(name: String, value: String) throws -> String {
        try JSONSerialization.data(withJSONObject: [UUID().uuidString, name, value])
            .base64EncodedString().replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }

    private func assertRejectedDraftToken(
        _ tokenResponse: String,
        expected: OpenID4VCBackendError
    ) async throws {
        let transport = Draft13OpenID4VCTransport(tokenResponse: tokenResponse)
        let backend = OpenID4VCW3CBackend(
            transport: transport,
            trustEvaluator: TrustedIssuerEvaluator(),
            keyProvider: FixtureKeyProvider(),
            credentialStore: FixtureCredentialStore(),
            credentialValidator: FixtureCredentialValidator(),
            profile: try .dcSdJWTVC(),
            clientSecurity: RecordingOID4VCIClientSecurity(),
            transportProfileRegistry: .developmentDraftCompatibility
        )
        let offer = try await backend.resolveOffer(try Self.draftOffer())
        await #expect(throws: expected) {
            _ = try await backend.issue(id: offer.id, allowUntrusted: false, transactionCode: "1234")
        }
        #expect(!(await transport.requests).contains { $0.url.path.hasSuffix("/credential") })
    }

    private static func draftOffer() throws -> String {
        let json = #"{"credential_issuer":"https://issuer.example/service/draft-13","credential_configuration_ids":["pid-config"],"grants":{"urn:ietf:params:oauth:grant-type:pre-authorized_code":{"pre-authorized_code":"pre-code","tx_code":{"input_mode":"numeric","length":4}}}}"#
        let encoded = try #require(json.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed))
        return "openid-credential-offer://?credential_offer=\(encoded)"
    }

    @Test("Manual live QESAC redemption emits only redacted interoperability diagnostics")
    func manualLiveQESACRedemption() async throws {
        guard let offerURI = ProcessInfo.processInfo.environment["OPENID4VCI_LIVE_QESAC_OFFER"] else {
            return
        }
        let transport = URLSessionOpenID4VCTransport()
        let keyProvider = FixtureKeyProvider()
        let store = FixtureCredentialStore()
        let validator = LiveDiagnosticCredentialValidator(
            validator: NativeW3CCredentialValidator(
                resolver: LiveRejectingDIDResolver(),
                transport: transport
            )
        )
        let backend = OpenID4VCW3CBackend(
            transport: transport,
            trustEvaluator: TrustedIssuerEvaluator(),
            keyProvider: keyProvider,
            credentialStore: store,
            credentialValidator: validator,
            profile: try .vcdm2JWTVC(),
            additionalProfiles: [try .vcdm11Jwt(), try .dcSdJWTVC(), try .vcdm2SdJWT()],
            clientSecurity: DefaultOID4VCIClientSecurity(keyProvider: keyProvider),
            transportProfileRegistry: .developmentDraftCompatibility
        )

        let offer = try await backend.resolveOffer(offerURI)
        let issued = try await backend.issue(
            id: offer.id,
            allowUntrusted: false,
            transactionCode: nil
        )
        #expect(issued.count == 1)
        #expect(try await store.credentials().count == 1)
        print("LIVE_QESAC stored=true format=dc+sd-jwt configuration_count=\(offer.configurationIDs.count)")
    }

    @Test("Manual live credential offer redemption")
    func manualLiveCredentialOfferRedemption() async throws {
        guard let offerURI = ProcessInfo.processInfo.environment["OPENID4VCI_LIVE_OFFER"],
              let transactionCode = ProcessInfo.processInfo.environment["OPENID4VCI_LIVE_PIN"] else {
            return
        }
        let transport = URLSessionOpenID4VCTransport()
        let keyProvider = FixtureKeyProvider()
        let store = FixtureCredentialStore()
        let backend = OpenID4VCW3CBackend(
            transport: transport,
            trustEvaluator: HTTPSCredentialIssuerServiceTrustEvaluator(),
            keyProvider: keyProvider,
            credentialStore: store,
            credentialValidator: FixtureCredentialValidator(),
            profile: try .vcdm2JWTVC(),
            additionalProfiles: [try .vcdm11Jwt(), try .dcSdJWTVC(), try .vcdm2SdJWT()],
            clientSecurity: DefaultOID4VCIClientSecurity(keyProvider: keyProvider),
            transportProfileRegistry: .productionInteroperability
        )

        let offer = try await backend.resolveOffer(offerURI)
        let issued = try await backend.issue(
            id: offer.id,
            allowUntrusted: false,
            transactionCode: transactionCode
        )
        #expect(issued.count == 1)
        #expect(try await store.credentials().count == 1)
        print("LIVE_OPENID4VCI stored=true configuration_count=\(offer.configurationIDs.count)")
    }
}

private struct LiveRejectingDIDResolver: DIDResolver {
    func resolve(_ did: String) async throws -> DIDDocument {
        throw DIDResolutionError.unsupportedMethod
    }
}

private struct LiveDiagnosticCredentialValidator: W3CCredentialValidating {
    let validator: NativeW3CCredentialValidator

    func validate(
        rawCredential: Data,
        profile: EbsiCredentialProfile,
        expectedIssuer: String?,
        expectedHolderDID: String,
        at date: Date
    ) async throws -> String {
        let compact = String(decoding: rawCredential, as: UTF8.self)
        let issuerJWS = compact.split(separator: "~", maxSplits: 1).first.map(String.init) ?? ""
        let parts = issuerJWS.split(separator: ".", omittingEmptySubsequences: false)
        var headerNames: [String] = []
        var kidKind = "absent"
        var certificateCount = 0
        var signatureBytes = 0
        if parts.count == 3,
           let headerData = Self.base64URLData(String(parts[0])),
           let header = try? JSONSerialization.jsonObject(with: headerData) as? [String: Any] {
            headerNames = header.keys.sorted()
            if let kid = header["kid"] as? String {
                kidKind = kid == "None" ? "sentinel" : "present"
            }
            certificateCount = (header["x5c"] as? [String])?.count ?? 0
            signatureBytes = Self.base64URLData(String(parts[2]))?.count ?? 0
        }
        print(
            "LIVE_QESAC protected_header_keys=\(headerNames.joined(separator: ",")) " +
            "kid=\(kidKind) x5c_count=\(certificateCount) signature_bytes=\(signatureBytes)"
        )
        return try await validator.validate(
            rawCredential: rawCredential,
            profile: profile,
            expectedIssuer: expectedIssuer,
            expectedHolderDID: expectedHolderDID,
            at: date
        )
    }

    private static func base64URLData(_ value: String) -> Data? {
        var base64 = value.replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        base64 += String(repeating: "=", count: (4 - base64.count % 4) % 4)
        return Data(base64Encoded: base64)
    }
}

private actor WildcardIssuerMetadataTransport: OpenID4VCHTTPTransport {
    func send(url: URL, method: String, headers: [String: String], body: Data?) async throws -> OpenID4VCHTTPResponse {
        guard url.path == "/.well-known/openid-credential-issuer" else {
            return OpenID4VCHTTPResponse(statusCode: 404, body: Data())
        }
        return OpenID4VCHTTPResponse(statusCode: 200, body: Data(#"""
        {
          "credential_issuer":"https://issuer.example",
          "credential_endpoint":"https://issuer.example/credential",
          "credential_configurations_supported":{
            "selected":{
              "format":"dc+sd-jwt",
              "vct":"UniversityDegree",
              "credential_metadata":{"display":[{"name":"University Degree"}],"claims":[{"path":["degree","name"]}]}
            },
            "PortableDocumentA1bDEeedcj":{
              "format":"jwt_vc_json",
              "credential_metadata":{
                "display":[{"name":"Portable Document A1"}],
                "claims":[
                  {"path":["credentialSubject","section5","workPlaceAddresses",null,"address","countryCode"]},
                  {"path":["credentialSubject","items",0,"name"]}
                ]
              }
            }
          }
        }
        """#.utf8))
    }
}

private actor DraftIARFallbackTransport: OpenID4VCHTTPTransport {
    struct Request: Sendable { let url: URL; let method: String; let body: Data? }
    private(set) var requests: [Request] = []

    func send(url: URL, method: String, headers: [String: String], body: Data?) async throws -> OpenID4VCHTTPResponse {
        requests.append(Request(url: url, method: method, body: body))
        switch url.path {
        case "/.well-known/openid-credential-issuer/service/draft-13":
            return OpenID4VCHTTPResponse(statusCode: 200, body: Data(#"{"credential_issuer":"https://issuer.example/service/draft-13","credential_endpoint":"https://issuer.example/credential","authorization_servers":["https://issuer.example/service/draft-13"],"credential_configurations_supported":{"pid":{"format":"dc+sd-jwt","vct":"urn:example:pid"}}}"#.utf8))
        case "/.well-known/oauth-authorization-server/service/draft-13":
            return OpenID4VCHTTPResponse(statusCode: 200, body: Data(#"{"issuer":"https://issuer.example/service/draft-13","authorization_endpoint":"https://issuer.example/service/draft-13/authorize","token_endpoint":"https://issuer.example/token"}"#.utf8))
        case "/service/draft-13/authorize":
            guard method == "GET" else {
                return OpenID4VCHTTPResponse(statusCode: 405, body: Data(#"{"detail":"method not allowed"}"#.utf8))
            }
            let payload = Self.base64URL(#"{"client_id":"redirect_uri:https://issuer.example/service/draft-13/authorize","response_type":"vp_token","response_mode":"iar-post","response_uri":"https://issuer.example/service/draft-13/authorize","nonce":"nonce","state":"state","dcql_query":{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:example:pid"]},"claims":[{"path":["given_name"]}]}]}}"#)
            let response = """
            {"status":"require_interaction","type":"openid4vp_presentation","openid4vp_request":{"request":"header.\(payload).signature"}}
            """
            return OpenID4VCHTTPResponse(statusCode: 200, body: Data(response.utf8))
        default:
            return OpenID4VCHTTPResponse(statusCode: 404, body: Data())
        }
    }

    private static func base64URL(_ value: String) -> String {
        Data(value.utf8).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

private actor VPThenWebTransport: OpenID4VCHTTPTransport {
    private let initialWeb: Bool
    private(set) var continuationBody: String?
    private(set) var authorizationMetadataRequestCount = 0

    init(initialWeb: Bool = false) {
        self.initialWeb = initialWeb
    }

    func send(url: URL, method: String, headers: [String: String], body: Data?) async throws -> OpenID4VCHTTPResponse {
        let form = String(decoding: body ?? Data(), as: UTF8.self)
        switch url.path {
        case "/.well-known/openid-credential-issuer":
            return .init(statusCode: 200, body: Data(#"{"credential_issuer":"https://issuer.example","credential_endpoint":"https://issuer.example/credential","authorization_servers":["https://issuer.example"],"credential_configurations_supported":{"example-vcdm2-jwt-vc":{"format":"application/vc+jwt"}}}"#.utf8))
        case "/.well-known/oauth-authorization-server":
            authorizationMetadataRequestCount += 1
            return .init(statusCode: 200, body: Data(#"{"authorization_endpoint":"https://issuer.example/browser-authorize","authorization_challenge_endpoint":"https://issuer.example/authorize-challenge","token_endpoint":"https://issuer.example/token"}"#.utf8))
        case "/authorize-challenge" where form.contains("issuer_state=") && initialWeb:
            return .init(statusCode: 403, body: Data(#"{"error":"insufficient_authorization","interaction_type_required":"urn:openid:dcp:ia:auth_via_web","request_uri":"urn:ietf:params:oauth:request_uri:web-session-1","expires_in":60}"#.utf8))
        case "/authorize-challenge" where form.contains("issuer_state="):
            let query = #"{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:example:pid"]},"claims":[{"path":["given_name"]}]}"#
            return .init(statusCode: 403, body: Data("""
            {"error":"insufficient_authorization","interaction_type_required":"urn:openid:dcp:ia:openid4vp_presentation","auth_session":"vp-session","openid4vp_request":{"response_type":"vp_token","response_mode":"ia_post","nonce":"nonce","state":"state","dcql_query":{"credentials":[\(query)]}}}
            """.utf8))
        case "/authorize-challenge" where form.contains("openid4vp_response="):
            return .init(statusCode: 403, body: Data(#"{"error":"insufficient_authorization","interaction_type_required":"urn:openid:dcp:ia:auth_via_web","request_uri":"urn:ietf:params:oauth:request_uri:web-session-1","expires_in":60}"#.utf8))
        case "/authorize-challenge" where form.contains("auth_session=continued-session"):
            continuationBody = form
            return .init(statusCode: 200, body: Data(#"{"authorization_code":"web-code"}"#.utf8))
        default:
            return .init(statusCode: 404, body: Data())
        }
    }
}

private actor RedirectURIStandaloneTransport: OpenID4VCHTTPTransport {
    static let endpoint = "https://wallet.dev.oari.io/openid/vp/7ecf09ec-162a-4792-a097-a0cae714fdcb"
    static let clientID = "redirect_uri:" + endpoint

    struct Request: Sendable { let url: URL; let method: String; let headers: [String: String]; let body: Data? }
    private(set) var requests: [Request] = []

    func send(
        url: URL, method: String, headers: [String: String], body: Data?
    ) async throws -> OpenID4VCHTTPResponse {
        requests.append(Request(url: url, method: method, headers: headers, body: body))
        guard url.absoluteString == Self.endpoint else {
            return OpenID4VCHTTPResponse(statusCode: 404, body: Data())
        }
        if method == "GET" {
            return OpenID4VCHTTPResponse(
                statusCode: 200,
                body: Data(Self.requestObject().utf8),
                headers: ["Content-Type": "application/oauth-authz-req+jwt"]
            )
        }
        return OpenID4VCHTTPResponse(
            statusCode: 200,
            body: Data(#"{"redirect_uri":"https://verifier.example/done"}"#.utf8),
            headers: ["Content-Type": "application/json"]
        )
    }

    private static func requestObject() -> String {
        func encode(_ value: String) -> String {
            Data(value.utf8).base64EncodedString().replacingOccurrences(of: "+", with: "-")
                .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
        }
        let header = encode(#"{"alg":"ES256","typ":"oauth-authz-req+jwt"}"#)
        let issuedAt = Int(Date().timeIntervalSince1970)
        let payload = encode("""
        {"iss":"did:ebsi:zVerifier","aud":"did:ebsi:zVerifier","client_id":"\(clientID)","response_type":"vp_token","response_mode":"direct_post","response_uri":"\(endpoint)","nonce":"vp-nonce","iat":\(issuedAt),"exp":\(issuedAt + 300),"dcql_query":{"credentials":[{"id":"user","format":"jwt_vc_json","meta":{"type_values":[["VerifiableCredential"]]},"claims":[{"path":["credentialSubject","given_name"]},{"path":["credentialSubject","family_name"]}]}]},"client_metadata":{"client_name":"TigMar GmbH","vp_formats_supported":{"jwt_vc_json":{"alg_values":["ES256"]}}}}
        """)
        return "\(header).\(payload).signature"
    }
}

private actor StandaloneEnvelopeTransport: OpenID4VCHTTPTransport {
    private let response: OpenID4VCHTTPResponse
    private(set) var requestCount = 0

    init(response: OpenID4VCHTTPResponse) { self.response = response }

    func send(
        url: URL, method: String, headers: [String: String], body: Data?
    ) async throws -> OpenID4VCHTTPResponse {
        requestCount += 1
        return response
    }
}

private actor FixtureOpenID4VCTransport: OpenID4VCHTTPTransport {
    static let png = Data([
        0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a,
        0x00, 0x00, 0x00, 0x00,
    ])
    struct Request: Sendable { let url: URL; let method: String; let headers: [String: String]; let body: Data? }
    private(set) var requests: [Request] = []
    private let presentationFormat: String
    private let credentialFormat: String
    private let credentialResponse: String
    private let iGrantCompactPresentation: Bool
    private let omitAuthorizationResponseState: Bool
    private let authorizationResponseStateOverride: String?
    private let deferredInterval: Int?
    private let emitsTransaction: Bool
    private let initialCredentialStatus: Int
    private let initialTransactionID: String?
    private let pendingTransactionID: String?
    private let pendingInterval: Int?
    private let deferredStatus: Int
    private let legacyPendingError: Bool
    private let completedCredentialStatus: Int
    private let twoDeferredConfigurations: Bool
    private let secondDeferredFails: Bool
    private let advertisesNonceEndpoint: Bool
    private let tokenResponse: String
    private let credentialIssuerMetadata: String
    private var authorizationState: String?

    init(
        presentationFormat: String = "dc+sd-jwt",
        credentialFormat: String = "application/vc+jwt",
        credentialResponse: String = "header.payload.signature",
        iGrantCompactPresentation: Bool = false,
        omitAuthorizationResponseState: Bool = false,
        authorizationResponseStateOverride: String? = nil,
        deferredInterval: Int? = nil,
        emitsTransaction: Bool = false,
        initialCredentialStatus: Int = 202,
        initialTransactionID: String? = "transaction-1",
        pendingTransactionID: String? = nil,
        pendingInterval: Int? = nil,
        deferredStatus: Int = 202,
        legacyPendingError: Bool = false,
        completedCredentialStatus: Int = 200,
        twoDeferredConfigurations: Bool = false,
        secondDeferredFails: Bool = false,
        advertisesNonceEndpoint: Bool = false,
        tokenResponse: String = #"{"access_token":"access","token_type":"Bearer","c_nonce":"nonce-1"}"#,
        credentialIssuerMetadata: String = "https://issuer.example"
    ) {
        self.presentationFormat = presentationFormat
        self.credentialFormat = credentialFormat
        self.credentialResponse = credentialResponse
        self.iGrantCompactPresentation = iGrantCompactPresentation
        self.omitAuthorizationResponseState = omitAuthorizationResponseState
        self.authorizationResponseStateOverride = authorizationResponseStateOverride
        self.deferredInterval = deferredInterval
        self.emitsTransaction = emitsTransaction || deferredInterval != nil
        self.initialCredentialStatus = initialCredentialStatus
        self.initialTransactionID = initialTransactionID
        self.pendingTransactionID = pendingTransactionID
        self.pendingInterval = pendingInterval
        self.deferredStatus = deferredStatus
        self.legacyPendingError = legacyPendingError
        self.completedCredentialStatus = completedCredentialStatus
        self.twoDeferredConfigurations = twoDeferredConfigurations
        self.secondDeferredFails = secondDeferredFails
        self.advertisesNonceEndpoint = advertisesNonceEndpoint
        self.tokenResponse = tokenResponse
        self.credentialIssuerMetadata = credentialIssuerMetadata
    }
    func send(url: URL, method: String, headers: [String: String], body: Data?) async throws -> OpenID4VCHTTPResponse {
        requests.append(Request(url: url, method: method, headers: headers, body: body))
        let response: String
        var statusCode = 200
        switch url.path {
        case "/offer":
            let configurationIDs = twoDeferredConfigurations
                ? #"["example-vcdm2-jwt-vc","second-vcdm2-jwt-vc"]"#
                : #"["example-vcdm2-jwt-vc"]"#
            response = #"{"credential_issuer":"https://issuer.example","credential_configuration_ids":\#(configurationIDs),"grants":{"urn:ietf:params:oauth:grant-type:pre-authorized_code":{"pre-authorized_code":"pre-code","tx_code":{"input_mode":"numeric","length":6}}}}"#
        case "/.well-known/openid-credential-issuer":
            let secondConfiguration = twoDeferredConfigurations
                ? #", "second-vcdm2-jwt-vc":{"format":"application/vc+jwt","display":[{"name":"Second Credential"}]}"#
                : ""
            let nonceEndpoint = advertisesNonceEndpoint
                ? #""nonce_endpoint":"https://issuer.example/nonce","#
                : ""
            response = """
            {"credential_issuer":"\(credentialIssuerMetadata)","credential_endpoint":"https://issuer.example/credential",\(nonceEndpoint)"deferred_credential_endpoint":"https://issuer.example/deferred","notification_endpoint":"https://issuer.example/notification","authorization_servers":["https://issuer.example"],"credential_configurations_supported":{"example-vcdm2-jwt-vc":{"format":"\(credentialFormat)","display":[{"name":"Legal Person ID","locale":"en","description":"Legal person credential","background_color":"#003366","text_color":"#ffffff","logo":{"uri":"https://assets.example/logo.png","alt_text":"Issuer mark"},"background_image":{"uri":"https://assets.example/background.png"}}]}\(secondConfiguration)}}
            """
        case "/.well-known/oauth-authorization-server":
            response = #"{"authorization_challenge_endpoint":"https://issuer.example/authorize-challenge","token_endpoint":"https://issuer.example/token"}"#
        case "/token":
            response = tokenResponse
        case "/nonce":
            response = #"{"c_nonce":"nonce-from-endpoint"}"#
        case "/authorize-challenge", "/authorize":
            if String(decoding: body ?? Data(), as: UTF8.self).contains("issuer_state") ||
                (url.query?.contains("issuer_state") == true) {
                let encodedBody = String(decoding: body ?? Data(), as: UTF8.self)
                let encoded = encodedBody.isEmpty ? (url.query ?? "") : encodedBody
                authorizationState = URLComponents(string: "?\(encoded)")?.queryItems?
                    .first(where: { $0.name == "state" })?.value
                if url.path == "/authorize" {
                    if iGrantCompactPresentation {
                        return OpenID4VCHTTPResponse(
                            statusCode: 200,
                            body: Data(#"{"status":"require_interaction","type":"openid4vp_presentation","openid4vp_request":{"request":"header.eyJjbGllbnRfaWQiOiJyZWRpcmVjdF91cmk6aHR0cHM6Ly9pc3N1ZXIuZXhhbXBsZS9zZXJ2aWNlL3ZlcnNpb24tMDEiLCJyZXNwb25zZV90eXBlIjoidnBfdG9rZW4iLCJyZXNwb25zZV9tb2RlIjoiaWFyLXBvc3QiLCJyZXNwb25zZV91cmkiOiJodHRwczovL2lzc3Vlci5leGFtcGxlL3NlcnZpY2UvaWFyIiwibm9uY2UiOiJub25jZSIsInN0YXRlIjoic3RhdGUiLCJkY3FsX3F1ZXJ5Ijp7ImNyZWRlbnRpYWxzIjpbeyJpZCI6IlByZXNlbnRhdGlvbiBEZWZpbml0aW9uIDEiLCJmb3JtYXQiOiJkYytzZC1qd3QifV19fQ.signature"}}"#.utf8)
                        )
                    }
                    return OpenID4VCHTTPResponse(
                        statusCode: 200,
                        body: Data(#"{"status":"require_interaction","type":"openid4vp_presentation","auth_session":"auth-session","openid4vp_request":{"request":"PLACEHOLDER"}}"#.replacingOccurrences(of: "PLACEHOLDER", with: Self.signedPresentationRequest(format: presentationFormat)).utf8)
                    )
                }
                let query = Self.credentialQuery(format: presentationFormat)
                return OpenID4VCHTTPResponse(
                    statusCode: 403,
                    body: Data("""
                    {"error":"insufficient_authorization","interaction_type_required":"urn:openid:dcp:ia:openid4vp_presentation","auth_session":"auth-session","openid4vp_request":{"response_type":"vp_token","response_mode":"ia_post","nonce":"vp-nonce","state":"vp-state","dcql_query":{"credentials":[\(query)]}}}
                    """.utf8)
                )
            }
            var authorizationResponse = [
                "authorization_code": "auth-code",
                "code": "auth-code",
            ]
            if !omitAuthorizationResponseState,
               let responseState = authorizationResponseStateOverride ?? authorizationState {
                authorizationResponse["state"] = responseState
            }
            response = String(decoding: try JSONSerialization.data(withJSONObject: authorizationResponse), as: UTF8.self)
        case "/credential":
            if emitsTransaction {
                statusCode = initialCredentialStatus
                let request = body.flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }
                let configurationID = request?["credential_configuration_id"] as? String
                let effectiveTransactionID = configurationID == "second-vcdm2-jwt-vc"
                    ? "transaction-2"
                    : initialTransactionID
                if let deferredInterval, let effectiveTransactionID {
                    response = #"{"transaction_id":"\#(effectiveTransactionID)","interval":\#(deferredInterval)}"#
                } else if let deferredInterval {
                    response = #"{"interval":\#(deferredInterval)}"#
                } else if let effectiveTransactionID {
                    response = #"{"transaction_id":"\#(effectiveTransactionID)"}"#
                } else {
                    response = #"{}"#
                }
            } else {
                response = """
                {"credentials":[{"credential":"\(credentialResponse)"}]}
                """
            }
        case "/deferred":
            let deferredRequest = body.flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: String] }
            if secondDeferredFails, deferredRequest?["transaction_id"] == "transaction-2" {
                statusCode = 500
                response = #"{"detail":"second failed"}"#
            } else if legacyPendingError {
                statusCode = 400
                response = #"{"error":"issuance_pending"}"#
            } else if let pendingTransactionID {
                statusCode = deferredStatus
                if let pendingInterval {
                    response = #"{"transaction_id":"\#(pendingTransactionID)","interval":\#(pendingInterval)}"#
                } else {
                    response = #"{"transaction_id":"\#(pendingTransactionID)"}"#
                }
            } else {
                statusCode = completedCredentialStatus
                response = """
                {"credentials":[{"credential":"\(credentialResponse)"}],"notification_id":"deferred-notification"}
                """
            }
        case "/notification":
            statusCode = 204
            response = ""
        case "/openid4vp/request":
            return OpenID4VCHTTPResponse(
                statusCode: 200,
                body: Data(Self.standalonePresentationRequest(format: presentationFormat).utf8),
                headers: ["content-type": "Application/OAuth-Authz-Req+JWT; charset=UTF-8"]
            )
        case "/openid4vp/response":
            return OpenID4VCHTTPResponse(
                statusCode: 200,
                body: Data(#"{"redirect_uri":"https://verifier.example/done"}"#.utf8),
                headers: ["Content-Type": "application/json; charset=utf-8"]
            )
        case "/logo.png", "/background.png":
            return OpenID4VCHTTPResponse(
                statusCode: 200,
                body: Self.png,
                headers: ["Content-Type": "image/png"]
            )
        default: throw OpenID4VCBackendError.invalidResponse
        }
        return OpenID4VCHTTPResponse(statusCode: statusCode, body: Data(response.utf8))
    }

    private static func signedPresentationRequest(format: String) -> String {
        func encode(_ value: String) -> String {
            Data(value.utf8).base64EncodedString().replacingOccurrences(of: "+", with: "-")
                .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
        }
        let header = encode(#"{"alg":"ES256","typ":"oauth-authz-req+jwt"}"#)
        let query = credentialQuery(format: format)
        let payload = encode("""
        {"aud":"https://self-issued.me/v2","client_id":"redirect_uri:https://issuer.example/authorize","response_type":"vp_token","response_mode":"direct_post","response_uri":"https://issuer.example/authorize","nonce":"vp-nonce","state":"auth-session","dcql_query":{"credentials":[\(query)]}}
        """)
        return "\(header).\(payload).signature"
    }

    private static func standalonePresentationRequest(format: String) -> String {
        func encode(_ value: String) -> String {
            Data(value.utf8).base64EncodedString().replacingOccurrences(of: "+", with: "-")
                .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
        }
        let header = encode(#"{"alg":"ES256","typ":"oauth-authz-req+jwt","kid":"did:key:verifier#key"}"#)
        let query = credentialQuery(format: format)
        let issuedAt = Int(Date().timeIntervalSince1970)
        let payload = encode("""
        {"aud":"https://self-issued.me/v2","client_id":"decentralized_identifier:did:key:verifier","response_type":"vp_token","response_mode":"direct_post","response_uri":"https://issuer.example/openid4vp/response","nonce":"vp-nonce","iat":\(issuedAt),"exp":\(issuedAt + 300),"state":"vp-state","dcql_query":{"credentials":[\(query)]},"client_metadata":{"vp_formats_supported":{"jwt_vc_json":{"alg_values":["ES256"]}}}}
        """)
        return "\(header).\(payload).signature"
    }

    private static func credentialQuery(format: String) -> String {
        format == "jwt_vc_json"
            ? #"{"id":"pid","format":"jwt_vc_json","meta":{"type_values":[["VerifiableCredential","PersonIdentificationData"]]},"claims":[{"path":["credentialSubject","given_name"]},{"path":["credentialSubject","family_name"]}]}"#
            : #"{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eu.europa.ec.eudi:pid:1"]},"claims":[{"path":["given_name"]},{"path":["family_name"]},{"path":["email"]}]}"#
    }
}

private actor Draft13OpenID4VCTransport: OpenID4VCHTTPTransport {
    struct Request: Sendable {
        let url: URL
        let method: String
        let headers: [String: String]
        let body: Data?
    }
    private(set) var requests: [Request] = []
    private let tokenResponse: String
    private let allowsAnonymousAuthentication: Bool
    private let supportsES256Attestation: Bool
    private let advertisesDPoP: Bool
    private let legacyWellKnownOnly: Bool
    private let rejectedCredentialIdentifier: String?
    private let plaintextCredentialResponse: Bool
    private let credentialIssuer: String

    init(
        tokenResponse: String = #"{"access_token":"access-token","token_type":"Bearer","c_nonce":"credential-nonce","authorization_details":[{"type":"openid_credential","credential_configuration_id":"pid-config","credential_identifiers":["authorized-pid"]}]}"#,
        allowsAnonymousAuthentication: Bool = true,
        supportsES256Attestation: Bool = true,
        advertisesDPoP: Bool = true,
        legacyWellKnownOnly: Bool = false,
        rejectedCredentialIdentifier: String? = nil,
        plaintextCredentialResponse: Bool = false,
        credentialIssuer: String = "https://issuer.example/service/draft-13"
    ) {
        self.tokenResponse = tokenResponse
        self.allowsAnonymousAuthentication = allowsAnonymousAuthentication
        self.supportsES256Attestation = supportsES256Attestation
        self.advertisesDPoP = advertisesDPoP
        self.legacyWellKnownOnly = legacyWellKnownOnly
        self.rejectedCredentialIdentifier = rejectedCredentialIdentifier
        self.plaintextCredentialResponse = plaintextCredentialResponse
        self.credentialIssuer = credentialIssuer
    }

    func send(url: URL, method: String, headers: [String: String], body: Data?) async throws -> OpenID4VCHTTPResponse {
        requests.append(Request(url: url, method: method, headers: headers, body: body))
        let response: String
        let statusCode: Int
        if url.path.contains("/.well-known/openid-credential-issuer") {
            let isLegacy = url.path.hasSuffix("/.well-known/openid-credential-issuer")
            if legacyWellKnownOnly != isLegacy {
                response = "Demo issuer landing page"
                statusCode = 200
            } else {
                response = #"{"credential_issuer":"\#(credentialIssuer)","credential_endpoint":"https://issuer.example/credential","authorization_servers":["https://issuer.example/service/draft-13"],"credential_configurations_supported":{"pid-config":{"format":"dc+sd-jwt","vct":"urn:example:pid"},"pid-alias":{"format":"dc+sd-jwt","vct":"urn:example:pid"},"pid-alias-two":{"format":"dc+sd-jwt","vct":"urn:example:pid"},"other-config":{"format":"dc+sd-jwt","vct":"urn:example:legal-person"}},"notification_endpoint":"https://issuer.example/notification"}"#
                statusCode = 200
            }
        } else if url.path.contains("/.well-known/oauth-authorization-server") {
            let isLegacy = url.path.hasSuffix("/.well-known/oauth-authorization-server")
            if legacyWellKnownOnly != isLegacy {
                response = "Demo issuer landing page"
                statusCode = 200
            } else {
                let methods = allowsAnonymousAuthentication
                    ? #"["attest_jwt_client_auth","none"]"#
                    : #"["attest_jwt_client_auth"]"#
                let algorithms = supportsES256Attestation ? #"["ES256"]"# : #"["ES384"]"#
                let dpopMetadata = advertisesDPoP
                    ? #", "dpop_signing_alg_values_supported":["ES256"]"#
                    : ""
                response = """
                {"token_endpoint":"https://issuer.example/token","token_endpoint_auth_methods_supported":\(methods),"client_attestation_signing_alg_values_supported":\(algorithms)\(dpopMetadata)}
                """
                statusCode = 200
            }
        } else if url.path.hasSuffix("/token") {
            response = tokenResponse
            statusCode = 200
        } else if url.path.hasSuffix("/credential") {
            let bodyObject = body.flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }
            if bodyObject?["credential_identifier"] as? String == rejectedCredentialIdentifier {
                response =
                #"{"error":"invalid_credential_request","error_description":"identifier rejected"}"#
                statusCode = 400
            } else {
                response = plaintextCredentialResponse
                    ? #"{"credentials":[{"credential":"eyJhbGciOiJFUzI1NiJ9.eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiXSwiaXNzIjoiZGlkOmtleTppc3N1ZXIiLCJ2Y3QiOiJ1cm46ZXhhbXBsZTpwaWQifQ.signature~"}],"notification_id":"notification-id"}"#
                    : "header.encrypted-key.iv.ciphertext.tag"
                statusCode = 200
            }
        } else if url.path.hasSuffix("/notification") {
            response = ""
            statusCode = 204
        } else {
            throw OpenID4VCBackendError.invalidResponse
        }
        return OpenID4VCHTTPResponse(statusCode: statusCode, body: Data(response.utf8))
    }
}

private actor RecordingOID4VCIClientSecurity: OID4VCIClientSecurity {
    private(set) var dpopAccessTokens: [String?] = []
    private(set) var decryptionCalls = 0
    private let attestationHeaders: [String: String]

    init(attestationHeaders: [String: String] = ["test-attestation": "available"]) {
        self.attestationHeaders = attestationHeaders
    }

    func state(for profile: OID4VCITransportProfile) async throws -> OID4VCIClientSecurityState {
        OID4VCIClientSecurityState(
            dpopKeyID: KeyID(),
            clientAttestationKeyID: nil,
            responseEncryptionKeyID: KeyID()
        )
    }

    func dpopHeader(
        state: OID4VCIClientSecurityState,
        method: String,
        targetURI: URL,
        accessToken: String?
    ) async throws -> String {
        dpopAccessTokens.append(accessToken)
        return accessToken == nil ? "dpop-token" : "dpop-access-token"
    }

    func clientAttestationHeaders(
        state: OID4VCIClientSecurityState,
        audience: URL
    ) async throws -> [String: String] {
        attestationHeaders
    }

    func responseEncryption(
        state: OID4VCIClientSecurityState
    ) async throws -> OID4VCIResponseEncryptionParameters {
        OID4VCIResponseEncryptionParameters(
            publicJWK: #"{"alg":"ECDH-ES","crv":"P-256","enc":"A128CBC-HS256","kty":"EC","use":"enc","x":"x","y":"y"}"#
        )
    }

    func decryptCredentialResponse(
        state: OID4VCIClientSecurityState,
        compactJWE: Data
    ) async throws -> Data {
        decryptionCalls += 1
        return Data(#"{"credentials":[{"credential":"eyJhbGciOiJFUzI1NiJ9.eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiXSwiaXNzIjoiZGlkOmtleTppc3N1ZXIiLCJ2Y3QiOiJ1cm46ZXhhbXBsZTpwaWQifQ.signature~"}],"notification_id":"notification-id"}"#.utf8)
    }
}

private struct UntrustedIssuerEvaluator: CredentialIssuerServiceTrustEvaluating {
    func evaluate(issuer: String, at date: Date) async -> TrustVerdict {
        .untrusted(reasons: [.issuerNotAccredited], evidence: [])
    }
}

private struct TrustedIssuerEvaluator: CredentialIssuerServiceTrustEvaluating {
    func evaluate(issuer: String, at date: Date) async -> TrustVerdict { .trusted(evidence: []) }
}

private struct UntrustedSignerEvaluator: CredentialSignerTrustEvaluating {
    func evaluate(issuer: String, at date: Date) async -> TrustVerdict {
        .untrusted(reasons: [.issuerNotAccredited], evidence: [])
    }
}

private actor FixtureCredentialStore: EbsiCredentialStore {
    private var values: [StoredEbsiCredential] = []
    init(values: [StoredEbsiCredential] = []) { self.values = values }
    func credentials() async throws -> [StoredEbsiCredential] { values }
    func save(_ credential: StoredEbsiCredential) async throws { values.append(credential) }
    func delete(id: UUID) async throws { values.removeAll { $0.id == id } }
}

private actor FixtureCredentialValidator: W3CCredentialValidating {
    private(set) var calls = 0
    private let signedIssuer: String?
    init(signedIssuer: String? = nil) { self.signedIssuer = signedIssuer }
    func validate(
        rawCredential: Data,
        profile: EbsiCredentialProfile,
        expectedIssuer: String?,
        expectedHolderDID: String,
        at date: Date
    ) async throws -> String {
        calls += 1
        #expect(expectedIssuer?.isEmpty != true)
        #expect(!expectedHolderDID.isEmpty)
        return signedIssuer ?? expectedIssuer ?? "https://issuer.example"
    }
}

private struct FixturePresentationRequestValidator: OpenID4VPRequestObjectValidating {
    func validate(compactJWT: String, at date: Date) async throws -> VerifiedOpenID4VPRequestObject {
        let parts = compactJWT.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 3 else { throw OpenID4VCBackendError.invalidResponse }
        var base64 = String(parts[1]).replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        base64 += String(repeating: "=", count: (4 - base64.count % 4) % 4)
        guard let data = Data(base64Encoded: base64) else { throw OpenID4VCBackendError.invalidResponse }
        let payload = try JSONDecoder().decode([String: AnySendableJSON].self, from: data)
        guard let clientID = payload["client_id"]?.string,
              let responseMode = payload["response_mode"]?.string,
              let nonce = payload["nonce"]?.string,
              let dcqlQuery = payload["dcql_query"]?.object else {
            throw OpenID4VCBackendError.invalidResponse
        }
        let signingDID: String? = if clientID.hasPrefix("decentralized_identifier:") {
            String(clientID.dropFirst("decentralized_identifier:".count))
        } else if clientID.hasPrefix("redirect_uri:") {
            nil
        } else {
            "did:key:interactive-verifier"
        }
        let issuedAt: Date? = if case let .number(value)? = payload["iat"] {
            Date(timeIntervalSince1970: value)
        } else { nil }
        let expiresAt: Date? = if case let .number(value)? = payload["exp"] {
            Date(timeIntervalSince1970: value)
        } else { nil }
        var vpFormatsSupported: [String: Set<String>]?
        if let metadata = payload["client_metadata"]?.object {
            vpFormatsSupported = [:]
            if let advertisedFormats = metadata["vp_formats_supported"]?.object {
                for (format, parameters) in advertisedFormats {
                    let names = format == "dc+sd-jwt"
                        ? ["kb-jwt_alg_values", "kb_jwt_alg_values", "kb-jwt_alg_values_supported"]
                        : ["alg_values", "alg_values_supported"]
                    let parameterObject = parameters.object ?? [:]
                    var algorithms = Set<String>()
                    for name in names {
                        if case let .array(values)? = parameterObject[name] {
                            algorithms.formUnion(values.compactMap { $0.string })
                        }
                    }
                    vpFormatsSupported?[format] = algorithms
                }
            }
        }
        return VerifiedOpenID4VPRequestObject(
            clientID: clientID,
            issuer: payload["iss"]?.string,
            audience: payload["aud"]?.string,
            responseType: payload["response_type"]?.string,
            responseMode: responseMode,
            responseURI: payload["response_uri"]?.string,
            nonce: nonce,
            state: payload["state"]?.string,
            dcqlQuery: dcqlQuery,
            vpFormatsSupported: vpFormatsSupported,
            signingDID: signingDID,
            issuedAt: issuedAt,
            expiresAt: expiresAt
        )
    }
}

private actor FixtureKeyProvider: KeyProvider {
    private let key = P256.Signing.PrivateKey()
    private let id = KeyID()
    func createKey(
        purpose: KeyPurpose,
        algorithm: SigningAlgorithm,
        requiresUserPresence: Bool,
        protection: KeyProtectionPolicy
    ) async throws -> KeyRecord {
        KeyRecord(
            id: id,
            purpose: purpose,
            algorithm: algorithm,
            assurance: .keychainSoftware,
            applicationTag: "fixture",
            createdAt: Date()
        )
    }
    func sign(_ request: SigningRequest) async throws -> Data {
        try key.signature(for: request.payload).rawRepresentation
    }
    func publicKey(id: KeyID) async throws -> PublicKeyMaterial {
        PublicKeyMaterial(algorithm: .es256, x963Representation: key.publicKey.x963Representation)
    }
    func deleteKey(id: KeyID) async throws {}
}
