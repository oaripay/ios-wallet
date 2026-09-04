@testable import EudiWalletKitAdapter
import EudiWalletKit
import Foundation
import MdocSecurity18013
import Security
import Testing
import WalletDomain

struct EudiWalletKitAdapterTests {
    @Test("Structured transaction values preserve nested consent data")
    func structuredTransactionValues() {
        let value = EudiTransactionDataValue.object([
            "amount": .object([
                "currency": .string("EUR"),
                "value": .number("125.50")
            ]),
            "recipients": .array([
                .object(["name": .string("Example Merchant")]),
                .null
            ]),
            "recurring": .bool(false)
        ])
        let field = EudiTransactionDataField(id: "transaction-0.payment", key: "Payment", value: value)

        #expect(field.id == "transaction-0.payment")
        #expect(field.value == value)
    }

    @Test("Presentation credential retains wallet artwork and issuer metadata")
    func presentationCredentialMetadata() {
        let display = CredentialDisplayMetadata(
            locale: "en",
            description: "Identity credential",
            backgroundColor: "#123456",
            textColor: "#FFFFFF"
        )
        let credential = EudiPresentationCredential(
            id: "document-1",
            displayName: "Digital ID",
            issuerIdentifier: "https://issuer.example",
            configurationID: "pid",
            format: .sdJWTVC,
            profileID: "eudi",
            representation: "sdjwt",
            receivedAt: .distantPast,
            display: display
        )

        #expect(credential.issuerIdentifier == "https://issuer.example")
        #expect(credential.configurationID == "pid")
        #expect(credential.display == display)
    }

    @Test("Native document summary carries normalized validity")
    func documentSummaryValidity() {
        let validFrom = Date(timeIntervalSince1970: 1_700_000_000)
        let validUntil = Date(timeIntervalSince1970: 1_800_000_000)
        let summary = EudiWalletDocumentSummary(
            id: "document-1", documentType: "eu.europa.ec.eudi.pid.1",
            displayName: "PID", format: "cbor", status: "issued",
            validFrom: validFrom, validUntil: validUntil
        )

        #expect(summary.validFrom == validFrom)
        #expect(summary.validUntil == validUntil)
    }

    @Test("HAIP issuance is normalized only at the Wallet Kit boundary")
    func haipIssuanceNormalization() throws {
        let source = "haip-vci://authorize?credential_offer_uri=https%3A%2F%2Fissuer.example%2Foffer%3Fpin%3Da%252Bb&state=x%2By"
        let normalized = try EudiWalletKitAdapter.validatedOfferURI(
            source,
            allowedOrigins: ["https://issuer.example"]
        )
        let before = try #require(URLComponents(string: source))
        let after = try #require(URLComponents(string: normalized))
        #expect(after.scheme == "openid-credential-offer")
        #expect(after.host == before.host)
        #expect(after.path == before.path)
        #expect(after.queryItems == before.queryItems)
        #expect(normalized.dropFirst("openid-credential-offer".count) == source.dropFirst("haip-vci".count))
        #expect(throws: EudiWalletKitAdapterError.unapprovedIssuer) {
            try EudiWalletKitAdapter.validatedOfferURI(
                "haip-vci://authorize?credential_offer_uri=https%3A%2F%2Fevil.example%2Foffer",
                allowedOrigins: ["https://issuer.example"]
            )
        }
    }

    @Test("EUDI presentation schemes normalize to OpenID4VP without changing query values")
    func eudiPresentationNormalization() throws {
        for scheme in ["haip-vp", "eudi-openid4vp", "mdoc-openid4vp"] {
            let source = "\(scheme)://authorize?request_uri=https%3A%2F%2Fverifier.example%2Frequest%3Fx%3Da%252Bb&state=a%2Bb"
            let normalized = try EudiWalletKitAdapter.validatedPresentationURI(
                source,
                allowedOrigins: ["https://verifier.example"]
            )
            let before = try #require(URLComponents(string: source))
            let after = try #require(URLComponents(string: normalized))
            #expect(after.scheme == "openid4vp")
            #expect(after.host == before.host)
            #expect(after.path == before.path)
            #expect(after.queryItems == before.queryItems)
            #expect(normalized.dropFirst("openid4vp".count) == source.dropFirst(scheme.count))
        }
        #expect(throws: EudiWalletKitAdapterError.unapprovedVerifier) {
            try EudiWalletKitAdapter.validatedPresentationURI(
                "haip-vp://authorize?request_uri=https%3A%2F%2Fevil.example%2Frequest",
                allowedOrigins: ["https://verifier.example"]
            )
        }
    }

    @Test("Generic Wallet Kit URIs are not rewritten")
    func genericURIsRemainUnchanged() throws {
        let offer = "openid-credential-offer://authorize?credential_offer_uri=https%3A%2F%2Fissuer.example%2Foffer%3Fx%3Da%252Bb&state=a%2Bb"
        #expect(try EudiWalletKitAdapter.validatedOfferURI(
            offer, allowedOrigins: ["https://issuer.example"]
        ) == offer)
        let presentation = "openid4vp://authorize?request_uri=https%3A%2F%2Fverifier.example%2Frequest%3Fx%3Da%252Bb&state=a%2Bb"
        #expect(try EudiWalletKitAdapter.validatedPresentationURI(
            presentation, allowedOrigins: ["https://verifier.example"]
        ) == presentation)
    }

    @Test("Wallet Kit inline display artwork becomes offline credential metadata")
    func walletKitDisplayArtwork() throws {
        let png = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="
        let metadata = Data("""
        {
          "credentialIssuerIdentifier":"https://issuer.example",
          "configurationIdentifier":"pid",
          "docType":"pid",
          "display":[{
            "name":"PID",
            "localeIdentifier":"en",
            "description":"Identity credential",
            "backgroundColor":"#003366",
            "textColor":"#ffffff",
            "logo":{"urlString":"data:image/png;base64,\(png)","alternativeText":"Issuer mark"},
            "backgroundImageURL":"data:image/png;base64,\(png)"
          }]
        }
        """.utf8)

        let display = try #require(EudiWalletKitAdapter.credentialDisplayMetadata(
            fromWalletKitMetadata: metadata
        ))
        #expect(display.backgroundColor == "#003366")
        #expect(display.textColor == "#ffffff")
        #expect(display.logo?.alternativeText == "Issuer mark")
        #expect(display.logo?.data == display.backgroundImage?.data)
        #expect(display.logo?.data.isEmpty == false)
    }

    @Test("Selected Wallet Kit revision is immutable and explicit")
    func selectedRevision() {
        #expect(EudiWalletKitBaseline.selectedVersion == "0.39.1")
        #expect(EudiWalletKitBaseline.selectedCommit == "79005ab4bf0399238c1c9ebff9ee7d8a42c521f9")
    }

    @Test("Wallet configuration disables SDK file logging and requires authentication")
    func safeConfiguration() throws {
        let baseline = try testBaseline(serviceName: "io.oari.wallet.documents")
        let configuration = baseline.walletConfiguration()

        #expect(configuration.serviceName == "io.oari.wallet.documents")
        #expect(configuration.userAuthenticationRequired)
        #expect(configuration.logFileName == nil)
    }

    @Test("Invalid Keychain service names fail before Wallet Kit initialization")
    func invalidServiceName() {
        #expect(throws: EudiWalletKitAdapterError.invalidServiceName) {
            try testBaseline(serviceName: "io.oari:wallet")
        }
        #expect(throws: EudiWalletKitAdapterError.invalidServiceName) {
            try testBaseline(serviceName: "  ")
        }
    }

    @Test("Wallet construction requires explicit trust anchors")
    func trustAnchorsRequired() {
        #expect(throws: EudiWalletKitAdapterError.missingTrustAnchors) {
            try EudiTrustAnchorSource(
                profileID: "test",
                anchors: [],
                approvedSHA256Digests: []
            )
        }
    }

    @Test("Wallet Kit initializes behind the adapter with explicit trust input")
    func walletInitialization() throws {
        let baseline = try testBaseline(serviceName: "io.oari.wallet.adapter-tests")
        _ = try baseline.makeWallet(trustSource: try approvedSystemTrustSource())
    }

    @Test("Operational configuration requires a private redirect scheme and client identifier")
    func operationalConfigurationValidation() throws {
        #expect(throws: EudiWalletKitAdapterError.invalidOperationalConfiguration) {
            try EudiOperationalConfiguration(
                clientID: " ",
                authorizationRedirectURI: URL(string: "oari-wallet://authorize")!,
                attestationProvider: FixtureAttestationProvider(),
                auditRepository: MemoryAuditRepository(),
                auditPolicy: .development,
                auditPolicyVersion: AuditPolicyVersion(rawValue: 1),
                metadataRepository: MemoryMetadataRepository(),
                recoveryStore: MemoryRecoveryStore(),
                statusProvider: FixtureStatusProvider(),
                allowedIssuerOrigins: ["https://issuer.example"],
                allowedVerifierOrigins: ["https://verifier.example"],
                allowedApplicationRedirectOrigins: ["https://wallet.example"]
            )
        }
        #expect(throws: EudiWalletKitAdapterError.invalidOperationalConfiguration) {
            try EudiOperationalConfiguration(
                clientID: "ftp",
                authorizationRedirectURI: URL(string: "ftp://authorize")!,
                attestationProvider: FixtureAttestationProvider(),
                auditRepository: MemoryAuditRepository(),
                auditPolicy: .development,
                auditPolicyVersion: AuditPolicyVersion(rawValue: 1),
                metadataRepository: MemoryMetadataRepository(),
                recoveryStore: MemoryRecoveryStore(),
                statusProvider: FixtureStatusProvider(),
                allowedIssuerOrigins: ["https://issuer.example"],
                allowedVerifierOrigins: ["https://verifier.example"],
                allowedApplicationRedirectOrigins: ["https://wallet.example"]
            )
        }
        #expect(throws: EudiWalletKitAdapterError.invalidOperationalConfiguration) {
            try EudiOperationalConfiguration(
                clientID: "oari-wallet",
                authorizationRedirectURI: URL(string: "file://authorize")!,
                attestationProvider: FixtureAttestationProvider(),
                auditRepository: MemoryAuditRepository(),
                auditPolicy: .development,
                auditPolicyVersion: AuditPolicyVersion(rawValue: 1),
                metadataRepository: MemoryMetadataRepository(),
                recoveryStore: MemoryRecoveryStore(),
                statusProvider: FixtureStatusProvider(),
                allowedIssuerOrigins: ["https://issuer.example"],
                allowedVerifierOrigins: ["https://verifier.example"],
                allowedApplicationRedirectOrigins: ["https://wallet.example"]
            )
        }
        #expect(throws: EudiWalletKitAdapterError.invalidOperationalConfiguration) {
            try EudiOperationalConfiguration(
                clientID: "oari-wallet",
                authorizationRedirectURI: URL(string: "https://wallet.example/callback")!,
                attestationProvider: FixtureAttestationProvider(),
                auditRepository: MemoryAuditRepository(),
                auditPolicy: .development,
                auditPolicyVersion: AuditPolicyVersion(rawValue: 1),
                metadataRepository: MemoryMetadataRepository(),
                recoveryStore: MemoryRecoveryStore(),
                statusProvider: FixtureStatusProvider(),
                allowedIssuerOrigins: ["https://issuer.example"],
                allowedVerifierOrigins: ["https://verifier.example"],
                allowedApplicationRedirectOrigins: ["https://wallet.example"]
            )
        }
        let configuration = try EudiOperationalConfiguration(
            clientID: "oari-wallet",
            authorizationRedirectURI: URL(string: "https://wallet.example/oauth/callback")!,
            attestationProvider: FixtureAttestationProvider(),
            auditRepository: MemoryAuditRepository(),
            auditPolicy: .development,
            auditPolicyVersion: AuditPolicyVersion(rawValue: 1),
            metadataRepository: MemoryMetadataRepository(),
            recoveryStore: MemoryRecoveryStore(),
            statusProvider: FixtureStatusProvider(),
            allowedIssuerOrigins: ["https://issuer.example"],
            allowedVerifierOrigins: ["https://verifier.example"],
            allowedApplicationRedirectOrigins: ["https://wallet.example"],
            allowUnregisteredDevelopmentCounterparties: false
        )
        #expect(configuration.clientID == "oari-wallet")
        #expect(try configuration.validateIssuanceOfferURI(
            "https://issuer.example/offer"
        ) == "https://issuer.example/offer")
        #expect(throws: EudiWalletKitAdapterError.unapprovedIssuer) {
            try configuration.validateIssuanceOfferURI("https://evil.example/offer")
        }
        #expect(throws: EudiWalletKitAdapterError.unapprovedIssuer) {
            try configuration.validateIssuanceOfferURI("https://issuer.example:8443/offer")
        }
        #expect(try configuration.validateIssuanceOfferURI(
            "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fissuer.example%2Foffer"
        ).hasPrefix("openid-credential-offer:"))
        #expect(try configuration.validatePresentationRequestURI(
            "openid4vp://authorize?request_uri=https%3A%2F%2Fverifier.example%2Frequest"
        ).hasPrefix("openid4vp:"))
        #expect(throws: EudiWalletKitAdapterError.unapprovedVerifier) {
            try configuration.validatePresentationRequestURI(
                "openid4vp://authorize?request_uri=https%3A%2F%2Fevil.example%2Frequest"
            )
        }
        #expect(throws: EudiWalletKitAdapterError.unapprovedVerifier) {
            try configuration.validatePresentationRequestURI(
                "openid4vp://authorize?request=unverified-inline-jar"
            )
        }
        func base64URL(_ data: Data) -> String {
            data.base64EncodedString().replacingOccurrences(of: "+", with: "-")
                .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
        }
        let header = base64URL(Data(#"{"alg":"ES256","typ":"oauth-authz-req+jwt"}"#.utf8))
        let payload = base64URL(Data(#"{"client_id":"redirect_uri:https://verifier.example/callback","response_uri":"https://verifier.example/response","response_type":"vp_token","response_mode":"direct_post","nonce":"nonce"}"#.utf8))
        let signedRequest = "\(header).\(payload).signature"
        var signedComponents = URLComponents(string: "openid4vp://authorize")!
        signedComponents.queryItems = [URLQueryItem(name: "request", value: signedRequest)]
        #expect(try configuration.validatePresentationRequestURI(
            signedComponents.url!.absoluteString
        ).hasPrefix("openid4vp:"))
        let evilPayload = base64URL(Data(#"{"client_id":"redirect_uri:https://evil.example/callback","response_uri":"https://evil.example/response","response_type":"vp_token","response_mode":"direct_post","nonce":"nonce"}"#.utf8))
        signedComponents.queryItems = [URLQueryItem(name: "request", value: "\(header).\(evilPayload).signature")]
        #expect(throws: EudiWalletKitAdapterError.unapprovedVerifier) {
            try configuration.validatePresentationRequestURI(signedComponents.url!.absoluteString)
        }
        #expect(try configuration.validatePendingIssuancePresentationURI(
            "https://issuer.example/presentation-authorization"
        ) == "https://issuer.example/presentation-authorization")
        #expect(try configuration.validatePendingIssuancePresentationURI(
            "openid4vp://authorize?request_uri=https%3A%2F%2Fverifier.example%2Frequest"
        ).hasPrefix("openid4vp:"))
        #expect(throws: EudiWalletKitAdapterError.unapprovedIssuer) {
            try configuration.validatePendingIssuancePresentationURI(
                "https://evil.example/presentation-authorization"
            )
        }
    }

    @Test("Wallet Kit registers strict VCI operational configuration behind adapter")
    func operationalWalletInitialization() throws {
        let baseline = try testBaseline(serviceName: "io.oari.wallet.operational-configuration-tests")
        let configuration = try EudiOperationalConfiguration(
            clientID: "oari-wallet",
            authorizationRedirectURI: URL(string: "https://wallet.example/oauth/callback")!,
            attestationProvider: FixtureAttestationProvider(),
            auditRepository: MemoryAuditRepository(),
            auditPolicy: .development,
            auditPolicyVersion: AuditPolicyVersion(rawValue: 1),
            metadataRepository: MemoryMetadataRepository(),
            recoveryStore: MemoryRecoveryStore(),
            statusProvider: FixtureStatusProvider(),
            allowedIssuerOrigins: ["https://issuer.example"],
            allowedVerifierOrigins: ["https://verifier.example"],
            allowedApplicationRedirectOrigins: ["https://wallet.example"]
        )
        let trustSource = try approvedSystemTrustSource()
        let adapter = try baseline.makeWallet(
            trustSource: trustSource,
            operationalConfiguration: configuration
        )
        #expect(adapter.trustProfileID == trustSource.profileID)
    }

    @Test("Transaction code rules are exact and ASCII numeric")
    func transactionCodeValidation() {
        let numeric = EudiTransactionCodeRequirement(
            inputMode: "numeric",
            length: 6,
            displayDescription: nil
        )
        #expect(numeric.accepts("123456"))
        #expect(!numeric.accepts("12345"))
        #expect(!numeric.accepts("１２３４５６"))
        let text = EudiTransactionCodeRequirement(
            inputMode: "text",
            length: nil,
            displayDescription: nil
        )
        #expect(text.accepts("A-123"))
        #expect(!text.accepts("A 123"))
    }

    @Test("Pending issuance handles are stable per Wallet Kit document and removable")
    func pendingIssuanceState() async {
        let state = EudiOperationalState()
        let credentialID = CredentialID()
        let first = await state.upsertPending(
            documentID: "pending-document",
            issuerName: "https://issuer.example",
            profileID: "eudi-final-1",
            metadataCredentialID: credentialID,
            presentationRequestURI: "https://issuer.example/presentation"
        )
        let reconstructed = await state.upsertPending(
            documentID: "pending-document",
            issuerName: "https://issuer.example",
            profileID: "eudi-final-1",
            metadataCredentialID: credentialID,
            presentationRequestURI: "https://issuer.example/presentation"
        )
        #expect(first == reconstructed)
        #expect(await state.pending(id: first)?.documentID == "pending-document")
        await state.replacePending(
            id: first,
            documentID: "replacement-pending-document",
            issuerName: "https://issuer.example",
            profileID: "eudi-final-1",
            metadataCredentialID: credentialID,
            presentationRequestURI: "https://issuer.example/replacement-presentation"
        )
        #expect(await state.pending(id: first)?.documentID == "replacement-pending-document")
        await state.removePending(id: first)
        #expect(await state.pending(id: first) == nil)
    }

    @Test("Pending issuance policy never loses a repeated pending document")
    func pendingIssuancePolicy() throws {
        #expect(try EudiPendingIssuancePolicy.nextPresentationURI(
            status: "pending",
            candidate: "https://issuer.example/presentation"
        ) == "https://issuer.example/presentation")
        #expect(try EudiPendingIssuancePolicy.nextPresentationURI(
            status: "issued",
            candidate: nil
        ) == nil)
        #expect(throws: EudiWalletKitAdapterError.invalidPendingIssuance) {
            _ = try EudiPendingIssuancePolicy.nextPresentationURI(status: "pending", candidate: nil)
        }
        #expect(throws: EudiWalletKitAdapterError.unexpectedPendingIssuanceStatus) {
            _ = try EudiPendingIssuancePolicy.nextPresentationURI(status: "deferred", candidate: nil)
        }
        #expect(EudiPendingIssuancePolicy.recoveryReferences(
            originalDocumentID: "original",
            resumedDocumentID: "replacement",
            resumedStatus: "issued"
        ) == [
            WalletDocumentRecoveryReference(id: "original", status: "pending"),
            WalletDocumentRecoveryReference(id: "replacement", status: "issued"),
        ])
        #expect(EudiPendingIssuancePolicy.recoveryReferences(
            originalDocumentID: "same-document",
            resumedDocumentID: "same-document",
            resumedStatus: "pending"
        ) == [WalletDocumentRecoveryReference(id: "same-document", status: "pending")])
        #expect(EudiPendingIssuancePolicy.mergeObservedRecoveryReferences(
            affected: [WalletDocumentRecoveryReference(id: "same-document", status: "pending")],
            newlyCreated: [],
            changedOriginal: WalletDocumentRecoveryReference(id: "same-document", status: "issued")
        ) == [WalletDocumentRecoveryReference(id: "same-document", status: "issued")])
        #expect(EudiPendingIssuancePolicy.mergeObservedRecoveryReferences(
            affected: [WalletDocumentRecoveryReference(id: "original", status: "pending")],
            newlyCreated: [WalletDocumentRecoveryReference(id: "replacement", status: "issued")],
            changedOriginal: nil
        ) == [
            WalletDocumentRecoveryReference(id: "original", status: "pending"),
            WalletDocumentRecoveryReference(id: "replacement", status: "issued"),
        ])
    }

    @Test("Malformed trust anchors fail before Wallet Kit initialization")
    func malformedTrustAnchor() throws {
        let baseline = try testBaseline(serviceName: "io.oari.wallet.invalid-anchor-tests")
        let malformed = Data([0x30, 0x00])
        let source = try EudiTrustAnchorSource(
            profileID: "test",
            anchors: [malformed],
            approvedSHA256Digests: [EudiTrustAnchorSource.sha256Digest(of: malformed)]
        )
        #expect(throws: EudiWalletKitAdapterError.invalidTrustAnchor) {
            try baseline.makeWallet(trustSource: source)
        }
    }

    @Test("Valid leaf and unapproved CA certificates cannot become trust anchors")
    func trustAnchorAuthorization() throws {
        let baseline = try testBaseline(serviceName: "io.oari.wallet.anchor-policy-tests")
        let leaf = try #require(Data(
            base64Encoded: Self.nonCABase64,
            options: .ignoreUnknownCharacters
        ))
        let leafSource = try EudiTrustAnchorSource(
            profileID: "test",
            anchors: [leaf],
            approvedSHA256Digests: [EudiTrustAnchorSource.sha256Digest(of: leaf)]
        )
        #expect(throws: EudiWalletKitAdapterError.invalidTrustAnchor) {
            try baseline.makeWallet(trustSource: leafSource)
        }

        let root = try systemRootCertificate()
        let unapproved = try EudiTrustAnchorSource(
            profileID: "test",
            anchors: [root],
            approvedSHA256Digests: [String(repeating: "0", count: 64)]
        )
        #expect(throws: EudiWalletKitAdapterError.unapprovedTrustAnchor) {
            try baseline.makeWallet(trustSource: unapproved)
        }
    }

    private func approvedSystemTrustSource() throws -> EudiTrustAnchorSource {
        let anchor = try systemRootCertificate()
        return try EudiTrustAnchorSource(
            profileID: "adapter-tests",
            anchors: [anchor],
            approvedSHA256Digests: [EudiTrustAnchorSource.sha256Digest(of: anchor)]
        )
    }

    private func testBaseline(serviceName: String) throws -> EudiWalletKitBaseline {
        let anchor = try systemRootCertificate()
        #if canImport(EudiEtsi1196x2)
        let trustConfiguration = TrustConfiguration(
            trustSource: .staticList(StaticListTrustSource(rootCertificates: [anchor])),
            defaultPolicy: .warning,
            requireSignedMetadata: true,
            statusTrustPolicy: .warning,
            wrprcTrustPolicy: .warning
        )
        #else
        let trustConfiguration = TrustConfiguration(
            rootIaca: [[anchor]],
            defaultPolicy: .warning,
            requireSignedMetadata: true,
            statusTrustPolicy: .warning,
            wrprcTrustPolicy: .warning
        )
        #endif
        return try EudiWalletKitBaseline(
            serviceName: serviceName,
            trustConfiguration: trustConfiguration,
            openID4VciConfigurations: [:],
            openID4VpConfiguration: OpenId4VpConfiguration(
                clientIdSchemes: [.x509SanDns, .x509Hash]
            )
        )
    }

    private func systemRootCertificate() throws -> Data {
        let repositoryRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        return try Data(contentsOf: repositoryRoot
            .appendingPathComponent("Tests/Resources/TestTrustAnchor.bin"))
    }

    private static let nonCABase64 = """
    MIIDBDCCAeygAwIBAgIUTpdNHxMBD4Gy1dDs4XgGszteYUgwDQYJKoZIhvcNAQELBQAwEzERMA8G
    A1UEAwwITm90IEEgQ0EwHhcNMjYwODA3MTMzMzM1WhcNMzYwODA0MTMzMzM1WjATMREwDwYDVQQD
    DAhOb3QgQSBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKxtDT7YJYlTRcOqLrB3
    GFT0vI3a1Pm3imIbguZCR/n8Op0oGcQGx3iacRG9qSo14JSfO4Um1YoOTjyDqPjhGo3Li7ml2ntL
    LMZqhycob0G2pp0ZJWG48VEqT/ip0UlTXSp+vZnYzXJ7PySw3GoTcfHX7DPMed5ztQTFJNxOPc+a
    L2zCFW0Bfp+cRCXdMRyKx0YYPTSLrDjVAgMUnZ0WZmcDTHZ0Flf0+qFgifYj1Qbz52XjW4yvmOL1
    Ryv9K2UdpCFseOQLwKnset7F2npUTx0kByfeskMKksRdtfuokIu6C2NMAzIRsYXHCcld5BDndaXr
    yGfd+rzPsMwreUGrO/cCAwEAAaNQME4wHQYDVR0OBBYEFCPr2JCU6xvfMnPAMSWgKRxtfnpmMB8G
    A1UdIwQYMBaAFCPr2JCU6xvfMnPAMSWgKRxtfnpmMAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQEL
    BQADggEBAEltT0gjhiIrf80gEHnBxEcZMM/lNhAhuzXLIyP7D4yn0G8UimtktGhHS8vkqtlHvx9T
    Yy8XSa6kwRbRkczr9jaN5opItOBoHGSffpuKiDcjJr50gmJLTXp60ay5xCxkP6aBzMUvocal2asg
    sTeYgMrSVvYeXPihCcviN9nhJA/73HeOoQuf4r3cre2+8W6yggIxEWpXS9MsXHmRys9KnhRqm/u8
    H6E78TkGq1BoyW0HZfILX8VVvxrczMuyp/VAZP48QE9eWkge6OQCjUtSv1FWeQlFMot1Wjdj0rq+
    OZaxuJKYgGezcJamUYOXmj+gvlknAVOvuPeg2wwk/Sq988g=
    """
}

private struct FixtureAttestationProvider: EudiWalletAttestationProviding {
    func walletAttestation(publicJWK: String) async throws -> String { "fixture-wallet-attestation" }
    func keyAttestation(publicJWKs: [String], nonce: String?) async throws -> String {
        "fixture-key-attestation"
    }
}

private actor MemoryAuditRepository: AuditRepository {
    private var storage: [AuditEvent] = []
    func events() async throws -> [AuditEvent] { storage }
    func append(_ event: AuditEvent) async throws { storage.append(event) }
    func deleteAll() async throws { storage = [] }
}

private actor MemoryMetadataRepository: CredentialMetadataRepository {
    private var storage: [CredentialID: CredentialRecord] = [:]
    func credentials() async throws -> [CredentialRecord] { Array(storage.values) }
    func saveMetadata(_ credential: CredentialRecord) async throws { storage[credential.id] = credential }
    func replaceMetadata(_ credential: CredentialRecord) async throws { storage[credential.id] = credential }
    func deleteMetadata(id: CredentialID) async throws { storage[id] = nil }
}

private actor MemoryRecoveryStore: WalletOperationRecoveryStore {
    private var storage: [UUID: WalletOperationRecovery] = [:]
    func recoveries() async throws -> [WalletOperationRecovery] { Array(storage.values) }
    func saveRecovery(_ recovery: WalletOperationRecovery) async throws { storage[recovery.id] = recovery }
    func replaceRecovery(_ recovery: WalletOperationRecovery) async throws { storage[recovery.id] = recovery }
    func deleteRecovery(id: UUID) async throws { storage[id] = nil }
}

private struct FixtureStatusProvider: EudiCredentialStatusProviding {
    func status(for document: EudiWalletDocumentSummary) async throws -> CredentialStatusState {
        .notEvaluated
    }
}
