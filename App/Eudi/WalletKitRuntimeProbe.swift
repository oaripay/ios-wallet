import EudiWalletKitAdapter
import Foundation
import WalletDomain

enum WalletKitRuntimeProbe {
    static func loadDocumentCount(trustAnchor: Data) async throws -> Int {
        let baseline = try EudiWalletKitBaseline(
            serviceName: "io.oari.wallet.ios-integration-tests"
        )
        let trustSource = try EudiTrustAnchorSource(
            profileID: "ios-integration-test",
            anchors: [trustAnchor],
            approvedSHA256Digests: [EudiTrustAnchorSource.sha256Digest(of: trustAnchor)]
        )
        let adapter = try baseline.makeWallet(trustSource: trustSource)
        return try await adapter.loadDocumentSummaries().count
    }

    static func rejectMalformedOperationalInputs(trustAnchor: Data) async throws {
        let baseline = try EudiWalletKitBaseline(
            serviceName: "io.oari.wallet.ios-operational-input-tests"
        )
        let trustSource = try EudiTrustAnchorSource(
            profileID: "ios-operational-input-test",
            anchors: [trustAnchor],
            approvedSHA256Digests: [EudiTrustAnchorSource.sha256Digest(of: trustAnchor)]
        )
        let configuration = try EudiOperationalConfiguration(
            clientID: "oari-wallet-tests",
            authorizationRedirectURI: URL(string: "https://wallet.ios.oari.io/oauth/callback")!,
            attestationProvider: RuntimeProbeAttestationProvider(),
            auditRepository: RuntimeProbeAuditRepository(),
            auditPolicy: .development,
            auditPolicyVersion: AuditPolicyVersion(rawValue: 1),
            metadataRepository: RuntimeProbeMetadataRepository(),
            recoveryStore: RuntimeProbeRecoveryStore(),
            statusProvider: RuntimeProbeStatusProvider(),
            allowedIssuerOrigins: ["https://issuer.example"],
            allowedVerifierOrigins: ["https://verifier.example"],
            allowedApplicationRedirectOrigins: ["https://oari.io"]
        )
        let adapter = try baseline.makeWallet(
            trustSource: trustSource,
            operationalConfiguration: configuration
        )
        do {
            _ = try await adapter.resolveIssuanceOffer(uri: "http://issuer.example/offer")
            throw WalletKitRuntimeProbeError.unsafeInputAccepted
        } catch EudiWalletKitAdapterError.invalidOfferURI {}
        do {
            _ = try await adapter.beginOpenID4VPPresentation(
                requestURI: "https://user:password@verifier.example/request"
            )
            throw WalletKitRuntimeProbeError.unsafeInputAccepted
        } catch EudiWalletKitAdapterError.invalidPresentationURI {}
    }

    static func useInjectedOperationalTransport(trustAnchor: Data) async throws {
        let transport = RuntimeProbeNetworkTransport()
        let baseline = try EudiWalletKitBaseline(
            serviceName: "io.oari.wallet.ios-operational-transport-tests"
        )
        let trustSource = try EudiTrustAnchorSource(
            profileID: "ios-operational-transport-test",
            anchors: [trustAnchor],
            approvedSHA256Digests: [EudiTrustAnchorSource.sha256Digest(of: trustAnchor)]
        )
        let configuration = try EudiOperationalConfiguration(
            clientID: "oari-wallet-tests",
            authorizationRedirectURI: URL(string: "https://wallet.ios.oari.io/oauth/callback")!,
            attestationProvider: RuntimeProbeAttestationProvider(),
            auditRepository: RuntimeProbeAuditRepository(),
            auditPolicy: .development,
            auditPolicyVersion: AuditPolicyVersion(rawValue: 1),
            metadataRepository: RuntimeProbeMetadataRepository(),
            recoveryStore: RuntimeProbeRecoveryStore(),
            statusProvider: RuntimeProbeStatusProvider(),
            allowedIssuerOrigins: ["https://issuer.example"],
            allowedVerifierOrigins: ["https://verifier.example"],
            allowedApplicationRedirectOrigins: ["https://oari.io"],
            networkTransport: transport
        )
        let adapter = try baseline.makeWallet(
            trustSource: trustSource,
            operationalConfiguration: configuration
        )
        do {
            _ = try await adapter.resolveIssuanceOffer(
                uri: "https://issuer.example/credential-offer"
            )
            throw WalletKitRuntimeProbeError.fixtureUnexpectedlySucceeded
        } catch WalletKitRuntimeProbeError.fixtureUnexpectedlySucceeded {
            throw WalletKitRuntimeProbeError.fixtureUnexpectedlySucceeded
        } catch {}
        guard await transport.requestHosts == ["issuer.example"] else {
            throw WalletKitRuntimeProbeError.injectedTransportNotUsed
        }

        let redirectTransport = RuntimeProbeNetworkTransport(statusCode: 302)
        let redirectConfiguration = try EudiOperationalConfiguration(
            clientID: "oari-wallet-tests",
            authorizationRedirectURI: URL(string: "https://wallet.ios.oari.io/oauth/callback")!,
            attestationProvider: RuntimeProbeAttestationProvider(),
            auditRepository: RuntimeProbeAuditRepository(),
            auditPolicy: .development,
            auditPolicyVersion: AuditPolicyVersion(rawValue: 1),
            metadataRepository: RuntimeProbeMetadataRepository(),
            recoveryStore: RuntimeProbeRecoveryStore(),
            statusProvider: RuntimeProbeStatusProvider(),
            allowedIssuerOrigins: ["https://issuer.example"],
            allowedVerifierOrigins: ["https://verifier.example"],
            allowedApplicationRedirectOrigins: ["https://oari.io"],
            networkTransport: redirectTransport
        )
        let redirectAdapter = try baseline.makeWallet(
            trustSource: trustSource,
            operationalConfiguration: redirectConfiguration
        )
        do {
            _ = try await redirectAdapter.resolveIssuanceOffer(
                uri: "https://issuer.example/credential-offer"
            )
            throw WalletKitRuntimeProbeError.fixtureUnexpectedlySucceeded
        } catch WalletKitRuntimeProbeError.fixtureUnexpectedlySucceeded {
            throw WalletKitRuntimeProbeError.fixtureUnexpectedlySucceeded
        } catch {}
        guard await redirectTransport.requestHosts == ["issuer.example"] else {
            throw WalletKitRuntimeProbeError.redirectWasFollowed
        }
    }

    static func reconcileDurableOperationalState(trustAnchor: Data) async throws {
        let baseline = try EudiWalletKitBaseline(
            serviceName: "io.oari.wallet.ios-recovery-tests"
        )
        let trustSource = try EudiTrustAnchorSource(
            profileID: "ios-recovery-test",
            anchors: [trustAnchor],
            approvedSHA256Digests: [EudiTrustAnchorSource.sha256Digest(of: trustAnchor)]
        )
        let metadata = RuntimeProbeMetadataRepository()
        let audit = RuntimeProbeAuditRepository()
        let recoveries = RuntimeProbeRecoveryStore()
        let staleCredential = CredentialRecord(
            configurationID: "fixture",
            walletDocumentID: "already-deleted-wallet-document",
            displayName: "Fixture",
            format: .sdJWTVC,
            profileID: "fixture",
            issuerIdentifier: "https://issuer.example",
            createdAt: Date(timeIntervalSince1970: 1_700_000_000)
        )
        try await metadata.saveMetadata(staleCredential)
        let pendingAudit = AuditEvent(
            operation: .credentialDeletion,
            outcome: .completed,
            occurredAt: Date(timeIntervalSince1970: 1_700_000_001),
            counterpartyIdentifierDigest: .sha256("https://verifier.example"),
            disclosedClaimDigests: [.sha256("family_name")],
            policy: .development,
            policyVersion: AuditPolicyVersion(rawValue: 1)
        )
        try await recoveries.saveRecovery(WalletOperationRecovery(
            kind: .deletion,
            affectedDocuments: [WalletDocumentRecoveryReference(
                id: "already-deleted-wallet-document",
                status: "issued"
            )],
            metadataCredentialIDs: [staleCredential.id],
            pendingAuditEvent: pendingAudit
        ))
        let configuration = try EudiOperationalConfiguration(
            clientID: "oari-wallet-tests",
            authorizationRedirectURI: URL(string: "https://wallet.ios.oari.io/oauth/callback")!,
            attestationProvider: RuntimeProbeAttestationProvider(),
            auditRepository: audit,
            auditPolicy: .development,
            auditPolicyVersion: AuditPolicyVersion(rawValue: 1),
            metadataRepository: metadata,
            recoveryStore: recoveries,
            statusProvider: RuntimeProbeStatusProvider(),
            allowedIssuerOrigins: ["https://issuer.example"],
            allowedVerifierOrigins: ["https://verifier.example"],
            allowedApplicationRedirectOrigins: ["https://oari.io"]
        )
        let adapter = try baseline.makeWallet(
            trustSource: trustSource,
            operationalConfiguration: configuration
        )
        try await adapter.reconcilePendingOperations()
        guard try await metadata.credentials().isEmpty,
              try await recoveries.recoveries().isEmpty,
              try await audit.events() == [pendingAudit]
        else {
            throw WalletKitRuntimeProbeError.recoveryDidNotConverge
        }
        try await adapter.reconcilePendingOperations()
        guard try await audit.events() == [pendingAudit] else {
            throw WalletKitRuntimeProbeError.recoveryWasNotIdempotent
        }
    }
}

enum WalletKitRuntimeProbeError: Error, Equatable {
    case unsafeInputAccepted
    case fixtureUnexpectedlySucceeded
    case injectedTransportNotUsed
    case redirectWasFollowed
    case recoveryDidNotConverge
    case recoveryWasNotIdempotent
}

private struct RuntimeProbeAttestationProvider: EudiWalletAttestationProviding {
    func walletAttestation(publicJWK: String) async throws -> String { "not-used-by-input-probe" }
    func keyAttestation(publicJWKs: [String], nonce: String?) async throws -> String {
        "not-used-by-input-probe"
    }
}

private actor RuntimeProbeAuditRepository: AuditRepository {
    private var storage: [AuditEvent] = []
    func events() async throws -> [AuditEvent] { storage }
    func append(_ event: AuditEvent) async throws {
        guard !storage.contains(where: { $0.id == event.id }) else { return }
        storage.append(event)
    }
    func deleteAll() async throws { storage = [] }
}

private actor RuntimeProbeMetadataRepository: CredentialMetadataRepository {
    private var storage: [CredentialID: CredentialRecord] = [:]
    func credentials() async throws -> [CredentialRecord] { Array(storage.values) }
    func saveMetadata(_ credential: CredentialRecord) async throws { storage[credential.id] = credential }
    func replaceMetadata(_ credential: CredentialRecord) async throws { storage[credential.id] = credential }
    func deleteMetadata(id: CredentialID) async throws { storage[id] = nil }
}

private actor RuntimeProbeRecoveryStore: WalletOperationRecoveryStore {
    private var storage: [UUID: WalletOperationRecovery] = [:]
    func recoveries() async throws -> [WalletOperationRecovery] { Array(storage.values) }
    func saveRecovery(_ recovery: WalletOperationRecovery) async throws { storage[recovery.id] = recovery }
    func replaceRecovery(_ recovery: WalletOperationRecovery) async throws { storage[recovery.id] = recovery }
    func deleteRecovery(id: UUID) async throws { storage[id] = nil }
}

private struct RuntimeProbeStatusProvider: EudiCredentialStatusProviding {
    func status(for document: EudiWalletDocumentSummary) async throws -> CredentialStatusState {
        .notEvaluated
    }
}

private actor RuntimeProbeNetworkTransport: EudiNetworkTransport {
    private(set) var requestHosts: [String] = []
    private let statusCode: Int

    init(statusCode: Int = 404) {
        self.statusCode = statusCode
    }

    func data(for request: URLRequest) async throws -> EudiHTTPResponse {
        requestHosts.append(request.url?.host ?? "")
        return EudiHTTPResponse(
            body: Data("{\"error\":\"fixture-stop\"}".utf8),
            statusCode: statusCode,
            headers: [
                "Content-Type": "application/json",
                "Location": "https://evil.example/redirect",
            ]
        )
    }
}
