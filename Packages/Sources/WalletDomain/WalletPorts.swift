import Foundation

/// Application-owned display and policy metadata. Raw Wallet Kit document bytes and
/// document-bound keys must never cross this boundary.
public protocol CredentialMetadataRepository: Sendable {
    func credentials() async throws -> [CredentialRecord]
    func saveMetadata(_ credential: CredentialRecord) async throws
    func replaceMetadata(_ credential: CredentialRecord) async throws
    func deleteMetadata(id: CredentialID) async throws
}

public enum WalletOperationRecoveryKind: String, Codable, Equatable, Sendable {
    case issuance
    case deferredIssuance
    case pendingIssuance
    case deletion
    case audit
}

public struct WalletDocumentRecoveryReference: Codable, Equatable, Sendable {
    public let id: String
    public let status: String

    public init(id: String, status: String) {
        self.id = id
        self.status = status
    }
}

public struct WalletOperationRecovery: Codable, Equatable, Identifiable, Sendable {
    public let id: UUID
    public let kind: WalletOperationRecoveryKind
    public let baselineDocumentIDs: Set<String>
    public let affectedDocuments: [WalletDocumentRecoveryReference]
    public let metadataCredentialIDs: [CredentialID]
    public let metadataCommitted: Bool
    public let pendingAuditEvent: AuditEvent?
    public let createdAt: Date

    public init(
        id: UUID = UUID(),
        kind: WalletOperationRecoveryKind,
        baselineDocumentIDs: Set<String> = [],
        affectedDocuments: [WalletDocumentRecoveryReference] = [],
        metadataCredentialIDs: [CredentialID] = [],
        metadataCommitted: Bool = false,
        pendingAuditEvent: AuditEvent? = nil,
        createdAt: Date = Date()
    ) {
        self.id = id
        self.kind = kind
        self.baselineDocumentIDs = baselineDocumentIDs
        self.affectedDocuments = affectedDocuments
        self.metadataCredentialIDs = metadataCredentialIDs
        self.metadataCommitted = metadataCommitted
        self.pendingAuditEvent = pendingAuditEvent
        self.createdAt = createdAt
    }
}

public protocol WalletOperationRecoveryStore: Sendable {
    func recoveries() async throws -> [WalletOperationRecovery]
    func saveRecovery(_ recovery: WalletOperationRecovery) async throws
    func replaceRecovery(_ recovery: WalletOperationRecovery) async throws
    func deleteRecovery(id: UUID) async throws
}

public protocol AuditRepository: Sendable {
    func events() async throws -> [AuditEvent]
    func append(_ event: AuditEvent) async throws
    func delete(id: AuditEventID) async throws
    func deleteAll() async throws
}

public extension AuditRepository {
    func delete(id: AuditEventID) async throws {
        let remaining = try await events().filter { $0.id != id }
        try await deleteAll()
        for event in remaining {
            try await append(event)
        }
    }
}

public protocol KeyProvider: Sendable {
    func createKey(
        purpose: KeyPurpose,
        algorithm: SigningAlgorithm,
        requiresUserPresence: Bool,
        protection: KeyProtectionPolicy
    ) async throws -> KeyRecord

    func sign(_ request: SigningRequest) async throws -> Data
    func publicKey(id: KeyID) async throws -> PublicKeyMaterial
    func deleteKey(id: KeyID) async throws
}

public enum WalletRepositoryError: Error, Equatable, Sendable {
    case duplicateCredential
    case credentialNotFound
    case duplicateDeferredIssuance
    case deferredIssuanceNotFound
    case duplicateRefreshContinuation
    case refreshContinuationNotFound
    case keyNotFound
    case unsupportedAlgorithm
    case userAuthenticationRequired
    case storageFailure
}
