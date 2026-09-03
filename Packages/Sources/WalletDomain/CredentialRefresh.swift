import Foundation

public enum CredentialRefreshContinuationState: String, Codable, Equatable, Sendable {
    case pending
    case authorizationRequired
    case signerTrustRequired
    case refreshing
    case failed
}

/// Scheduling metadata around an opaque W3C refresh protocol continuation.
public struct CredentialRefreshContinuation: Codable, Equatable, Identifiable, Sendable {
    public let id: UUID
    public let credentialID: CredentialID
    public let continuation: Data
    public let dueAt: Date
    public let attempts: Int
    public let state: CredentialRefreshContinuationState
    public let createdAt: Date
    public let updatedAt: Date

    public init(
        id: UUID = UUID(), credentialID: CredentialID, continuation: Data,
        dueAt: Date, attempts: Int = 0,
        state: CredentialRefreshContinuationState = .pending,
        createdAt: Date, updatedAt: Date
    ) {
        self.id = id
        self.credentialID = credentialID
        self.continuation = continuation
        self.dueAt = dueAt
        self.attempts = attempts
        self.state = state
        self.createdAt = createdAt
        self.updatedAt = updatedAt
    }
}

public protocol CredentialRefreshContinuationRepository: Sendable {
    func refreshContinuations() async throws -> [CredentialRefreshContinuation]
    func saveRefreshContinuation(_ continuation: CredentialRefreshContinuation) async throws
    func replaceRefreshContinuation(_ continuation: CredentialRefreshContinuation) async throws
    func deleteRefreshContinuation(id: UUID) async throws
}
