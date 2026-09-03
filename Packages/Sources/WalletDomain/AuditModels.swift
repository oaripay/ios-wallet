import CryptoKit
import Foundation

public struct AuditEventID: RawRepresentable, Codable, Hashable, Sendable {
    public let rawValue: UUID

    public init(rawValue: UUID) {
        self.rawValue = rawValue
    }

    public init() {
        self.init(rawValue: UUID())
    }
}

public enum AuditOperation: String, Codable, Sendable {
    case issuance
    case presentation
    case credentialDeletion
    case credentialRefresh
    case keyDeletion
}

public enum AuditOutcome: String, Codable, Sendable {
    case completed
    case cancelled
    case rejected
    case failed
}

public struct AuditDigest: Codable, Equatable, Hashable, Sendable {
    private let value: String

    public static func sha256(_ data: Data) -> AuditDigest {
        let value = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
        return AuditDigest(validatedValue: value)
    }

    public static func sha256(_ value: String) -> AuditDigest {
        sha256(Data(value.utf8))
    }

    private init(validatedValue: String) {
        value = validatedValue
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let candidate = try container.decode(String.self)
        let isLowercaseHex = candidate.utf8.count == 64 && candidate.utf8.allSatisfy {
            (48 ... 57).contains($0) || (97 ... 102).contains($0)
        }
        guard isLowercaseHex else {
            throw DecodingError.dataCorruptedError(
                in: container,
                debugDescription: "Audit digest must be a lowercase SHA-256 value"
            )
        }
        value = candidate
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(value)
    }
}

public enum AuditPolicy: String, Codable, Sendable {
    case regulatedStrict
    case productionConsent
    case development
}

public struct AuditPolicyVersion: RawRepresentable, Codable, Equatable, Sendable {
    public let rawValue: UInt

    public init(rawValue: UInt) {
        self.rawValue = rawValue
    }
}

public enum AuditReasonCode: String, Codable, Sendable {
    case userCancelled
    case userRejected
    case trustRejected
    case unsupportedProfile
    case expired
    case replayDetected
    case localAuthenticationFailed
    case deliveryFailed
    case storageFailed
}

public struct AuditEvent: Codable, Equatable, Identifiable, Sendable {
    public let id: AuditEventID
    public let operation: AuditOperation
    public let outcome: AuditOutcome
    public let occurredAt: Date
    public let counterpartyIdentifierDigest: AuditDigest?
    public let credentialIDs: [CredentialID]
    public let disclosedClaimDigests: [AuditDigest]
    public let policy: AuditPolicy
    public let policyVersion: AuditPolicyVersion
    public let reasonCode: AuditReasonCode?

    public init(
        id: AuditEventID = AuditEventID(),
        operation: AuditOperation,
        outcome: AuditOutcome,
        occurredAt: Date,
        counterpartyIdentifierDigest: AuditDigest? = nil,
        credentialIDs: [CredentialID] = [],
        disclosedClaimDigests: [AuditDigest] = [],
        policy: AuditPolicy,
        policyVersion: AuditPolicyVersion,
        reasonCode: AuditReasonCode? = nil
    ) {
        self.id = id
        self.operation = operation
        self.outcome = outcome
        self.occurredAt = occurredAt
        self.counterpartyIdentifierDigest = counterpartyIdentifierDigest
        self.credentialIDs = credentialIDs
        self.disclosedClaimDigests = disclosedClaimDigests
        self.policy = policy
        self.policyVersion = policyVersion
        self.reasonCode = reasonCode
    }
}
