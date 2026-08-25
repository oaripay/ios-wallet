import Foundation
import TrustDomain

public enum EbsiTrustEnvironment: String, Codable, Equatable, Sendable {
    case development
    case production
}

public struct EbsiTrustWarning: Equatable, Identifiable, Sendable {
    public let id: UUID
    public let counterpartyIdentifier: String
    public let role: Role
    public let reasons: [TrustReason]
    public let evidenceSources: [String]
    public let nextAction: String
    public let diagnostic: String

    public enum Role: String, Codable, Equatable, Sendable {
        case issuer
        case verifier
    }

    public init(
        id: UUID = UUID(),
        counterpartyIdentifier: String,
        role: Role,
        reasons: [TrustReason],
        evidenceSources: [String],
        nextAction: String,
        diagnostic: String = ""
    ) {
        self.id = id
        self.counterpartyIdentifier = counterpartyIdentifier
        self.role = role
        self.reasons = reasons
        self.evidenceSources = evidenceSources
        self.nextAction = nextAction
        self.diagnostic = diagnostic
    }
}

public enum EbsiTrustGateOutcome: Equatable, Sendable {
    case allow
    case requireExplicitWarning(EbsiTrustWarning)
    case reject([TrustReason])
}

public struct EbsiTrustGate: Sendable {
    public init() {}

    public func evaluate(
        verdict: TrustVerdict,
        environment: EbsiTrustEnvironment,
        counterpartyIdentifier: String,
        role: EbsiTrustWarning.Role
    ) -> EbsiTrustGateOutcome {
        switch verdict {
        case .trusted:
            return .allow
        case let .untrusted(reasons, evidence):
            guard environment == .development else { return .reject(reasons) }
            return .requireExplicitWarning(EbsiTrustWarning(
                counterpartyIdentifier: counterpartyIdentifier,
                role: role,
                reasons: reasons,
                evidenceSources: evidence.map(\.sourceIdentifier).sorted(),
                nextAction: role == .issuer
                    ? "Continue the credential issuance request. No credential has been stored yet."
                    : "Continue to claim selection. No information has been shared yet."
            ))
        case let .invalid(reasons, _):
            return .reject(reasons)
        case let .indeterminate(reasons, evidence):
            guard environment == .development else { return .reject(reasons) }
            return .requireExplicitWarning(EbsiTrustWarning(
                counterpartyIdentifier: counterpartyIdentifier,
                role: role,
                reasons: reasons,
                evidenceSources: evidence.map(\.sourceIdentifier).sorted(),
                nextAction: role == .issuer
                    ? "Continue the development issuance request. Registry evidence is unavailable; nothing has been stored yet."
                    : "Continue to development claim selection. Registry evidence is unavailable; nothing has been shared yet."
            ))
        }
    }
}
