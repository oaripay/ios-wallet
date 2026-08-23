import EbsiW3CBackend
import EudiWalletKitAdapter
import Foundation
import WalletDomain
import WalletVault

enum OpenID4VCInteractionKind: Equatable, Sendable {
    case issuance
    case presentation
}

struct OpenID4VCResolvedInteraction: Equatable, Identifiable, Sendable {
    let id: UUID
    let kind: OpenID4VCInteractionKind
    let counterpartyIdentifier: String
    let displayName: String?
    let trustOutcome: EbsiTrustGateOutcome
    let transactionCodeRequired: Bool
    let transactionCodeLength: Int?
    let transactionCodeDescription: String?
    let configurationIDs: [String]
    let authorizationRequired: Bool
    let representations: [String]
    let credentialDisplay: [String: CredentialConfigurationDisplay]
}

enum OpenID4VCInteractionCompletion: Equatable, Sendable {
    case completed(String)
    case pending(String)
    case presentationRequired(OpenID4VPPresentationRequest)
    case webAuthorizationRequired(WebAuthorizationChallenge)
    case credentialSignerTrustWarning(EbsiTrustWarning)
}

protocol OpenID4VCOperating: Sendable {
    func resolveInteraction(uri: String) async throws -> OpenID4VCResolvedInteraction
    func beginPresentation(uri: String) async throws -> EudiPresentationRequest
    func completePresentation(
        id: UUID,
        selectedClaimIDs: Set<String>,
        userAccepted: Bool
    ) async throws -> URL?
    func continueInteraction(
        id: UUID,
        allowUntrusted: Bool,
        transactionCode: String?
    ) async throws -> OpenID4VCInteractionCompletion
    func cancelInteraction(id: UUID) async
    func deferredIssuances() async throws -> [DeferredIssuance]
    func checkDeferredIssuance(id: UUID, allowUntrustedSigner: Bool) async throws -> OpenID4VCInteractionCompletion
    func removeDeferredIssuance(id: UUID) async throws
    func resumeEligibleDeferredIssuances() async
    func preparePIDPresentation(id: UUID) async throws -> EudiPresentationRequest
    func completePIDPresentation(
        id: UUID,
        selectedClaimIDs: Set<String>,
        userAccepted: Bool
    ) async throws -> OpenID4VCInteractionCompletion
    func completeAuthorization(id: UUID, code: String) async throws -> OpenID4VCInteractionCompletion
    func pollWebAuthorization(id: UUID) async throws -> WebAuthorizationPollResult
    func deleteCredential(
        backendID: UUID,
        metadataID: CredentialID,
        issuerIdentifier: String
    ) async throws
}

actor LiveOpenID4VCService: OpenID4VCOperating {
    private struct PersistedDeferredContinuation: Codable {
        let backend: DeferredW3CCredential
        let signerWarning: PersistedSignerWarning?
        let issuerUntrusted: Bool
        let completion: DeferredCompletion?
    }

    private struct DeferredCompletion: Codable {
        let records: [CredentialRecord]
        let auditEvent: AuditEvent
    }

    private struct PersistedSignerWarning: Codable {
        let id: UUID
        let counterpartyIdentifier: String
        let role: EbsiTrustWarning.Role
        let reasons: [String]
        let evidenceSources: [String]
        let nextAction: String

        init(_ warning: EbsiTrustWarning) {
            id = warning.id
            counterpartyIdentifier = warning.counterpartyIdentifier
            role = warning.role
            reasons = warning.reasons.map(\.rawValue)
            evidenceSources = warning.evidenceSources
            nextAction = warning.nextAction
        }

        var value: EbsiTrustWarning {
            EbsiTrustWarning(
                id: id, counterpartyIdentifier: counterpartyIdentifier, role: role,
                reasons: reasons.compactMap { .init(rawValue: $0) },
                evidenceSources: evidenceSources, nextAction: nextAction
            )
        }
    }
    private let backend: OpenID4VCW3CBackend
    private let metadata: any CredentialMetadataRepository
    private let audit: any AuditRepository
    private let deferredRepository: any DeferredIssuanceRepository
    private var issuers: [UUID: String] = [:]
    private var authorizationRequired: Set<UUID> = []
    private var activeDeferredChecks: Set<UUID> = []

    init(
        backend: OpenID4VCW3CBackend,
        metadata: any CredentialMetadataRepository,
        audit: any AuditRepository,
        deferredRepository: any DeferredIssuanceRepository
    ) {
        self.backend = backend
        self.metadata = metadata
        self.audit = audit
        self.deferredRepository = deferredRepository
    }

    func resolveInteraction(uri: String) async throws -> OpenID4VCResolvedInteraction {
        let offer = try await backend.resolveOffer(uri)
        issuers[offer.id] = offer.issuer
        if offer.authorizationRequired { authorizationRequired.insert(offer.id) }
        return OpenID4VCResolvedInteraction(
            id: offer.id,
            kind: .issuance,
            counterpartyIdentifier: offer.issuer,
            displayName: offer.displayName,
            trustOutcome: offer.trustOutcome,
            transactionCodeRequired: offer.transactionCodeRequired,
            transactionCodeLength: offer.transactionCodeLength,
            transactionCodeDescription: offer.transactionCodeDescription,
            configurationIDs: offer.configurationIDs
            , authorizationRequired: offer.authorizationRequired,
            representations: offer.representations
            , credentialDisplay: offer.credentialDisplay
        )
    }

    func beginPresentation(uri: String) async throws -> EudiPresentationRequest {
        let request = try await backend.beginStoredOpenID4VPPresentation(uri: uri)
        return presentationRequest(request)
    }

    func completePresentation(
        id: UUID,
        selectedClaimIDs: Set<String>,
        userAccepted: Bool
    ) async throws -> URL? {
        let redirectURI = try await backend.completeStoredOpenID4VPPresentation(
            id: id,
            selectedClaimIDs: selectedClaimIDs,
            userAccepted: userAccepted
        )
        try await audit.append(AuditEvent(
            operation: .presentation,
            outcome: userAccepted ? .completed : .cancelled,
            occurredAt: Date(),
            counterpartyIdentifierDigest: .sha256("openid4vp"),
            credentialIDs: [],
            policy: .development,
            policyVersion: AuditPolicyVersion(rawValue: 1)
        ))
        return redirectURI
    }

    func continueInteraction(
        id: UUID,
        allowUntrusted: Bool,
        transactionCode: String?
    ) async throws -> OpenID4VCInteractionCompletion {
        if authorizationRequired.contains(id) {
            let challenge = try await backend.beginPresentationRequired(
                id: id,
                allowUntrusted: allowUntrusted,
                interactionTypes: ["urn:openid:dcp:ia:openid4vp_presentation"]
            )
            switch challenge {
            case let .presentation(request): return .presentationRequired(request)
            case let .web(challenge): return .webAuthorizationRequired(challenge)
            }
        }
        let outcome: W3CCredentialIssuanceOutcome
        do {
            outcome = try await backend.issueOutcome(
                id: id,
                allowUntrusted: allowUntrusted,
                transactionCode: transactionCode
            )
        } catch OpenID4VCBackendError.credentialSignerTrustWarning(let warning) {
            return .credentialSignerTrustWarning(warning)
        }
        if case let .deferred(continuation) = outcome {
            let now = Date()
            let expectation = continuation.configurationIDs.compactMap { continuation.expectations[$0] }.first
            try await deferredRepository.saveDeferredIssuance(DeferredIssuance(
                id: continuation.transactionID,
                continuation: try encodeContinuation(continuation, issuerUntrusted: allowUntrusted),
                issuerIdentifier: continuation.issuer.absoluteString,
                configurationIDs: continuation.configurationIDs,
                displayName: expectation?.displayName ?? "Pending credential",
                display: expectation?.display,
                nextAttemptAt: continuation.nextPollAt,
                createdAt: now,
                updatedAt: now
            ))
            issuers.removeValue(forKey: id)
            authorizationRequired.remove(id)
            return .pending("Credential issuance is pending. You can check it from your wallet.")
        }
        guard case let .issued(credentials) = outcome else { throw OpenID4VCBackendError.invalidResponse }
        let issuer = issuers.removeValue(forKey: id) ?? "unknown"
        authorizationRequired.remove(id)
        try await saveIssuedCredentials(credentials, issuer: issuer, allowUntrusted: allowUntrusted)
        return .completed("Issued and stored \(credentials.count) W3C credential(s).")
    }

    func deferredIssuances() async throws -> [DeferredIssuance] {
        try await deferredRepository.deferredIssuances()
    }

    func checkDeferredIssuance(
        id: UUID,
        allowUntrustedSigner: Bool
    ) async throws -> OpenID4VCInteractionCompletion {
        guard !activeDeferredChecks.contains(id) else { return .pending("A check is already in progress.") }
        activeDeferredChecks.insert(id)
        defer { activeDeferredChecks.remove(id) }
        guard let envelope = try await deferredRepository.deferredIssuances().first(where: { $0.id == id }) else {
            throw WalletRepositoryError.deferredIssuanceNotFound
        }
        let persisted = try JSONDecoder().decode(PersistedDeferredContinuation.self, from: envelope.continuation)
        var continuation = persisted.backend
        if let completion = persisted.completion {
            do {
                return try await finishDeferredCompletion(envelope: envelope, completion: completion)
            } catch {
                try? await replace(
                    envelope, continuation: continuation, state: .pending,
                    nextAttemptAt: Date().addingTimeInterval(Self.backoff(after: envelope.attempts + 1)),
                    completion: completion
                )
                return .pending("The credential is stored. Wallet bookkeeping will retry while active.")
            }
        }
        if envelope.state == .signerTrustRequired, !allowUntrustedSigner,
           let warning = persisted.signerWarning {
            return .credentialSignerTrustWarning(warning.value)
        }
        do {
            var outcome: W3CCredentialIssuanceOutcome
            if envelope.state == .signerTrustRequired && allowUntrustedSigner {
                outcome = try await backend.commitDeferredCredential(continuation, allowUntrusted: true)
            } else {
                outcome = try await backend.retrieveDeferredCredential(continuation)
            }
            if case let .deferred(updated) = outcome, updated.remoteTransactionIDs.isEmpty {
                // The final credential response is staged before signer trust and
                // durable storage. Finish that local-only phase in this check rather
                // than scheduling an immediately eligible second poll.
                continuation = updated
                outcome = try await backend.retrieveDeferredCredential(updated)
            }
            switch outcome {
            case let .deferred(updated):
                try await replace(envelope, continuation: updated, state: .pending)
                return .pending("Credential is still pending at the issuer.")
            case let .issued(credentials):
                let completion = makeCompletion(
                    credentials,
                    issuer: envelope.issuerIdentifier,
                    allowUntrusted: persisted.issuerUntrusted || allowUntrustedSigner
                )
                try await replace(
                    envelope, continuation: continuation, state: .completing,
                    completion: completion
                )
                let checkpoint = try await deferredRepository.deferredIssuances().first { $0.id == id } ?? envelope
                do {
                    return try await finishDeferredCompletion(envelope: checkpoint, completion: completion)
                } catch {
                    try? await replace(
                        checkpoint, continuation: continuation, state: .pending,
                        nextAttemptAt: Date().addingTimeInterval(Self.backoff(after: checkpoint.attempts + 1)),
                        completion: completion
                    )
                    return .pending("The credential is stored. Wallet bookkeeping will resume while active.")
                }
            }
        } catch OpenID4VCBackendError.deferredCredentialNotReady(let nextPollAt) {
            try await replace(
                envelope, continuation: continuation, state: .pending,
                nextAttemptAt: nextPollAt, incrementAttempts: false
            )
            return .pending("The issuer asked the wallet to wait before checking again.")
        } catch OpenID4VCBackendError.deferredCredentialSignerTrustWarning(let warning, let updated) {
            continuation = updated
            try await replace(
                envelope, continuation: updated, state: .signerTrustRequired, signerWarning: warning
            )
            return .credentialSignerTrustWarning(warning)
        } catch OpenID4VCBackendError.authorizationFailed {
            try await replace(envelope, continuation: continuation, state: .authorizationRequired)
            return .pending("Issuer authorization is required before this credential can be retrieved.")
        } catch OpenID4VCBackendError.remoteOAuthError(let code, _) where code == "invalid_token" || code == "invalid_grant" {
            try await replace(envelope, continuation: continuation, state: .authorizationRequired)
            return .pending("Issuer authorization is required before this credential can be retrieved.")
        } catch {
            if Self.isTransient(error) {
                let retryAt = Date().addingTimeInterval(Self.backoff(after: envelope.attempts + 1))
                try? await replace(
                    envelope, continuation: continuation, state: .pending,
                    nextAttemptAt: retryAt
                )
                return .pending("The check could not complete. The wallet will retry while active.")
            }
            try? await replace(envelope, continuation: continuation, state: .failed)
            throw error
        }
    }

    func removeDeferredIssuance(id: UUID) async throws {
        try await deferredRepository.deleteDeferredIssuance(id: id)
    }

    func resumeEligibleDeferredIssuances() async {
        guard let issuances = try? await deferredRepository.deferredIssuances() else { return }
        for issuance in issuances where issuance.state == .completing
            || (issuance.state == .pending && issuance.nextAttemptAt <= Date()) {
            _ = try? await checkDeferredIssuance(id: issuance.id, allowUntrustedSigner: false)
        }
    }

    private func replace(
        _ envelope: DeferredIssuance,
        continuation: DeferredW3CCredential,
        state: DeferredIssuanceState,
        nextAttemptAt: Date? = nil,
        signerWarning: EbsiTrustWarning? = nil,
        incrementAttempts: Bool = true,
        completion: DeferredCompletion? = nil
    ) async throws {
        let issuerUntrusted = try JSONDecoder().decode(
            PersistedDeferredContinuation.self, from: envelope.continuation
        ).issuerUntrusted
        try await deferredRepository.replaceDeferredIssuance(DeferredIssuance(
            id: envelope.id,
            continuation: try encodeContinuation(
                continuation, signerWarning: signerWarning, issuerUntrusted: issuerUntrusted,
                completion: completion
            ),
            issuerIdentifier: envelope.issuerIdentifier,
            configurationIDs: envelope.configurationIDs,
            displayName: envelope.displayName,
            display: envelope.display,
            nextAttemptAt: nextAttemptAt ?? continuation.nextPollAt,
            attempts: envelope.attempts + (incrementAttempts ? 1 : 0),
            state: state,
            createdAt: envelope.createdAt,
            updatedAt: Date()
        ))
    }

    private func encodeContinuation(
        _ continuation: DeferredW3CCredential,
        signerWarning: EbsiTrustWarning? = nil,
        issuerUntrusted: Bool? = nil,
        completion: DeferredCompletion? = nil
    ) throws -> Data {
        try JSONEncoder().encode(PersistedDeferredContinuation(
            backend: continuation,
            signerWarning: signerWarning.map(PersistedSignerWarning.init),
            issuerUntrusted: issuerUntrusted ?? false,
            completion: completion
        ))
    }

    private func makeCompletion(
        _ credentials: [IssuedW3CCredential], issuer: String, allowUntrusted: Bool
    ) -> DeferredCompletion {
        let now = Date()
        let records = credentials.map { credential in
            CredentialRecord(
                configurationID: credential.configurationID,
                backendID: W3CBackendComposition.backendID,
                backendDocumentID: credential.id.uuidString,
                displayName: credential.displayName,
                format: credential.representation == .dcSdJwt || credential.representation == .vcdm2SdJwt
                    ? .sdJWTVC : .jwtVC,
                profileID: credential.profileID,
                issuerIdentifier: credential.issuerIdentifier,
                cryptographicValidity: .valid,
                issuerTrust: allowUntrusted ? .untrusted : .trusted,
                status: credential.hasStatusReference ? .notEvaluated : .notProvided,
                legalClassification: .provisional,
                createdAt: now,
                displayClaims: credential.displayClaims,
                display: credential.display
            )
        }
        return DeferredCompletion(records: records, auditEvent: AuditEvent(
            operation: .issuance,
            outcome: .completed,
            occurredAt: now,
            counterpartyIdentifierDigest: .sha256(issuer),
            credentialIDs: records.map(\.id),
            policy: .development,
            policyVersion: AuditPolicyVersion(rawValue: 1)
        ))
    }

    private func finishDeferredCompletion(
        envelope: DeferredIssuance, completion: DeferredCompletion
    ) async throws -> OpenID4VCInteractionCompletion {
        let existing = try await metadata.credentials()
        let existingBackendIDs = Set(existing.compactMap(\.backendDocumentID))
        for record in completion.records where !existingBackendIDs.contains(record.backendDocumentID ?? "") {
            try await metadata.saveMetadata(record)
        }
        try await audit.append(completion.auditEvent)
        try await deferredRepository.deleteDeferredIssuance(id: envelope.id)
        return .completed("Issued and stored \(completion.records.count) W3C credential(s).")
    }

    static func backoff(after attempts: Int) -> TimeInterval {
        min(900, 15 * pow(2, Double(min(max(attempts - 1, 0), 6))))
    }

    static func isTransient(_ error: Error) -> Bool {
        if error is URLError { return true }
        if case let OpenID4VCBackendError.remoteHTTPError(status, _) = error { return status >= 500 }
        if let repositoryError = error as? WalletRepositoryError {
            return repositoryError == .storageFailure || repositoryError == .userAuthenticationRequired
        }
        if let vaultError = error as? VaultError {
            switch vaultError {
            case .keychain, .storageFailure: return true
            case .corruptCiphertext: return false
            }
        }
        let nsError = error as NSError
        return nsError.domain == NSURLErrorDomain
    }

    private func saveIssuedCredentials(
        _ credentials: [IssuedW3CCredential],
        issuer: String,
        allowUntrusted: Bool
    ) async throws {
        var credentialIDs: [CredentialID] = []
        for credential in credentials {
            let record = CredentialRecord(
                configurationID: credential.configurationID,
                backendID: W3CBackendComposition.backendID,
                backendDocumentID: credential.id.uuidString,
                displayName: credential.displayName,
                format: credential.representation == .dcSdJwt || credential.representation == .vcdm2SdJwt
                    ? .sdJWTVC
                    : .jwtVC,
                 profileID: credential.profileID,
                 issuerIdentifier: credential.issuerIdentifier,
                cryptographicValidity: .valid,
                issuerTrust: allowUntrusted ? .untrusted : .trusted,
                status: credential.hasStatusReference ? .notEvaluated : .notProvided,
                legalClassification: .provisional,
                 createdAt: Date(),
                 displayClaims: credential.displayClaims,
                 display: credential.display
            )
            try await metadata.saveMetadata(record)
            credentialIDs.append(record.id)
        }
        try await audit.append(AuditEvent(
            operation: .issuance,
            outcome: .completed,
            occurredAt: Date(),
            counterpartyIdentifierDigest: .sha256(issuer),
            credentialIDs: credentialIDs,
            policy: .development,
            policyVersion: AuditPolicyVersion(rawValue: 1)
        ))
    }

    func cancelInteraction(id: UUID) async {
        issuers[id] = nil
        authorizationRequired.remove(id)
        await backend.cancel(id: id)
    }

    func preparePIDPresentation(id: UUID) async throws -> EudiPresentationRequest {
        let request = try await backend.prepareStoredPIDPresentation(id: id)
        return presentationRequest(request)
    }

    private func presentationRequest(_ request: DCQLCredentialPresentationRequest) -> EudiPresentationRequest {
        return EudiPresentationRequest(
            id: request.id,
            verifierName: request.verifierName,
            verifierLegalName: nil,
            verifierCertificateValid: nil,
            claims: request.claims.map { claim in
                EudiRequestedClaim(
                    id: claim.id,
                    documentID: request.id.uuidString,
                    documentType: "W3C credential",
                    displayName: "PID",
                    claimPath: claim.path,
                    displayValue: claim.value,
                    required: claim.required,
                    intentToRetain: false
                )
            },
            warningCount: 0,
            transactionData: request.transactionData.map(Self.transactionDataFields)
        )
    }

    private static func transactionDataFields(
        _ object: [String: AnySendableJSON]
    ) -> [EudiTransactionDataField] {
        object.keys.sorted().map { key in
            EudiTransactionDataField(key: key, value: Self.displayValue(object[key] ?? .null))
        }
    }

    private static func displayValue(_ value: AnySendableJSON) -> String {
        switch value {
        case let .string(string): string
        case let .number(number):
            number == number.rounded() && abs(number) < 1e15
                ? String(Int64(number))
                : String(number)
        case let .bool(bool): bool ? "Yes" : "No"
        case let .array(values): values.map(Self.displayValue).joined(separator: ", ")
        case let .object(object):
            object.keys.sorted()
                .map { "\($0): \(Self.displayValue(object[$0] ?? .null))" }
                .joined(separator: ", ")
        case .null: "—"
        }
    }

    func completePIDPresentation(
        id: UUID,
        selectedClaimIDs: Set<String>,
        userAccepted: Bool
    ) async throws -> OpenID4VCInteractionCompletion {
        guard userAccepted else {
            await cancelInteraction(id: id)
            return .completed("PID request declined. Nothing was shared.")
        }
        let token = try await backend.storedPIDPresentationToken(
            id: id,
            selectedClaimIDs: selectedClaimIDs
        )
        return try await submitPIDPresentation(id: id, vpToken: token)
    }

    private func submitPIDPresentation(id: UUID, vpToken: String) async throws -> OpenID4VCInteractionCompletion {
        _ = try await backend.submitPresentation(id: id, vpToken: vpToken)
        authorizationRequired.remove(id)
        return try await continueInteraction(id: id, allowUntrusted: true, transactionCode: nil)
    }
    func completeAuthorization(id: UUID, code: String) async throws -> OpenID4VCInteractionCompletion {
        try await backend.acceptAuthorizationCode(id: id, code: code)
        authorizationRequired.remove(id)
        return try await continueInteraction(id: id, allowUntrusted: true, transactionCode: nil)
    }

    func pollWebAuthorization(id: UUID) async throws -> WebAuthorizationPollResult {
        try await backend.pollWebAuthorization(id: id)
    }

    func deleteCredential(
        backendID: UUID,
        metadataID: CredentialID,
        issuerIdentifier: String
    ) async throws {
        try await backend.deleteStoredCredential(id: backendID)
        try await metadata.deleteMetadata(id: metadataID)
        try await audit.append(AuditEvent(
            operation: .credentialDeletion,
            outcome: .completed,
            occurredAt: Date(),
            counterpartyIdentifierDigest: .sha256(issuerIdentifier),
            credentialIDs: [metadataID],
            policy: .development,
            policyVersion: AuditPolicyVersion(rawValue: 1)
        ))
    }
}
