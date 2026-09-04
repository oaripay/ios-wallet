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

enum W3CCredentialRefreshCompletion: Equatable, Sendable {
    case completed(CredentialRecord)
    case authorizationRequired
    case signerTrustRequired(EbsiTrustWarning)
    case retryScheduled(Date)
}

protocol OpenID4VCOperating: Sendable {
    func backfillCredentialValidity() async
    func resolveInteraction(uri: String) async throws -> OpenID4VCResolvedInteraction
    func beginPresentation(uri: String) async throws -> EudiPresentationRequest
    func completePresentation(
        id: UUID,
        selectedOptionID: String?,
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
        selectedOptionID: String?,
        selectedClaimIDs: Set<String>,
        userAccepted: Bool
    ) async throws -> OpenID4VCInteractionCompletion
    func completeAuthorization(id: UUID, code: String) async throws -> OpenID4VCInteractionCompletion
    func continueWebAuthorization(id: UUID, authSession: String) async throws -> OpenID4VCInteractionCompletion
    func pollWebAuthorization(id: UUID) async throws -> WebAuthorizationPollResult
    func deleteCredential(
        backendID: UUID,
        metadataID: CredentialID,
        issuerIdentifier: String
    ) async throws
    func canRefreshCredential(id: CredentialID) async -> Bool
    func refreshCredential(id: CredentialID, allowUntrustedSigner: Bool) async throws -> W3CCredentialRefreshCompletion
    func setAutomaticRefresh(id: CredentialID, enabled: Bool) async throws -> CredentialRecord
    func refreshContinuations() async throws -> [CredentialRefreshContinuation]
    func resumeEligibleAutomaticRefreshes() async
}

actor LiveOpenID4VCService: OpenID4VCOperating {
    private struct PersistedRefresh: Codable, Sendable {
        let backend: W3CCredentialRefreshContinuation
        let pending: PendingW3CCredentialRefresh?
        let signerWarning: PersistedSignerWarning?
    }
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
    private let refreshRepository: any CredentialRefreshContinuationRepository
    private var issuers: [UUID: String] = [:]
    private var authorizationRequired: Set<UUID> = []
    private var activeDeferredChecks: Set<UUID> = []

    init(
        backend: OpenID4VCW3CBackend,
        metadata: any CredentialMetadataRepository,
        audit: any AuditRepository,
        deferredRepository: any DeferredIssuanceRepository,
        refreshRepository: any CredentialRefreshContinuationRepository
    ) {
        self.backend = backend
        self.metadata = metadata
        self.audit = audit
        self.deferredRepository = deferredRepository
        self.refreshRepository = refreshRepository
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
        return try await presentationRequest(request)
    }

    func completePresentation(
        id: UUID,
        selectedOptionID: String?,
        selectedClaimIDs: Set<String>,
        userAccepted: Bool
    ) async throws -> URL? {
        let redirectURI = try await backend.completeStoredOpenID4VPPresentation(
            id: id,
            selectedCredentialID: selectedOptionID.flatMap(UUID.init(uuidString:)),
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
                interactionTypes: [
                    "urn:openid:dcp:ia:openid4vp_presentation",
                    "urn:openid:dcp:ia:auth_via_web",
                ]
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
                display: credential.display,
                validFrom: credential.validFrom,
                validUntil: credential.validUntil
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
                 display: credential.display,
                 validFrom: credential.validFrom,
                 validUntil: credential.validUntil
            )
            try await metadata.saveMetadata(record)
            if let continuation = credential.refreshContinuation {
                let now = Date()
                try await refreshRepository.saveRefreshContinuation(CredentialRefreshContinuation(
                    credentialID: record.id,
                    continuation: try JSONEncoder().encode(PersistedRefresh(
                        backend: continuation, pending: nil, signerWarning: nil
                    )),
                    dueAt: Self.defaultRefreshDate(for: record, now: now),
                    createdAt: now,
                    updatedAt: now
                ))
            }
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
        return try await presentationRequest(request)
    }

    private func presentationRequest(_ request: DCQLCredentialPresentationRequest) async throws -> EudiPresentationRequest {
        let records = try await metadata.credentials()
        let recordsByDocumentID = Dictionary(uniqueKeysWithValues: records.map { ($0.backendDocumentID, $0) })
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
                    displayName: nil,
                    claimPath: claim.path,
                    displayValue: claim.value,
                    required: claim.required,
                    intentToRetain: false
                )
            },
            warningCount: 0,
            transactionData: request.transactionData.enumerated().map { index, entry in
                Self.transactionDataPresentation(entry.decoded, index: index)
            },
            credentials: request.credentials.map {
                let record = recordsByDocumentID[$0.id.uuidString]
                return EudiPresentationCredential(
                    id: $0.id.uuidString,
                    displayName: record?.displayName ?? Self.displayCredentialID($0.displayName),
                    issuerIdentifier: record?.issuerIdentifier,
                    configurationID: record?.configurationID,
                    format: record?.format ?? ($0.representation == .dcSdJwt || $0.representation == .vcdm2SdJwt ? .sdJWTVC : .jwtVC),
                    profileID: record?.profileID ?? $0.profileID,
                    representation: $0.representation.rawValue,
                    receivedAt: $0.receivedAt,
                    display: record?.display
                )
            },
            options: request.credentials.map { credential in
                EudiPresentationOption(
                    id: credential.id.uuidString,
                    credentialIDs: [credential.id.uuidString],
                    claims: credential.claims.map { claim in
                        EudiRequestedClaim(
                            id: claim.id,
                            documentID: credential.id.uuidString,
                            documentType: "W3C credential",
                            displayName: nil,
                            claimPath: claim.path,
                            displayValue: claim.value,
                            required: claim.required,
                            intentToRetain: false
                        )
                    }
                )
            }
        )
    }

    private static func transactionDataPresentation(
        _ object: [String: AnySendableJSON],
        index: Int
    ) -> EudiTransactionDataPresentation {
        let type = object["type"]?.string ?? "unknown"
        let purpose = object["purpose"]?.string
        let credentialIDs: [String]
        if case let .array(values)? = object["credential_ids"] {
            credentialIDs = values.compactMap(\.string)
        } else {
            credentialIDs = []
        }
        let reference = object["transaction_id"]?.string
        var fields: [EudiTransactionDataField] = []

        for key in object.keys.sorted() where !["type", "purpose", "transaction_id", "credential_ids"].contains(key) {
            fields.append(EudiTransactionDataField(
                id: "transaction-\(index).\(key)",
                key: humanizedTransactionKey(key),
                value: transactionValue(object[key] ?? .null)
            ))
        }

        return EudiTransactionDataPresentation(
            id: "transaction-\(index)",
            type: type,
            title: transactionTitle(for: type),
            purpose: purpose,
            credentialIDs: credentialIDs,
            reference: reference,
            fields: fields
        )
    }

    private static func transactionTitle(for type: String) -> String {
        if type.localizedCaseInsensitiveContains("payment") { return "Payment authorization" }
        if type.localizedCaseInsensitiveContains("oari-test-transaction") { return "Credential presentation" }
        return "Transaction details"
    }

    private static func humanizedTransactionKey(_ key: String) -> String {
        key.split(separator: "_").map { $0.capitalized }.joined(separator: " ")
    }

    private static func displayCredentialID(_ value: String) -> String {
        switch value {
        case "oari-vcdm2-refresh-test": return "OARI Refresh Test Credential"
        case "oari-rtao-vcdm2-refreshable-credential": return "OARI VCDM 2.0 Credential"
        default: return value
        }
    }

    private static func transactionValue(_ value: AnySendableJSON) -> EudiTransactionDataValue {
        switch value {
        case let .string(string): .string(string)
        case let .number(number): .number(
            number == number.rounded() && abs(number) < 1e15
                ? String(Int64(number))
                : String(number)
        )
        case let .bool(bool): .bool(bool)
        case let .array(values): .array(values.map(Self.transactionValue))
        case let .object(object):
            .object(object.mapValues(Self.transactionValue))
        case .null: .null
        }
    }

    func completePIDPresentation(
        id: UUID,
        selectedOptionID: String?,
        selectedClaimIDs: Set<String>,
        userAccepted: Bool
    ) async throws -> OpenID4VCInteractionCompletion {
        guard userAccepted else {
            await cancelInteraction(id: id)
            return .completed("PID request declined. Nothing was shared.")
        }
        let token = try await backend.storedPIDPresentationToken(
            id: id,
            selectedCredentialID: selectedOptionID.flatMap(UUID.init(uuidString:)),
            selectedClaimIDs: selectedClaimIDs
        )
        return try await submitPIDPresentation(id: id, vpToken: token)
    }

    private func submitPIDPresentation(id: UUID, vpToken: String) async throws -> OpenID4VCInteractionCompletion {
        switch try await backend.submitPresentation(id: id, vpToken: vpToken) {
        case let .interaction(.web(challenge)):
            return .webAuthorizationRequired(challenge)
        case let .interaction(.presentation(request)):
            return .presentationRequired(request)
        case .authorizationCode:
            authorizationRequired.remove(id)
            return try await continueInteraction(id: id, allowUntrusted: true, transactionCode: nil)
        }
    }
    func completeAuthorization(id: UUID, code: String) async throws -> OpenID4VCInteractionCompletion {
        try await backend.acceptAuthorizationCode(id: id, code: code)
        authorizationRequired.remove(id)
        return try await continueInteraction(id: id, allowUntrusted: true, transactionCode: nil)
    }

    func continueWebAuthorization(
        id: UUID,
        authSession: String
    ) async throws -> OpenID4VCInteractionCompletion {
        switch try await backend.continueWebAuthorization(id: id, authSession: authSession) {
        case let .interaction(.web(challenge)):
            return .webAuthorizationRequired(challenge)
        case let .interaction(.presentation(request)):
            return .presentationRequired(request)
        case .authorizationCode:
            authorizationRequired.remove(id)
            return try await continueInteraction(id: id, allowUntrusted: true, transactionCode: nil)
        }
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
        for continuation in try await refreshRepository.refreshContinuations()
            .filter({ $0.credentialID == metadataID }) {
            try await refreshRepository.deleteRefreshContinuation(id: continuation.id)
        }
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

    func canRefreshCredential(id: CredentialID) async -> Bool {
        (try? await refreshRepository.refreshContinuations().contains { $0.credentialID == id }) ?? false
    }

    func refreshContinuations() async throws -> [CredentialRefreshContinuation] {
        try await refreshRepository.refreshContinuations()
    }

    func setAutomaticRefresh(id: CredentialID, enabled: Bool) async throws -> CredentialRecord {
        guard let record = try await metadata.credentials().first(where: { $0.id == id }),
              let envelope = try await refreshRepository.refreshContinuations().first(where: { $0.credentialID == id })
        else { throw WalletRepositoryError.refreshContinuationNotFound }
        let dueAt = enabled ? max(envelope.dueAt, Date()) : envelope.dueAt
        let resumedState: CredentialRefreshContinuationState = if enabled,
            envelope.state == .failed || envelope.state == .refreshing {
            .pending
        } else {
            envelope.state
        }
        try await refreshRepository.replaceRefreshContinuation(refreshEnvelope(
            envelope, dueAt: dueAt,
            state: resumedState,
            incrementAttempts: false
        ))
        let updated = replacing(record, refresh: CredentialRefreshMetadata(
            mode: enabled ? .automatic : .manual,
            state: enabled ? .scheduled : .idle,
            nextRefreshAt: enabled ? dueAt : nil,
            lastAttemptAt: record.refresh.lastAttemptAt,
            lastSuccessfulRefreshAt: record.refresh.lastSuccessfulRefreshAt,
            consecutiveFailures: record.refresh.consecutiveFailures
        ))
        try await metadata.replaceMetadata(updated)
        return updated
    }

    func refreshCredential(
        id: CredentialID, allowUntrustedSigner: Bool = false
    ) async throws -> W3CCredentialRefreshCompletion {
        guard let record = try await metadata.credentials().first(where: { $0.id == id }),
              let envelope = try await refreshRepository.refreshContinuations().first(where: { $0.credentialID == id })
        else { throw WalletRepositoryError.refreshContinuationNotFound }
        let persisted = try JSONDecoder().decode(PersistedRefresh.self, from: envelope.continuation)
        if envelope.state == .signerTrustRequired, !allowUntrustedSigner,
           let warning = persisted.signerWarning {
            return .signerTrustRequired(warning.value)
        }
        let now = Date()
        try await refreshRepository.replaceRefreshContinuation(refreshEnvelope(
            envelope, state: .refreshing, incrementAttempts: false
        ))
        do {
            let outcome = if let pending = persisted.pending {
                try await backend.commitRefresh(pending, allowUntrustedSigner: allowUntrustedSigner)
            } else {
                try await backend.refreshCredential(
                    persisted.backend,
                    allowUntrustedSigner: allowUntrustedSigner
                ) { [refreshRepository, envelope] rotated in
                    try await refreshRepository.replaceRefreshContinuation(CredentialRefreshContinuation(
                        id: envelope.id, credentialID: envelope.credentialID,
                        continuation: try JSONEncoder().encode(PersistedRefresh(
                            backend: rotated, pending: nil, signerWarning: nil
                        )),
                        dueAt: envelope.dueAt, attempts: envelope.attempts,
                        state: .refreshing, createdAt: envelope.createdAt, updatedAt: Date()
                    ))
                }
            }
            switch outcome {
            case let .replaced(result, rotated):
                let next = Self.defaultRefreshDate(for: record, now: now)
                let updated = replacing(record, issued: result, refresh: CredentialRefreshMetadata(
                    mode: record.refresh.mode,
                    state: record.refresh.mode == .automatic ? .scheduled : .idle,
                    nextRefreshAt: record.refresh.mode == .automatic ? next : nil,
                    lastAttemptAt: now, lastSuccessfulRefreshAt: now, consecutiveFailures: 0
                ))
                try await refreshRepository.replaceRefreshContinuation(refreshEnvelope(
                    envelope,
                    continuation: try JSONEncoder().encode(PersistedRefresh(
                        backend: rotated, pending: nil, signerWarning: nil
                    )),
                    dueAt: next, attempts: 0, state: .pending
                ))
                try await metadata.replaceMetadata(updated)
                try? await audit.append(AuditEvent(
                    operation: .credentialRefresh, outcome: .completed, occurredAt: now,
                    counterpartyIdentifierDigest: .sha256(updated.issuerIdentifier),
                    credentialIDs: [id], policy: .development,
                    policyVersion: AuditPolicyVersion(rawValue: 1)
                ))
                return .completed(updated)
            case let .signerTrustRequired(warning, pending):
                try await refreshRepository.replaceRefreshContinuation(refreshEnvelope(
                    envelope,
                    continuation: try JSONEncoder().encode(PersistedRefresh(
                        backend: pending.continuation, pending: pending,
                        signerWarning: PersistedSignerWarning(warning)
                    )), state: .signerTrustRequired
                ))
                try await metadata.replaceMetadata(replacing(record, refresh: CredentialRefreshMetadata(
                    mode: record.refresh.mode, state: .failed, nextRefreshAt: nil,
                    lastAttemptAt: now,
                    lastSuccessfulRefreshAt: record.refresh.lastSuccessfulRefreshAt,
                    consecutiveFailures: record.refresh.consecutiveFailures
                )))
                return .signerTrustRequired(warning)
            case let .authorizationRequired(continuation):
                try await refreshRepository.replaceRefreshContinuation(refreshEnvelope(
                    envelope,
                    continuation: try JSONEncoder().encode(PersistedRefresh(
                        backend: continuation, pending: nil, signerWarning: nil
                    )), state: .authorizationRequired
                ))
                try await metadata.replaceMetadata(replacing(record, refresh: CredentialRefreshMetadata(
                    mode: record.refresh.mode, state: .failed, nextRefreshAt: nil,
                    lastAttemptAt: now,
                    lastSuccessfulRefreshAt: record.refresh.lastSuccessfulRefreshAt,
                    consecutiveFailures: record.refresh.consecutiveFailures
                )))
                return .authorizationRequired
            }
        } catch {
            let currentEnvelope = (try? await refreshRepository.refreshContinuations()
                .first(where: { $0.id == envelope.id })) ?? envelope
            let failures = record.refresh.consecutiveFailures + 1
            if record.refresh.mode == .automatic && Self.isTransient(error) && failures <= 6 {
                let retryAt = now.addingTimeInterval(Self.backoff(after: failures))
                try? await refreshRepository.replaceRefreshContinuation(refreshEnvelope(
                    currentEnvelope, dueAt: retryAt, state: .pending
                ))
                try? await metadata.replaceMetadata(replacing(record, refresh: CredentialRefreshMetadata(
                    mode: record.refresh.mode, state: .failed,
                    nextRefreshAt: record.refresh.mode == .automatic ? retryAt : nil,
                    lastAttemptAt: now,
                    lastSuccessfulRefreshAt: record.refresh.lastSuccessfulRefreshAt,
                    consecutiveFailures: failures
                )))
                return .retryScheduled(retryAt)
            }
            try? await refreshRepository.replaceRefreshContinuation(refreshEnvelope(currentEnvelope, state: .failed))
            try? await metadata.replaceMetadata(replacing(record, refresh: CredentialRefreshMetadata(
                mode: record.refresh.mode,
                state: .failed,
                nextRefreshAt: nil,
                lastAttemptAt: now,
                lastSuccessfulRefreshAt: record.refresh.lastSuccessfulRefreshAt,
                consecutiveFailures: failures
            )))
            throw error
        }
    }

    func resumeEligibleAutomaticRefreshes() async {
        guard let records = try? await metadata.credentials(),
              let continuations = try? await refreshRepository.refreshContinuations() else { return }
        let automatic = Dictionary(uniqueKeysWithValues: records.filter { $0.refresh.mode == .automatic }.map { ($0.id, $0) })
        let eligible = continuations.filter {
            ($0.state == .pending || $0.state == .refreshing)
                && $0.dueAt <= Date() && automatic[$0.credentialID] != nil
        }
        for continuation in eligible.prefix(20) {
            _ = try? await refreshCredential(id: continuation.credentialID, allowUntrustedSigner: false)
        }
    }

    private func refreshEnvelope(
        _ value: CredentialRefreshContinuation, continuation: Data? = nil,
        dueAt: Date? = nil, attempts: Int? = nil,
        state: CredentialRefreshContinuationState, incrementAttempts: Bool = true
    ) -> CredentialRefreshContinuation {
        CredentialRefreshContinuation(
            id: value.id, credentialID: value.credentialID,
            continuation: continuation ?? value.continuation,
            dueAt: dueAt ?? value.dueAt,
            attempts: attempts ?? value.attempts + (incrementAttempts ? 1 : 0),
            state: state, createdAt: value.createdAt, updatedAt: Date()
        )
    }

    private static func defaultRefreshDate(for record: CredentialRecord, now: Date) -> Date {
        max(now.addingTimeInterval(3600), record.expiresAt?.addingTimeInterval(-7 * 86_400) ?? now.addingTimeInterval(86_400))
    }

    private func replacing(
        _ record: CredentialRecord, issued: IssuedW3CCredential? = nil,
        refresh: CredentialRefreshMetadata
    ) -> CredentialRecord {
        CredentialRecord(
            id: record.id, configurationID: issued?.configurationID ?? record.configurationID,
            walletDocumentID: record.walletDocumentID, backendID: record.backendID,
            backendDocumentID: issued?.id.uuidString ?? record.backendDocumentID,
            displayName: issued?.displayName ?? record.displayName,
            format: issued.map { $0.representation == .dcSdJwt || $0.representation == .vcdm2SdJwt ? .sdJWTVC : .jwtVC } ?? record.format,
            profileID: issued?.profileID ?? record.profileID,
            issuerIdentifier: issued?.issuerIdentifier ?? record.issuerIdentifier,
            subjectIdentifier: record.subjectIdentifier, holderBinding: record.holderBinding,
            cryptographicValidity: .valid, issuerTrust: record.issuerTrust,
            status: issued.map { $0.hasStatusReference ? .notEvaluated : .notProvided } ?? record.status,
            legalClassification: record.legalClassification, createdAt: record.createdAt,
            displayClaims: issued?.displayClaims ?? record.displayClaims,
            display: issued?.display ?? record.display, refresh: refresh,
            validFrom: issued?.validFrom ?? record.validFrom,
            validUntil: issued?.validUntil ?? record.validUntil
        )
    }

    func backfillCredentialValidity() async {
        guard let validity = try? await backend.storedCredentialValidity(),
              var records = try? await metadata.credentials() else { return }
        let byID = Dictionary(uniqueKeysWithValues: validity.map { ($0.credentialID.uuidString, $0) })
        for index in records.indices {
            let record = records[index]
            guard record.backendID == W3CBackendComposition.backendID,
                  let backendDocumentID = record.backendDocumentID,
                  let value = byID[backendDocumentID] else { continue }
            let validFrom = record.validFrom ?? value.validFrom
            let validUntil = record.validUntil ?? value.validUntil
            guard validFrom != record.validFrom || validUntil != record.validUntil else { continue }
            let updated = Self.copy(record, validFrom: validFrom, validUntil: validUntil)
            try? await metadata.replaceMetadata(updated)
            records[index] = updated
        }
    }

    private static func copy(
        _ record: CredentialRecord,
        validFrom: Date?,
        validUntil: Date?
    ) -> CredentialRecord {
        CredentialRecord(
            id: record.id, configurationID: record.configurationID,
            walletDocumentID: record.walletDocumentID, backendID: record.backendID,
            backendDocumentID: record.backendDocumentID, displayName: record.displayName,
            format: record.format, profileID: record.profileID,
            issuerIdentifier: record.issuerIdentifier, subjectIdentifier: record.subjectIdentifier,
            holderBinding: record.holderBinding, cryptographicValidity: record.cryptographicValidity,
            issuerTrust: record.issuerTrust, status: record.status,
            legalClassification: record.legalClassification, createdAt: record.createdAt,
            displayClaims: record.displayClaims, display: record.display, refresh: record.refresh,
            validFrom: validFrom, validUntil: validUntil
        )
    }
}
