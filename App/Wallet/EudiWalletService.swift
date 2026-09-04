import EudiWalletKitAdapter
import Foundation
import WalletDomain

protocol EudiWalletOperating: Sendable {
    var profileID: String { get async }
    func resolveIssuanceOffer(uri: String) async throws -> EudiIssuanceOffer
    func issueResolvedOffer(
        id: UUID,
        profileID: String,
        selectedConfigurationIDs: Set<String>,
        transactionCode: String?,
        promptMessage: String
    ) async throws -> EudiIssuanceResult
    func beginOpenID4VPPresentation(requestURI: String) async throws -> EudiPresentationRequest
    func beginPendingIssuancePresentation(id: UUID) async throws -> EudiPresentationRequest
    func completePresentation(
        id: UUID,
        pendingIssuanceID: UUID?,
        selectedOptionID: String?,
        selectedClaimIDs: Set<String>,
        userAccepted: Bool
    ) async throws -> EudiPresentationCompletion
    func loadDocumentSummaries() async throws -> [EudiWalletDocumentSummary]
    func loadStartupSnapshot() async throws -> EudiWalletStartupSnapshot
    func deleteDocument(id: String, status: String) async throws
    func retryDeferredIssuance(issuerName: String, documentID: String) async throws -> EudiWalletDocumentSummary
}

enum EudiPresentationCompletion: Equatable, Sendable {
    case presentation
    case pendingDeclined
    case issuance(EudiIssuanceResult)
    case externalAuthorization(String)
}

actor LiveEudiWalletService: EudiWalletOperating {
    private let adapter: EudiWalletKitAdapter
    init(adapter: EudiWalletKitAdapter) { self.adapter = adapter }
    var profileID: String { adapter.trustProfileID }

    func resolveIssuanceOffer(uri: String) async throws -> EudiIssuanceOffer {
        try await adapter.resolveIssuanceOffer(uri: uri)
    }
    func issueResolvedOffer(
        id: UUID,
        profileID: String,
        selectedConfigurationIDs: Set<String>,
        transactionCode: String?,
        promptMessage: String
    ) async throws -> EudiIssuanceResult {
        try await adapter.issueResolvedOffer(
            id: id,
            profileID: profileID,
            selectedConfigurationIDs: selectedConfigurationIDs,
            transactionCode: transactionCode,
            promptMessage: promptMessage
        )
    }
    func beginOpenID4VPPresentation(requestURI: String) async throws -> EudiPresentationRequest {
        try await adapter.beginOpenID4VPPresentation(requestURI: requestURI)
    }
    func beginPendingIssuancePresentation(id: UUID) async throws -> EudiPresentationRequest {
        try await adapter.beginPendingIssuancePresentation(id: id)
    }
    func completePresentation(
        id: UUID,
        pendingIssuanceID: UUID?,
        selectedOptionID: String?,
        selectedClaimIDs: Set<String>,
        userAccepted: Bool
    ) async throws -> EudiPresentationCompletion {
        let result = try await adapter.submitPresentation(
            id: id,
            selectedOptionID: selectedOptionID,
            selectedClaimIDs: selectedClaimIDs,
            userAccepted: userAccepted
        )
        if let code = result.authorizationCode { return .externalAuthorization(code) }
        guard let pendingIssuanceID else { return .presentation }
        guard userAccepted else { return .pendingDeclined }
        return .issuance(try await adapter.resumePendingIssuance(
            id: pendingIssuanceID,
            presentationResult: result
        ))
    }
    func loadDocumentSummaries() async throws -> [EudiWalletDocumentSummary] {
        try await adapter.loadDocumentSummaries()
    }
    func loadStartupSnapshot() async throws -> EudiWalletStartupSnapshot {
        try await adapter.loadStartupSnapshot()
    }
    func deleteDocument(id: String, status: String) async throws {
        try await adapter.deleteDocument(id: id, status: status)
    }
    func retryDeferredIssuance(issuerName: String, documentID: String) async throws -> EudiWalletDocumentSummary {
        try await adapter.retryDeferredIssuance(issuerName: issuerName, documentID: documentID)
    }
}

enum EudiWalletAvailability: Equatable, Sendable {
    case available
    case configurationRequired(String)
}
