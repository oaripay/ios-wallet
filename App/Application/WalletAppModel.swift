import Foundation
import EudiWalletKitAdapter
import EbsiW3CBackend
import ProtocolEngine
import SwiftUI
import WalletDomain
import WalletVault
import OariDesignSystem

@MainActor
final class WalletAppModel: ObservableObject {
    enum Tab: Hashable {
        case wallet
        case scan
        case history
        case settings
    }

    @Published private(set) var credentials: [CredentialRecord] = []
    @Published private(set) var deferredIssuances: [DeferredIssuance] = []
    @Published private(set) var checkingDeferredIssuanceIDs: Set<UUID> = []
    @Published private(set) var deferredSchedulerDeadline: Date?
    @Published private(set) var auditEvents: [AuditEvent] = []
    @Published private(set) var pendingExternalURL: URL?
    @Published private(set) var isAuditHistoryLoading = false
    @Published private(set) var hasLoadedAuditHistory = false
    @Published private(set) var deletingAuditEventIDs: Set<AuditEventID> = []
    @Published private(set) var isClearingAuditHistory = false
    @Published private(set) var auditHistoryError: String?
    @Published var theme: OariTheme {
        didSet { userDefaults.set(theme.rawValue, forKey: Self.themePreferenceKey) }
    }
    @Published var scanInput = ""
    @Published private(set) var scanResult: ScanResult = .idle
    @Published private(set) var loadingState: LoadingState = .idle
    @Published private(set) var appLockState: AppLockState
    @Published private(set) var requiresForegroundUnlock: Bool
    @Published private(set) var lifecyclePhase: AppLifecyclePhase = .active
    @Published private(set) var suppressesInactivePrivacyShield = false
    @Published private(set) var appLockAuthenticationKind: DeviceAuthenticationKind = .unavailable
    @Published private(set) var appLockSetupError: String?
    @Published var showsAppLockSetup = false
    @Published var selectedTab: Tab = .wallet
    @Published private(set) var eudiFlow: EudiFlow = .idle
    @Published var selectedIssuanceConfigurationIDs: Set<String> = []
    @Published var selectedClaimIDs: Set<String> = []
    @Published var selectedCredential: CredentialRecord?
    @Published private(set) var walletDocumentSummaries: [String: EudiWalletDocumentSummary] = [:]
    @Published private(set) var credentialActionState: CredentialActionState = .idle
    @Published var showsOnboarding: Bool
    @Published private(set) var eudiAvailability: EudiWalletAvailability = .configurationRequired("Loading wallet profile…")
    @Published private(set) var isEudiOperationLoading = false
    @Published var openID4VCTrustWarning: EbsiTrustWarning?
    private var openID4VCTransactionCode = ""
    private let allowedHosts: Set<String>
    private var eudiWallet: (any EudiWalletOperating)?
    private var eudiInitializationTask: Task<EudiInitializationResult, Never>?
    private var hasLoadedEudiStartupSnapshot = false
    private var activeEudiWaitID: UUID?
    private var openID4VCWallet: (any OpenID4VCOperating)?
    private var activeOpenID4VCInteractionID: UUID?
    private var activeOpenID4VPPresentationRequest: OpenID4VPPresentationRequest?
    private var activeOpenID4VCInteraction: OpenID4VCResolvedInteraction?
    private var activeOpenID4VCAllowsUntrusted = false
    private var pendingOpenID4VCSignerTrustWarning = false
    private var deferredSignerTrustWarningID: UUID?
    private var repositories: (credentials: any CredentialMetadataRepository, audit: any AuditRepository)?
    private var activePendingIssuanceID: UUID?
    private var activePendingIssuance: EudiPendingIssuance?
    private var activeIssuerAuthorizationPresentation = false
    private var activeStandaloneOpenID4VPPresentation = false
    private var appLockAuthenticator: (any AppLockAuthenticating)?
    private var backgroundGeneration = 0
    private var activeAuthenticationID: UUID?
    private var deferredSchedulerTask: Task<Void, Never>?
    private var webAuthorizationPollingTask: Task<Void, Never>?
    private(set) var autoReviewTask: Task<Void, Never>?
    private let userDefaults: UserDefaults

    private static let themePreferenceKey = "oari.appearance.theme"
    private static let appLockEnabledKey = "oari.security.app-lock.enabled"
    private static let appLockSetupCompletedKey = "oari.security.app-lock.setup-completed"

    init(
        allowedHosts: Set<String> = ["wallet.dev.oari.io"],
        showsOnboarding: Bool = false,
        userDefaults: UserDefaults = .standard
    ) {
        self.userDefaults = userDefaults
        let appLockEnabled = userDefaults.bool(forKey: Self.appLockEnabledKey)
        appLockState = appLockEnabled ? .locked(nil) : .disabled
        requiresForegroundUnlock = appLockEnabled
        theme = userDefaults.string(forKey: Self.themePreferenceKey)
            .flatMap(OariTheme.init(rawValue:)) ?? .system
        self.allowedHosts = allowedHosts
        self.showsOnboarding = showsOnboarding
    }

    enum AppLockState: Equatable {
        case disabled
        case locked(String?)
        case authenticating
        case unlocked
        case unavailable(String)
    }

    enum AppLifecyclePhase: Equatable {
        case active
        case inactive
        case background
    }

    enum LoadingState: Equatable {
        case idle
        case loading
        case loaded
        case failed(String)
    }

    var isAppLockEnabled: Bool { userDefaults.bool(forKey: Self.appLockEnabledKey) }
    var hasCompletedAppLockSetup: Bool { userDefaults.bool(forKey: Self.appLockSetupCompletedKey) }
    var appLockAuthenticationName: String { appLockAuthenticationKind.displayName }
    var appLockAuthenticationIcon: String {
        switch appLockAuthenticationKind {
        case .faceID: "faceid"
        case .touchID: "touchid"
        case .devicePasscode, .unavailable: "lock.shield.fill"
        }
    }
    var isAppLockBlocking: Bool {
        requiresForegroundUnlock
    }

    var shouldShowInactivePrivacyShield: Bool {
        lifecyclePhase != .active && !suppressesInactivePrivacyShield
    }
    var isPrivacyCoverVisible: Bool {
        lifecyclePhase == .background
    }

    enum ScanResult: Equatable {
        case idle
        case presentation
        case issuance
        case unsupported
        case rejected(String)
    }

    enum EudiFlow: Equatable {
        case idle
        case working(String)
        case issuanceReview(EudiIssuanceOffer)
        case presentationConsent(EudiPresentationRequest)
        case pending(EudiPendingIssuance)
        case completed(String)
        case failed(String)
        case configurationRequired(String)
        case openID4VCIssuanceReview(OpenID4VCResolvedInteraction)
        case openID4VPPresentationRequired(OpenID4VPPresentationRequest)
    }

    enum CredentialActionState: Equatable {
        case idle
        case working(String)
        case completed(String)
        case failed(String)
    }

    var credentialCountDescription: String {
        switch credentials.count {
        case 0: "No credentials"
        case 1: "1 credential"
        default: "\(credentials.count) credentials"
        }
    }

    func load(
        credentials repository: any CredentialMetadataRepository,
        audit auditRepository: any AuditRepository
    ) async throws {
        credentials = try await repository.credentials()
        auditEvents = try await auditRepository.events().sorted { $0.occurredAt > $1.occurredAt }
        hasLoadedAuditHistory = true
    }

    func load(_ dependencies: Result<WalletAppDependencies, Error>) async {
        loadingState = .loading
        do {
            let dependencies = try dependencies.get()
            eudiWallet = dependencies.eudiWallet
            eudiAvailability = dependencies.eudiAvailability
            openID4VCWallet = dependencies.openID4VCWallet
            appLockAuthenticator = dependencies.appLockAuthenticator
            appLockAuthenticationKind = dependencies.appLockAuthenticator.availability()
            repositories = (dependencies.credentials, dependencies.audit)
            if isEudiOperational, let eudiWallet {
                let snapshot = try await eudiWallet.loadStartupSnapshot()
                credentials = snapshot.metadata.isEmpty
                    ? try await dependencies.credentials.credentials()
                    : snapshot.metadata
                walletDocumentSummaries = Dictionary(
                    uniqueKeysWithValues: snapshot.documents.map { ($0.id, $0) }
                )
                if let pending = snapshot.pendingIssuances.first {
                    activePendingIssuanceID = pending.id
                    activePendingIssuance = pending
                    eudiFlow = .pending(pending)
                }
            } else {
                credentials = try await dependencies.credentials.credentials()
                if case let .configurationRequired(message) = dependencies.eudiAvailability {
                    eudiFlow = .configurationRequired(message)
                }
            }
            loadingState = .loaded
            await refreshDeferredIssuances()
            if canPollDeferredIssuances { await resumeDeferredIssuances() }
            if let initializer = dependencies.eudiInitializer {
                startEudiInitialization(using: initializer)
            }
            if isAppLockEnabled {
                Task { await unlockApp() }
                await Task.yield()
            } else if !showsOnboarding && !hasCompletedAppLockSetup {
                showsAppLockSetup = true
            }
        } catch {
            loadingState = .failed("Wallet setup failed: \(Self.setupErrorMessage(error))")
        }
    }

    private func startEudiInitialization(using initializer: @escaping WalletAppDependencies.EudiInitializer) {
        guard eudiInitializationTask == nil, eudiWallet == nil else { return }
        let task = Task { await initializer() }
        eudiInitializationTask = task
        Task {
            let result = await task.value
            await finishEudiInitialization(result)
        }
    }

    private func finishEudiInitialization(_ result: EudiInitializationResult) async {
        guard eudiWallet == nil else { return }
        switch result {
        case let .success(wallet):
            eudiWallet = wallet
            eudiAvailability = .available
            eudiInitializationTask = nil
            await loadEudiStartupSnapshot(from: wallet)
        case let .failure(message):
            eudiInitializationTask = nil
            eudiAvailability = .configurationRequired("EUDI Reference Demo is unavailable: \(message)")
        }
    }

    private func loadEudiStartupSnapshot(from wallet: any EudiWalletOperating) async {
        guard !hasLoadedEudiStartupSnapshot else { return }
        hasLoadedEudiStartupSnapshot = true
        do {
            let snapshot = try await wallet.loadStartupSnapshot()
            if !snapshot.metadata.isEmpty { credentials = snapshot.metadata }
            walletDocumentSummaries = Dictionary(
                uniqueKeysWithValues: snapshot.documents.map { ($0.id, $0) }
            )
            if let pending = snapshot.pendingIssuances.first {
                activePendingIssuanceID = pending.id
                activePendingIssuance = pending
                if case .configurationRequired = eudiFlow { eudiFlow = .pending(pending) }
            } else if case .configurationRequired = eudiFlow {
                eudiFlow = .idle
            }
        } catch {
            // The service remains usable for new requests when an existing
            // document snapshot cannot be loaded.
        }
    }

    private func requireEudiWallet() async throws -> any EudiWalletOperating {
        if let eudiWallet { return eudiWallet }
        guard let task = eudiInitializationTask else {
            throw EudiReadinessError.unavailable
        }
        let waitID = UUID()
        activeEudiWaitID = waitID
        isEudiOperationLoading = true
        Task {
            try? await Task.sleep(for: .seconds(15))
            guard activeEudiWaitID == waitID else { return }
            activeEudiWaitID = nil
            isEudiOperationLoading = false
            eudiFlow = .failed("EUDI Wallet Kit is taking longer than expected. Try the request again.")
        }
        let result = await task.value
        guard activeEudiWaitID == waitID else { throw EudiReadinessError.timedOut }
        activeEudiWaitID = nil
        isEudiOperationLoading = false
        switch result {
        case let .success(wallet):
            if eudiWallet == nil {
                eudiWallet = wallet
                eudiAvailability = .available
                eudiInitializationTask = nil
                Task { await loadEudiStartupSnapshot(from: wallet) }
            }
            return wallet
        case let .failure(message):
            eudiInitializationTask = nil
            eudiAvailability = .configurationRequired("EUDI Reference Demo is unavailable: \(message)")
            throw EudiReadinessError.initializationFailed(message)
        }
    }

    private enum EudiReadinessError: LocalizedError {
        case unavailable
        case timedOut
        case initializationFailed(String)

        var errorDescription: String? {
            switch self {
            case .unavailable: "EUDI Reference Demo is unavailable."
            case .timedOut: "EUDI Wallet Kit is taking longer than expected. Try the request again."
            case let .initializationFailed(message): "EUDI Reference Demo initialization failed: \(message)"
            }
        }
    }

    func configureAppLock(enabled: Bool) async {
        guard let appLockAuthenticator else { return }
        if enabled {
            appLockSetupError = nil
            appLockState = .authenticating
            let requestID = UUID()
            let generation = backgroundGeneration
            activeAuthenticationID = requestID
            do {
                try await appLockAuthenticator.authenticateAppLock(
                    reason: "Enable \(appLockAuthenticationName) to protect Oari Wallet"
                )
                guard activeAuthenticationID == requestID,
                      backgroundGeneration == generation,
                      lifecyclePhase != .background else { return }
                activeAuthenticationID = nil
                userDefaults.set(true, forKey: Self.appLockEnabledKey)
                userDefaults.set(true, forKey: Self.appLockSetupCompletedKey)
                requiresForegroundUnlock = false
                appLockState = .unlocked
                showsAppLockSetup = false
                await resumeDeferredIssuances()
            } catch {
                guard activeAuthenticationID == requestID else { return }
                activeAuthenticationID = nil
                appLockState = .disabled
                await resumeDeferredIssuances()
                appLockSetupError = "Authentication was cancelled or failed. Try again to enable app lock."
            }
        } else if isAppLockEnabled {
            appLockState = .authenticating
            let requestID = UUID()
            let generation = backgroundGeneration
            activeAuthenticationID = requestID
            do {
                try await appLockAuthenticator.authenticateAppLock(
                    reason: "Authenticate to disable Oari Wallet app lock"
                )
                guard activeAuthenticationID == requestID,
                      backgroundGeneration == generation,
                      lifecyclePhase != .background else { return }
                activeAuthenticationID = nil
                userDefaults.set(false, forKey: Self.appLockEnabledKey)
                userDefaults.set(true, forKey: Self.appLockSetupCompletedKey)
                requiresForegroundUnlock = false
                appLockState = .disabled
                await resumeDeferredIssuances()
            } catch {
                guard activeAuthenticationID == requestID else { return }
                activeAuthenticationID = nil
                appLockState = .locked("Authentication is required to change app lock.")
            }
        }
    }

    func declineAppLockSetup() {
        userDefaults.set(false, forKey: Self.appLockEnabledKey)
        userDefaults.set(true, forKey: Self.appLockSetupCompletedKey)
        requiresForegroundUnlock = false
        appLockState = .disabled
        appLockSetupError = nil
        showsAppLockSetup = false
        scheduleDeferredIssuances()
    }

    func unlockApp() async {
        guard isAppLockEnabled else {
            requiresForegroundUnlock = false
            appLockState = .disabled
            return
        }
        guard let appLockAuthenticator else {
            appLockState = .locked(nil)
            return
        }
        guard appLockState != .authenticating else { return }
        guard lifecyclePhase != .background else {
            appLockState = .locked(nil)
            return
        }
        appLockAuthenticationKind = appLockAuthenticator.availability()
        guard appLockAuthenticationKind != .unavailable else {
            appLockState = .unavailable("Set a device passcode to unlock Oari Wallet.")
            return
        }
        let requestID = UUID()
        let generation = backgroundGeneration
        activeAuthenticationID = requestID
        appLockState = .authenticating
        do {
            try await appLockAuthenticator.authenticateAppLock(reason: "Unlock Oari Wallet")
            guard activeAuthenticationID == requestID,
                  backgroundGeneration == generation,
                  lifecyclePhase != .background,
                  isAppLockEnabled else { return }
            activeAuthenticationID = nil
            requiresForegroundUnlock = false
            appLockState = .unlocked
            await resumeDeferredIssuances()
        } catch {
            guard activeAuthenticationID == requestID else { return }
            activeAuthenticationID = nil
            appLockState = .locked("Authentication was cancelled or failed.")
        }
    }

    func handleScenePhase(_ phase: AppLifecyclePhase) async {
        guard phase != lifecyclePhase else { return }
        lifecyclePhase = phase
        switch phase {
        case .inactive:
            // System authentication and permissions temporarily make the scene inactive.
            // Cover the snapshot, but do not create a new lock boundary.
            return
        case .background:
            stopDeferredScheduler()
            backgroundGeneration += 1
            activeAuthenticationID = nil
            suppressesInactivePrivacyShield = false
            requiresForegroundUnlock = isAppLockEnabled
            appLockState = isAppLockEnabled ? .locked(nil) : .disabled
        case .active:
            suppressesInactivePrivacyShield = false
            guard isAppLockEnabled else {
                requiresForegroundUnlock = false
                appLockState = .disabled
                await resumeDeferredIssuances()
                return
            }
            guard requiresForegroundUnlock, appLockState != .authenticating else { return }
            await unlockApp()
        }
    }

    func loadAuditHistoryIfNeeded() async {
        guard !hasLoadedAuditHistory, !isAuditHistoryLoading, let repositories else { return }
        isAuditHistoryLoading = true
        defer { isAuditHistoryLoading = false }
        do {
            auditEvents = try await repositories.audit.events().sorted { $0.occurredAt > $1.occurredAt }
            hasLoadedAuditHistory = true
        } catch {
            auditEvents = []
        }
    }

    @discardableResult
    func deleteAuditEvent(id: AuditEventID) async -> Bool {
        guard !deletingAuditEventIDs.contains(id), !isClearingAuditHistory, let repositories else { return false }
        deletingAuditEventIDs.insert(id)
        defer { deletingAuditEventIDs.remove(id) }
        do {
            try await authenticateForActivityDeletion(reason: "Remove this activity from Oari Wallet")
            try await repositories.audit.delete(id: id)
            auditEvents.removeAll { $0.id == id }
            return true
        } catch {
            auditHistoryError = "The activity could not be removed."
            return false
        }
    }

    func clearAllActivity() async {
        guard !isClearingAuditHistory, deletingAuditEventIDs.isEmpty, let repositories else { return }
        isClearingAuditHistory = true
        defer { isClearingAuditHistory = false }
        do {
            try await authenticateForActivityDeletion(reason: "Clear all activity from Oari Wallet")
            try await repositories.audit.deleteAll()
            auditEvents = []
        } catch {
            auditHistoryError = "Activity could not be cleared."
        }
    }

    func dismissAuditHistoryError() {
        auditHistoryError = nil
    }

    private func authenticateForActivityDeletion(reason: String) async throws {
        guard isAppLockEnabled else { return }
        guard let appLockAuthenticator,
              appLockAuthenticator.availability() != .unavailable else {
            throw WalletRepositoryError.storageFailure
        }
        let generation = backgroundGeneration
        suppressesInactivePrivacyShield = true
        defer { suppressesInactivePrivacyShield = false }
        try await appLockAuthenticator.authenticateAppLock(reason: reason)
        guard generation == backgroundGeneration, lifecyclePhase != .background else {
            throw CancellationError()
        }
    }

    func classifyScan() {
        do {
            switch try ProtocolInputClassifier(allowedHosts: allowedHosts).classify(scanInput) {
            case .openID4VP: scanResult = .presentation
            case .openID4VCI: scanResult = .issuance
            case .eudiOpenID4VP: scanResult = .presentation
            case .eudiOpenID4VCI: scanResult = .issuance
            case .eudiAuthorizationCallback: scanResult = .idle
            case .unsupported: scanResult = .unsupported
            }
        } catch {
            scanResult = .rejected("The code is malformed or is not from an approved host.")
        }
    }

    func handleIncomingURL(_ url: URL) {
        // This scheme is reserved for Wallet Kit's authorization-session
        // callback. Even a malformed or stale callback must never be surfaced
        // to the user as a scanner request.
        guard url.scheme?.lowercased() != "eu.europa.ec.euidi" else { return }
        handleScannedCode(url.absoluteString)
    }

    func clearPendingExternalURL() {
        pendingExternalURL = nil
    }

    func handleScannedCode(_ code: String) {
        scanInput = code
        classifyScan()
        selectedTab = .scan
        // A scan that classified as a credential offer or presentation
        // request enters the review flow immediately instead of waiting
        // for a manual redeem action. Requests are only auto-entered when a
        // wallet backend exists (or is still initializing); otherwise the
        // scanner keeps showing the configuration-required guidance instead
        // of a guaranteed failure sheet.
        guard scanResult == .issuance || scanResult == .presentation,
              canAutoEnterScannedRequest else { return }
        autoReviewTask?.cancel()
        autoReviewTask = Task { [weak self] in
            await self?.reviewScannedRequest()
        }
    }

    private var canAutoEnterScannedRequest: Bool {
        isEudiOperational || eudiInitializationTask != nil || openID4VCWallet != nil
    }

    func reviewScannedRequest() async {
        webAuthorizationPollingTask?.cancel()
        webAuthorizationPollingTask = nil
        classifyScan()
        do {
            let route = try ProtocolInputClassifier(allowedHosts: allowedHosts).classify(scanInput)
            switch route {
            case .openID4VCI, .eudiOpenID4VCI:
                eudiFlow = .working("Checking the issuer and credential offer…")
                if case .eudiOpenID4VCI = route {
                    let eudiWallet = try await requireEudiWallet()
                    let offer = try await eudiWallet.resolveIssuanceOffer(uri: scanInput)
                    selectedIssuanceConfigurationIDs = Set(offer.documents.map(\.configurationID))
                    eudiFlow = .issuanceReview(offer)
                    return
                }
                var w3cRoutingError: Error?
                if let openID4VCWallet {
                    do {
                        let interaction = try await openID4VCWallet.resolveInteraction(uri: scanInput)
                        activeOpenID4VCInteractionID = interaction.id
                        activeOpenID4VCInteraction = interaction
                        switch interaction.trustOutcome {
                        case .allow: prepareOpenID4VCInteraction(allowUntrusted: false)
                        case let .requireExplicitWarning(warning): openID4VCTrustWarning = warning; eudiFlow = .idle
                        case .reject: throw OpenID4VCBackendError.rejectedTrust
                        }
                        return
                    } catch {
                        if case OpenID4VCBackendError.unsupportedGrant = error {
                            // The offer advertises a non-W3C format; let Wallet Kit claim it.
                        } else {
                            w3cRoutingError = error
                        }
                    }
                }
                if let w3cRoutingError {
                    guard let eudiWallet, isEudiOperational else {
                        throw w3cRoutingError
                    }
                    do {
                        let offer = try await eudiWallet.resolveIssuanceOffer(uri: scanInput)
                        selectedIssuanceConfigurationIDs = Set(offer.documents.map(\.configurationID))
                        eudiFlow = .issuanceReview(offer)
                    } catch {
                        throw w3cRoutingError
                    }
                    return
                }
                if openID4VCWallet == nil {
                    guard let eudiWallet, isEudiOperational else {
                        throw EbsiCredentialError.backendUnavailable
                    }
                    let offer = try await eudiWallet.resolveIssuanceOffer(uri: scanInput)
                    selectedIssuanceConfigurationIDs = Set(offer.documents.map(\.configurationID))
                    eudiFlow = .issuanceReview(offer)
                }
                // W3C resolved the offer and owns the remaining issuance flow.
                return
            case .openID4VP, .eudiOpenID4VP:
                eudiFlow = .working("Checking the verifier and requested claims…")
                activePendingIssuanceID = nil
                let isEudiOwned: Bool
                if case .eudiOpenID4VP = route { isEudiOwned = true } else { isEudiOwned = false }
                if !isEudiOwned, let openID4VCWallet {
                    do {
                        let request = try await openID4VCWallet.beginPresentation(uri: scanInput)
                        activeOpenID4VCInteractionID = request.id
                        activeStandaloneOpenID4VPPresentation = true
                        selectedClaimIDs = Set(request.claims.filter(\.required).map(\.id))
                        eudiFlow = .presentationConsent(request)
                        return
                    } catch EbsiCredentialError.unsupportedRepresentation {
                        // Non-W3C presentation formats are owned by Wallet Kit.
                    }
                }
                let eudiWallet = try await requireEudiWallet()
                let request = try await eudiWallet.beginOpenID4VPPresentation(requestURI: scanInput)
                selectedClaimIDs = Set(request.claims.filter(\.required).map(\.id))
                eudiFlow = .presentationConsent(request)
            case .eudiAuthorizationCallback, .unsupported:
                break
            }
        } catch {
            eudiFlow = .failed(Self.safeMessage(error))
        }
    }

    func continueAfterOpenID4VCTrustWarning() async {
        guard openID4VCTrustWarning != nil else { return }
        if let id = deferredSignerTrustWarningID {
            openID4VCTrustWarning = nil
            deferredSignerTrustWarningID = nil
            await checkDeferredIssuance(id: id, allowUntrustedSigner: true)
            return
        }
        guard activeOpenID4VCInteractionID != nil else { return }
        openID4VCTrustWarning = nil
        if pendingOpenID4VCSignerTrustWarning {
            pendingOpenID4VCSignerTrustWarning = false
            activeOpenID4VCAllowsUntrusted = true
            do {
                try await continueOpenID4VCInteraction()
                try await refreshWalletState()
            } catch {
                if let id = activeOpenID4VCInteractionID { await openID4VCWallet?.cancelInteraction(id: id) }
                activeOpenID4VCInteractionID = nil
                activeOpenID4VCInteraction = nil
                eudiFlow = .failed(Self.safeMessage(error))
            }
            return
        }
        prepareOpenID4VCInteraction(allowUntrusted: true)
    }

    func cancelOpenID4VCTrustWarning() async {
        if deferredSignerTrustWarningID != nil {
            deferredSignerTrustWarningID = nil
            openID4VCTrustWarning = nil
            return
        }
        let id = activeOpenID4VCInteractionID
        openID4VCTrustWarning = nil
        pendingOpenID4VCSignerTrustWarning = false
        activeOpenID4VCInteractionID = nil
        activeOpenID4VCInteraction = nil
        webAuthorizationPollingTask?.cancel()
        webAuthorizationPollingTask = nil
        if let id { await openID4VCWallet?.cancelInteraction(id: id) }
        eudiFlow = .completed("Wallet request cancelled. Nothing was shared or stored.")
    }

    func issueReviewedOpenID4VCCredential(transactionCode: String? = nil) async {
        openID4VCTransactionCode = transactionCode ?? ""
        do {
            try await continueOpenID4VCInteraction()
            try await refreshWalletState()
        }
        catch {
            if let id = activeOpenID4VCInteractionID { await openID4VCWallet?.cancelInteraction(id: id) }
            activeOpenID4VCInteractionID = nil
            activeOpenID4VCInteraction = nil
            eudiFlow = .failed(Self.safeMessage(error))
        }
    }

    func startEudiCredentialPresentation(_ challenge: OpenID4VPPresentationRequest) async {
        guard activeOpenID4VCInteractionID == challenge.id else {
            eudiFlow = .failed("The issuer authorization challenge is stale. Start the credential offer again.")
            return
        }
        activeOpenID4VPPresentationRequest = challenge
        let requestedVCTs = Self.requestedVCTs(in: challenge.dcqlQuery)
        let requestedFormats = Self.requestedFormats(in: challenge.dcqlQuery)
        let hasMatchingEudiPID = requestedVCTs.isEmpty || walletDocumentSummaries.values.contains { document in
            document.status == "issued" && requestedVCTs.contains(document.documentType)
        }
        let requestsW3CCredential = requestedFormats.contains {
            $0 == "dc+sd-jwt" || $0 == "jwt_vc_json" || $0 == "jwt_vc_json-ld"
        }
        if requestsW3CCredential || !hasMatchingEudiPID {
            guard let id = activeOpenID4VCInteractionID, let openID4VCWallet else {
                eudiFlow = .failed("The issuer authorization transaction expired before PID selection.")
                return
            }
            do {
                eudiFlow = .working("Preparing W3C PID presentation…")
                let request = try await openID4VCWallet.preparePIDPresentation(id: id)
                activeIssuerAuthorizationPresentation = true
                selectedClaimIDs = Set(request.claims.filter(\.required).map(\.id))
                eudiFlow = .presentationConsent(request)
            } catch {
                eudiFlow = .failed(Self.safeMessage(error))
            }
            return
        }
        guard let eudiWallet else {
            eudiFlow = .configurationRequired("EUDI Wallet Kit is not configured for PID presentation.")
            return
        }
        activeIssuerAuthorizationPresentation = false
        guard let signedRequest = challenge.signedRequest else {
            eudiFlow = .failed("The issuer did not provide the signed PID presentation request required by Wallet Kit.")
            return
        }
        var components = URLComponents()
        components.scheme = "openid4vp"
        components.host = "authorize"
        components.queryItems = [URLQueryItem(name: "request", value: signedRequest)]
        guard let requestURI = components.url?.absoluteString else {
            eudiFlow = .failed("The issuer returned an invalid PID presentation request.")
            return
        }
        do {
            eudiFlow = .working("Preparing PID presentation…")
            let request = try await eudiWallet.beginOpenID4VPPresentation(requestURI: requestURI)
            selectedClaimIDs = Set(request.claims.filter(\.required).map(\.id))
            eudiFlow = .presentationConsent(request)
        } catch {
            eudiFlow = .failed(Self.safeMessage(error))
        }
    }

    private func finishWebAuthorization(code: String) async {
        pendingExternalURL = nil
        webAuthorizationPollingTask = nil
        do {
            guard let id = activeOpenID4VCInteractionID, let openID4VCWallet else { throw CancellationError() }
            let result = try await openID4VCWallet.completeAuthorization(id: id, code: code)
            await handleOpenID4VCCompletion(result)
        } catch { eudiFlow = .failed(Self.safeMessage(error)) }
    }

    private func handleOpenID4VCCompletion(_ result: OpenID4VCInteractionCompletion) async {
        switch result {
        case .completed:
            finishCredentialRedemption()
        case .pending:
            activeOpenID4VCInteractionID = nil
            activeOpenID4VCInteraction = nil
            await refreshDeferredIssuances()
            selectedTab = .wallet
            eudiFlow = .idle
        case let .presentationRequired(challenge):
            activeOpenID4VPPresentationRequest = challenge
            eudiFlow = .openID4VPPresentationRequired(challenge)
        case let .webAuthorizationRequired(challenge):
            pendingExternalURL = challenge.authorizationURL
            eudiFlow = .working("Waiting for issuer authentication…")
            startWebAuthorizationPolling(id: challenge.id)
        case let .credentialSignerTrustWarning(warning):
            pendingOpenID4VCSignerTrustWarning = true
            openID4VCTrustWarning = warning
            eudiFlow = .idle
        }
    }

    private func prepareOpenID4VCInteraction(allowUntrusted: Bool) {
        guard let interaction = activeOpenID4VCInteraction else {
            eudiFlow = .failed("The credential transaction expired before consent.")
            return
        }
        activeOpenID4VCAllowsUntrusted = allowUntrusted
        openID4VCTransactionCode = ""
        eudiFlow = .openID4VCIssuanceReview(interaction)
    }

    private func continueOpenID4VCInteraction() async throws {
        guard let id = activeOpenID4VCInteractionID, let openID4VCWallet else {
            throw EbsiCredentialError.backendUnavailable
        }
        eudiFlow = .working("Continuing credential issuance…")
        let result = try await openID4VCWallet.continueInteraction(
            id: id,
            allowUntrusted: activeOpenID4VCAllowsUntrusted,
            transactionCode: openID4VCTransactionCode.isEmpty ? nil : openID4VCTransactionCode
        )
        await handleOpenID4VCCompletion(result)
    }

    private func startWebAuthorizationPolling(id: UUID) {
        guard let openID4VCWallet else { return }
        webAuthorizationPollingTask?.cancel()
        webAuthorizationPollingTask = Task { [weak self] in
            let deadline = Date().addingTimeInterval(5 * 60)
            do {
                while !Task.isCancelled && Date() < deadline {
                    switch try await openID4VCWallet.pollWebAuthorization(id: id) {
                    case .pending:
                        try await Task.sleep(for: .seconds(2))
                        continue
                    case let .authorizationCode(code):
                        await self?.finishWebAuthorization(code: code)
                        return
                    case let .failed(error):
                        self?.eudiFlow = .failed("Issuer authentication failed: \(error)")
                        self?.webAuthorizationPollingTask = nil
                        return
                    }
                }
                if !Task.isCancelled {
                    self?.eudiFlow = .failed("Issuer authentication timed out. Start the credential offer again.")
                    self?.webAuthorizationPollingTask = nil
                }
            } catch is CancellationError {
                return
            } catch {
                self?.eudiFlow = .failed(Self.safeMessage(error))
                self?.webAuthorizationPollingTask = nil
            }
        }
    }

    func acceptIssuance(transactionCode: String?) async {
        guard isEudiOperational, case let .issuanceReview(offer) = eudiFlow, let eudiWallet else {
            eudiFlow = .configurationRequired(eudiConfigurationMessage)
            return
        }
        eudiFlow = .working("Adding the credential securely…")
        do {
            let result = try await eudiWallet.issueResolvedOffer(
                id: offer.id,
                profileID: await eudiWallet.profileID,
                selectedConfigurationIDs: selectedIssuanceConfigurationIDs,
                transactionCode: transactionCode,
                promptMessage: "Authenticate to add this credential to Oari Wallet"
            )
            try await refreshWalletState()
            if let pending = result.pendingIssuances.first {
                activePendingIssuanceID = pending.id
                activePendingIssuance = pending
                eudiFlow = .pending(pending)
            } else {
                finishCredentialRedemption()
            }
        } catch {
            eudiFlow = .failed(Self.safeMessage(error))
        }
    }

    func continuePendingIssuance() async {
        guard isEudiOperational, case let .pending(pending) = eudiFlow, let eudiWallet else {
            eudiFlow = .configurationRequired(eudiConfigurationMessage)
            return
        }
        eudiFlow = .working("Preparing PID verification…")
        do {
            activePendingIssuanceID = pending.id
            activePendingIssuance = pending
            let request = try await eudiWallet.beginPendingIssuancePresentation(id: pending.id)
            selectedClaimIDs = Set(request.claims.filter(\.required).map(\.id))
            eudiFlow = .presentationConsent(request)
        } catch {
            eudiFlow = .failed(Self.safeMessage(error))
        }
    }

    func submitPresentation(accepted: Bool) async {
        guard case let .presentationConsent(request) = eudiFlow else {
            eudiFlow = .configurationRequired(eudiConfigurationMessage)
            return
        }
        eudiFlow = .working(accepted ? "Sharing approved claims…" : "Declining the request…")
        do {
            if activeStandaloneOpenID4VPPresentation {
                guard let id = activeOpenID4VCInteractionID, let openID4VCWallet else {
                    throw EbsiCredentialError.backendUnavailable
                }
                let response = try await openID4VCWallet.completePresentation(
                    id: id,
                    selectedClaimIDs: accepted ? selectedClaimIDs : [],
                    userAccepted: accepted
                )
                pendingExternalURL = response
                activeStandaloneOpenID4VPPresentation = false
                activeOpenID4VCInteractionID = nil
                selectedClaimIDs = []
                eudiFlow = .completed(accepted ? "Approved claims were shared." : "Request declined. Nothing was shared.")
                return
            }
            if activeIssuerAuthorizationPresentation {
                guard let id = activeOpenID4VPPresentationRequest?.id,
                      id == activeOpenID4VCInteractionID,
                      let openID4VCWallet else {
                    throw EbsiCredentialError.backendUnavailable
                }
                let result = try await openID4VCWallet.completePIDPresentation(
                    id: id,
                    selectedClaimIDs: accepted ? selectedClaimIDs : [],
                    userAccepted: accepted
                )
                activeIssuerAuthorizationPresentation = false
                if accepted { try await refreshWalletState() }
                activeOpenID4VPPresentationRequest = nil
                await handleOpenID4VCCompletion(result)
                return
            }
            guard isEudiOperational, let eudiWallet else {
                eudiFlow = .configurationRequired(eudiConfigurationMessage)
                return
            }
            let completion = try await eudiWallet.completePresentation(
                id: request.id,
                pendingIssuanceID: activePendingIssuanceID,
                selectedClaimIDs: accepted ? selectedClaimIDs : [],
                userAccepted: accepted
            )
            switch completion {
            case let .issuance(result):
                try await refreshWalletState()
                if let pending = result.pendingIssuances.first {
                    activePendingIssuanceID = pending.id
                    activePendingIssuance = pending
                    eudiFlow = .pending(pending)
                } else {
                    activePendingIssuanceID = nil
                    activePendingIssuance = nil
                    finishCredentialRedemption()
                }
            case .pendingDeclined:
                if let activePendingIssuance {
                    eudiFlow = .pending(activePendingIssuance)
                } else {
                    eudiFlow = .failed("The pending credential could not be restored safely.")
                }
            case .presentation:
                activePendingIssuanceID = nil
                activePendingIssuance = nil
                eudiFlow = .completed(accepted ? "Approved claims were shared." : "Request declined. Nothing was shared.")
            case let .externalAuthorization(code):
                guard let id = activeOpenID4VPPresentationRequest?.id,
                      id == activeOpenID4VCInteractionID,
                      let openID4VCWallet else {
                    eudiFlow = .failed("The EBSI authorization transaction expired.")
                    return
                }
                let result = try await openID4VCWallet.completeAuthorization(id: id, code: code)
                try await refreshWalletState()
                switch result {
                case .completed:
                    activeOpenID4VCInteractionID = nil
                    activeOpenID4VCInteraction = nil
                    activeOpenID4VPPresentationRequest = nil
                    finishCredentialRedemption()
                case let .pending(message):
                    activeOpenID4VCInteractionID = nil
                    activeOpenID4VCInteraction = nil
                    activeOpenID4VPPresentationRequest = nil
                    eudiFlow = .completed(message)
                case .presentationRequired:
                    activeOpenID4VCInteractionID = nil
                    activeOpenID4VCInteraction = nil
                    activeOpenID4VPPresentationRequest = nil
                    eudiFlow = .failed("The issuer requested another unsupported presentation step.")
                case let .credentialSignerTrustWarning(warning):
                    pendingOpenID4VCSignerTrustWarning = true
                    openID4VCTrustWarning = warning
                    eudiFlow = .idle
                case let .webAuthorizationRequired(challenge):
                    pendingExternalURL = challenge.authorizationURL
                    eudiFlow = .working("Waiting for issuer authentication…")
                    startWebAuthorizationPolling(id: challenge.id)
                }
            }
        } catch {
            eudiFlow = .failed(Self.safeMessage(error))
        }
    }

    func dismissEudiFlow() {
        eudiFlow = .idle
    }

    func checkDeferredIssuance(id: UUID, allowUntrustedSigner: Bool = false) async {
        guard canPollDeferredIssuances,
              !checkingDeferredIssuanceIDs.contains(id),
              let issuance = deferredIssuances.first(where: { $0.id == id }),
              issuance.state == .signerTrustRequired || issuance.state == .completing
                || (issuance.state == .pending && issuance.nextAttemptAt <= Date()),
              let openID4VCWallet else { return }
        checkingDeferredIssuanceIDs.insert(id)
        defer { checkingDeferredIssuanceIDs.remove(id) }
        do {
            let result = try await openID4VCWallet.checkDeferredIssuance(
                id: id, allowUntrustedSigner: allowUntrustedSigner
            )
            switch result {
            case let .completed(message), let .pending(message):
                eudiFlow = .completed(message)
                try await refreshWalletState()
            case let .credentialSignerTrustWarning(warning):
                deferredSignerTrustWarningID = id
                openID4VCTrustWarning = warning
            case .presentationRequired:
                eudiFlow = .failed("Issuer authorization is required. Start the credential offer again.")
            case .webAuthorizationRequired:
                eudiFlow = .failed("The deferred credential returned an invalid authorization step.")
            }
        } catch {
            eudiFlow = .failed(Self.safeMessage(error))
        }
        await refreshDeferredIssuances()
    }

    func removeDeferredIssuance(id: UUID) async {
        do {
            try await openID4VCWallet?.removeDeferredIssuance(id: id)
            await refreshDeferredIssuances()
        } catch {
            eudiFlow = .failed(Self.safeMessage(error))
        }
    }

    private func resumeDeferredIssuances() async {
        guard canPollDeferredIssuances, let openID4VCWallet else {
            stopDeferredScheduler()
            return
        }
        await openID4VCWallet.resumeEligibleDeferredIssuances()
        await refreshDeferredIssuances()
        try? await refreshWalletState()
    }

    private func refreshDeferredIssuances() async {
        deferredIssuances = (try? await openID4VCWallet?.deferredIssuances()) ?? []
        scheduleDeferredIssuances()
    }

    private var canPollDeferredIssuances: Bool {
        lifecyclePhase == .active && (!isAppLockEnabled || (!requiresForegroundUnlock && appLockState == .unlocked))
    }

    private func scheduleDeferredIssuances() {
        stopDeferredScheduler()
        guard canPollDeferredIssuances,
              let deadline = deferredIssuances
                .filter({ $0.state == .pending })
                .map(\.nextAttemptAt)
                .min() else { return }
        deferredSchedulerDeadline = deadline
        deferredSchedulerTask = Task { [weak self] in
            let delay = max(0, deadline.timeIntervalSinceNow)
            try? await Task.sleep(for: .seconds(delay))
            guard !Task.isCancelled, let self else { return }
            await self.resumeDeferredIssuances()
        }
    }

    private func stopDeferredScheduler() {
        deferredSchedulerTask?.cancel()
        deferredSchedulerTask = nil
        deferredSchedulerDeadline = nil
    }

    private func finishCredentialRedemption() {
        webAuthorizationPollingTask?.cancel()
        webAuthorizationPollingTask = nil
        pendingExternalURL = nil
        scanInput = ""
        scanResult = .idle
        selectedTab = .wallet
        selectedIssuanceConfigurationIDs = []
        selectedClaimIDs = []
        openID4VCTransactionCode = ""
        activeOpenID4VCInteractionID = nil
        activeOpenID4VCInteraction = nil
        activeOpenID4VPPresentationRequest = nil
        activePendingIssuanceID = nil
        activePendingIssuance = nil
        activeIssuerAuthorizationPresentation = false
        activeStandaloneOpenID4VPPresentation = false
        eudiFlow = .idle
    }

    var hasRecoverablePendingIssuance: Bool { activePendingIssuance != nil }
    var isEudiOperational: Bool {
        eudiWallet != nil && eudiAvailability == .available
    }
    private var eudiConfigurationMessage: String {
        if case let .configurationRequired(message) = eudiAvailability { return message }
        return "EUDI wallet services are not configured for this environment."
    }

    var preventsInteractiveFlowDismissal: Bool {
        switch eudiFlow {
        case .working, .presentationConsent: true
        default: false
        }
    }

    func returnToPendingIssuance() {
        if let activePendingIssuance { eudiFlow = .pending(activePendingIssuance) }
    }

    func selectCredential(_ credential: CredentialRecord) {
        credentialActionState = .idle
        selectedCredential = credential
    }

    func deleteSelectedCredential() async {
        guard !credentialActionIsWorking, let credential = selectedCredential else { return }
        enum DeletionTarget {
            case eudi(documentID: String, service: any EudiWalletOperating)
            case w3c(backendID: UUID, service: any OpenID4VCOperating)
        }
        let target: DeletionTarget
        if W3CBackendComposition.ownsCredential(backendID: credential.backendID) {
            guard let backendID = credential.backendDocumentID.flatMap(UUID.init(uuidString:)),
                  let openID4VCWallet else {
                credentialActionState = .failed("This W3C credential has no valid backend reference.")
                return
            }
            target = .w3c(backendID: backendID, service: openID4VCWallet)
        } else {
            guard isEudiOperational, let documentID = credential.walletDocumentID, let eudiWallet else {
                credentialActionState = .failed("Wallet Kit is unavailable or the credential document reference is missing.")
                return
            }
            target = .eudi(documentID: documentID, service: eudiWallet)
        }
        guard let appLockAuthenticator,
              appLockAuthenticator.availability() != .unavailable else {
            credentialActionState = .failed("Device authentication is required to remove this credential.")
            return
        }
        credentialActionState = .working("Authenticating…")
        let deletionGeneration = backgroundGeneration
        suppressesInactivePrivacyShield = true
        defer { suppressesInactivePrivacyShield = false }
        do {
            try await appLockAuthenticator.authenticateAppLock(
                reason: "Remove this credential from Oari Wallet"
            )
            guard backgroundGeneration == deletionGeneration,
                  lifecyclePhase != .background else {
                credentialActionState = .failed("Credential removal was cancelled when the app left the foreground.")
                return
            }
            credentialActionState = .working("Removing credential…")
            switch target {
            case let .eudi(documentID, service):
                try await service.deleteDocument(
                    id: documentID,
                    status: walletDocumentSummaries[documentID]?.status ?? "issued"
                )
            case let .w3c(backendID, service):
                try await service.deleteCredential(
                    backendID: backendID,
                    metadataID: credential.id,
                    issuerIdentifier: credential.issuerIdentifier
                )
            }
            try await refreshWalletState()
            selectedCredential = nil
            credentialActionState = .completed("Credential removed.")
        } catch {
            if credentialActionState == .working("Authenticating…") {
                credentialActionState = .failed("Authentication is required to remove this credential.")
            } else {
                credentialActionState = .failed(Self.safeMessage(error))
            }
        }
    }

    func canDeleteCredential(_ credential: CredentialRecord) -> Bool {
        if W3CBackendComposition.ownsCredential(backendID: credential.backendID) {
            return openID4VCWallet != nil && credential.backendDocumentID.flatMap(UUID.init(uuidString:)) != nil
        }
        return isEudiOperational && credential.walletDocumentID != nil
    }

    func retrySelectedDeferredCredential() async {
        guard isEudiOperational, !credentialActionIsWorking,
              let credential = selectedCredential,
              let documentID = credential.walletDocumentID,
              let eudiWallet else { return }
        credentialActionState = .working("Checking deferred issuance…")
        do {
            let summary = try await eudiWallet.retryDeferredIssuance(
                issuerName: credential.issuerIdentifier,
                documentID: documentID
            )
            try await refreshWalletState()
            walletDocumentSummaries[summary.id] = summary
            credentialActionState = summary.status == "issued"
                ? .completed("Credential issuance completed.")
                : .completed("Credential is still pending at the issuer.")
        } catch {
            credentialActionState = .failed(Self.safeMessage(error))
        }
    }

    func dismissCredentialAction() { credentialActionState = .idle }
    var credentialActionIsWorking: Bool {
        if case .working = credentialActionState { true } else { false }
    }
    func acknowledgeCredentialAction() {
        if case .completed = credentialActionState,
           let selectedCredential,
           !credentials.contains(where: { $0.id == selectedCredential.id }) {
            self.selectedCredential = nil
        }
        credentialActionState = .idle
    }

    func documentStatus(for credential: CredentialRecord) -> String? {
        credential.walletDocumentID.flatMap { walletDocumentSummaries[$0]?.status }
    }

    func completeOnboarding() {
        guard hasCompletedAppLockSetup else { return }
        userDefaults.set(true, forKey: "oari.onboarding.completed")
        showsOnboarding = false
    }

    private func refreshWalletState() async throws {
        guard let repositories else { return }
        try await load(credentials: repositories.credentials, audit: repositories.audit)
        await refreshDeferredIssuances()
        if let eudiWallet {
            walletDocumentSummaries = Dictionary(
                uniqueKeysWithValues: try await eudiWallet.loadDocumentSummaries().map { ($0.id, $0) }
            )
        }
    }

    private static func requestedVCTs(
        in dcqlQuery: [String: AnySendableJSON]
    ) -> Set<String> {
        guard case let .array(credentials)? = dcqlQuery["credentials"] else { return [] }
        return Set(credentials.flatMap { credential -> [String] in
            guard case let .object(query) = credential,
                  case let .object(meta)? = query["meta"],
                  case let .array(values)? = meta["vct_values"] else {
                return []
            }
            return values.compactMap {
                if case let .string(value) = $0 { return value }
                return nil
            }
        })
    }

    private static func requestedFormats(
        in dcqlQuery: [String: AnySendableJSON]
    ) -> Set<String> {
        guard case let .array(credentials)? = dcqlQuery["credentials"] else { return [] }
        return Set(credentials.compactMap { credential in
            guard case let .object(query) = credential,
                  case let .string(format)? = query["format"] else { return nil }
            return format
        })
    }

    private static func safeMessage(_ error: Error) -> String {
        if let error = error as? OpenID4VCBackendError {
            switch error {
            case .malformedOffer: return "The issuer offer is malformed or missing a credential offer payload."
            case .unsafeEndpoint: return "The issuer endpoint is not an allowed HTTPS endpoint."
            case .unsupportedGrant: return "This issuer grant is not supported by the wallet."
            case .invalidTransactionCode: return "The transaction code is invalid for this offer."
            case .untrustedConsentRequired: return "Review the issuer trust warning before continuing."
            case .rejectedTrust: return "The issuer request failed trust or signature validation."
            case .credentialSignerTrustWarning:
                return "The credential signer could not be resolved or accredited. Review the warning before storing the credential."
            case .deferredCredentialPending:
                return "Credential issuance is pending at the issuer."
            case let .deferredCredentialNotReady(nextPollAt):
                return "The credential can be checked after \(nextPollAt.formatted(date: .omitted, time: .shortened))."
            case .deferredCredentialSignerTrustWarning:
                return "The deferred credential signer requires your review before storage."
            case .invalidResponse: return "The issuer returned an invalid or incomplete OpenID4VCI response."
            case .missingCredentialNonce:
                return "The issuer token response omitted the credential nonce required for a replay-protected proof. Create a new offer or correct the issuer configuration."
            case .missingCredentialAuthorization:
                return "The issuer token response contained no authorized credential identifier. This offer cannot be redeemed; create a new issuer offer."
            case let .credentialAuthorizationMismatch(offered, authorized):
                let values = authorized.isEmpty ? "none" : authorized.joined(separator: ", ")
                return "The issuer token did not authorize the reviewed configuration \(offered). It returned: \(values). The wallet stopped before requesting a credential."
            case .unknownTransaction: return "The issuer transaction expired or was already used."
            case .presentationRequired: return "The issuer requires PID presentation before issuing this credential."
            case .invalidPresentationResponse: return "The issuer rejected the PID presentation response."
            case .presentationCredentialUnavailable:
                return "No stored W3C credential satisfies the verifier's requested format, type, and claims."
            case let .invalidPresentationChallenge(reason):
                return "The verifier presentation challenge was invalid: \(reason)."
            case let .presentationSubmissionHTTPError(method, path, status, detail):
                return "Presentation submission failed: \(method) \(path) returned HTTP \(status)\(detail.map { ": \($0)" } ?? "")."
            case .authorizationFailed: return "The issuer authorization exchange failed."
            case let .decodingFailed(stage, path, reason):
                return "The issuer returned an invalid \(stage) at \(path): \(reason)."
            case let .remoteOAuthError(code, detail):
                if code == "invalid_grant" {
                    return "This credential offer has expired or was already redeemed. Scan a new offer from the issuer."
                }
                return detail.map { "The issuer returned \(code): \($0)" } ?? "The issuer returned \(code)."
            case let .remoteHTTPError(status, detail):
                return detail.map { "The issuer returned HTTP \(status): \($0)" }
                    ?? "The issuer returned HTTP \(status)."
            case .clientSecurityUnavailable:
                return "The issuer requires DPoP, client attestation, or encrypted credential responses that are unavailable."
            case let .invalidTokenType(expected, actual):
                return "The issuer returned an invalid token type. Expected \(expected), received \(actual ?? "no token type")."
            case .holderIdentityRecoveryRequired:
                return "The canonical W3C holder key is missing. Reset the W3C wallet data before continuing."
            }
        }
        if let error = error as? EbsiCredentialError {
            switch error {
            case .invalidProfile: return "The issuer credential profile is invalid."
            case .malformedCredential: return "The issuer returned a malformed credential."
            case .profileMismatch: return "The credential does not match its advertised W3C profile."
            case .algorithmNotAllowed: return "The credential uses an unsupported signing algorithm."
            case .unsupportedRepresentation: return "The credential representation is not supported by this wallet."
            case .verificationFailed: return "The credential's protected claims could not be verified. This cannot be overridden."
            case .issuerMismatch: return "The issued credential does not belong to the issuer in the reviewed offer."
            case .issuerDIDUnresolved:
                return "The issuer DID document could not be resolved, so the credential signature cannot be verified."
            case .issuerSigningKeysUnresolved:
                return "The issuer signing keys could not be resolved, so the credential signature cannot be verified."
            case .invalidSignature: return "The credential signature is invalid. This cannot be overridden."
            case .invalidHolderBinding: return "The credential is not bound to this wallet. This cannot be overridden."
            case .backendUnavailable: return "The W3C credential backend is unavailable."
            }
        }
        if let error = error as? DecodingError {
            return "A response could not be decoded at \(Self.decodingPath(error)): \(Self.decodingReason(error))."
        }
        guard let error = error as? EudiWalletKitAdapterError else {
            return "Wallet error: \(String(describing: error))"
        }
        return switch error {
        case .unapprovedIssuer: "This issuer is not approved for the active wallet profile."
        case .unapprovedVerifier: "This verifier is not approved for the active wallet profile."
        case .invalidTransactionCode: "Check the transaction code and try again."
        case .requiredClaimMissing: "Required claims must remain selected."
        case .recoveryRequired: "Wallet recovery must finish before this action can continue."
        case let .presentationRequestFailedWithReason(reason):
            "Wallet Kit could not resolve the PID presentation request: \(reason)"
        default: "EUDI Wallet Kit error: \(String(describing: error))"
        }
    }


    private static func setupErrorMessage(_ error: Error) -> String {
        if let error = error as? DecodingError {
            return "decoding failed at \(decodingPath(error)): \(decodingReason(error))"
        }
        if let error = error as? EudiWalletKitAdapterError {
            return "EUDI Wallet Kit \(String(describing: error))"
        }
        if let error = error as? OpenID4VCBackendError {
            return "EBSI backend \(String(describing: error))"
        }
        return String(describing: error)
    }

    private static func decodingPath(_ error: DecodingError) -> String {
        let path: [any CodingKey] = switch error {
        case let .dataCorrupted(context), let .typeMismatch(_, context),
             let .valueNotFound(_, context), let .keyNotFound(_, context): context.codingPath
        @unknown default: []
        }
        return path.reduce("$") { partial, key in
            key.intValue.map { "\(partial)[\($0)]" } ?? "\(partial).\(key.stringValue)"
        }
    }

    private static func decodingReason(_ error: DecodingError) -> String {
        switch error {
        case .dataCorrupted: "invalid value"
        case let .typeMismatch(type, _): "expected \(String(describing: type))"
        case let .valueNotFound(type, _): "missing \(String(describing: type))"
        case let .keyNotFound(key, _): "missing key \(key.stringValue)"
        @unknown default: "unknown decoding failure"
        }
    }

}
