import Foundation
import EudiWalletKitAdapter
import EbsiW3CBackend
import ProtocolEngine
import OariDesignSystem
import Testing
import WalletDomain
import WalletVault
@testable import OariWallet

@MainActor
struct WalletAppModelTests {
    @Test("Deferred retry classification is bounded and distinguishes terminal responses")
    func deferredRetryClassification() {
        #expect(LiveOpenID4VCService.isTransient(URLError(.timedOut)))
        #expect(LiveOpenID4VCService.isTransient(
            OpenID4VCBackendError.remoteHTTPError(status: 503, detail: nil)
        ))
        #expect(!LiveOpenID4VCService.isTransient(
            OpenID4VCBackendError.remoteHTTPError(status: 400, detail: nil)
        ))
        #expect(LiveOpenID4VCService.backoff(after: 1) == 15)
        #expect(LiveOpenID4VCService.backoff(after: 100) == 900)
    }

    @Test("Native deferred transactions load and can be cancelled")
    @MainActor
    func nativeDeferredTransactionLifecycle() async throws {
        let now = Date(timeIntervalSince1970: 1_800_000_000)
        let issuance = DeferredIssuance(
            continuation: Data("encrypted-by-repository".utf8),
            issuerIdentifier: "https://issuer.example",
            configurationIDs: ["pid"],
            displayName: "PID",
            nextAttemptAt: now.addingTimeInterval(60),
            createdAt: now,
            updatedAt: now
        )
        let service = FixtureOpenID4VCWallet(outcome: .allow, deferred: [issuance])
        let model = WalletAppModel()
        await model.load(.success(WalletAppDependencies(
            credentials: EmptyMetadataRepository(), audit: EmptyAuditRepository(),
            localAuthenticator: FixtureAuthenticator(), eudiWallet: nil,
            eudiAvailability: .configurationRequired("fixture"), openID4VCWallet: service
        )))

        #expect(model.deferredIssuances == [issuance])
        await model.removeDeferredIssuance(id: issuance.id)
        #expect(model.deferredIssuances.isEmpty)
    }

    @Test("Deferred scheduler tracks earliest deadline and stops in background")
    @MainActor
    func deferredForegroundScheduler() async {
        let first = Date().addingTimeInterval(600)
        let later = first.addingTimeInterval(60)
        let issuances = [first, later].map { deadline in
            DeferredIssuance(
                continuation: Data("fixture".utf8), issuerIdentifier: "https://issuer.example",
                configurationIDs: ["pid"], displayName: "PID", nextAttemptAt: deadline,
                createdAt: Date(), updatedAt: Date()
            )
        }
        let service = FixtureOpenID4VCWallet(outcome: .allow, deferred: issuances)
        let model = WalletAppModel()
        await model.load(.success(WalletAppDependencies(
            credentials: EmptyMetadataRepository(), audit: EmptyAuditRepository(),
            localAuthenticator: FixtureAuthenticator(), eudiWallet: nil,
            eudiAvailability: .configurationRequired("fixture"), openID4VCWallet: service
        )))
        #expect(model.deferredSchedulerDeadline == first)
        await model.checkDeferredIssuance(id: issuances[0].id)
        #expect(await service.deferredCheckCount == 0)

        await model.handleScenePhase(.background)
        #expect(model.deferredSchedulerDeadline == nil)
    }

    @Test("Deferred polling waits for successful app unlock")
    @MainActor
    func deferredPollingWaitsForUnlock() async {
        let suite = "WalletAppModelTests.deferred-lock.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suite)!
        defer { defaults.removePersistentDomain(forName: suite) }
        defaults.set(true, forKey: "oari.security.app-lock.enabled")
        let issuance = DeferredIssuance(
            continuation: Data("fixture".utf8), issuerIdentifier: "https://issuer.example",
            configurationIDs: ["pid"], displayName: "PID", nextAttemptAt: Date().addingTimeInterval(-1),
            createdAt: Date(), updatedAt: Date()
        )
        let service = FixtureOpenID4VCWallet(outcome: .allow, deferred: [issuance])
        let model = WalletAppModel(userDefaults: defaults)
        await model.load(.success(WalletAppDependencies(
            credentials: EmptyMetadataRepository(), audit: EmptyAuditRepository(),
            localAuthenticator: FixtureAuthenticator(),
            appLockAuthenticator: FixtureAppLockAuthenticator(shouldFail: true),
            eudiWallet: nil, eudiAvailability: .configurationRequired("fixture"),
            openID4VCWallet: service
        )))
        await Task.yield()
        #expect(await service.deferredResumeCount == 0)
        #expect(model.deferredSchedulerDeadline == nil)
    }

    @Test("Build configuration keeps only test fixture controls")
    func buildConfigurationGatesDevelopmentControls() {
        #if DEBUG
        let configuration = AppConfiguration.current(arguments: [
            "OariWallet",
            "--fixture", "populated",
            "--incoming-url", "openid4vp://authorize?request=fixture",
        ])
        #expect(configuration.fixture == .populated)
        #expect(configuration.incomingURL?.scheme == "openid4vp")
        #expect(configuration.allowedHosts.isSuperset(of: ["wallet.dev.oari.io", "issuer.example"]))
        #else
        let configuration = AppConfiguration.current(arguments: [
            "OariWallet",
            "--fixture", "populated",
            "--incoming-url", "openid4vp://authorize?request=fixture",
        ])
        #expect(configuration.fixture == .production)
        #expect(configuration.incomingURL == nil)
        #expect(configuration.allowedHosts.isEmpty)
        #endif
    }

    @Test("W3C composition is uniform across build configurations")
    func w3CReleaseComposition() throws {
        let production = try W3CBackendComposition.make()
        #expect(production.endpoint.id == "oari-production")
        #expect(production.environmentPolicy == .production)
        #expect(production.approvedProductionEndpoints[production.endpoint.id] == production.endpoint)
        #expect(production.transportProfileRegistry == .productionInteroperability)
        #expect(W3CBackendComposition.authorizationClientID == "io.oari.wallet")
        #expect(W3CBackendComposition.authorizationRedirectURI.absoluteString == "https://wallet.ios.oari.io/oauth/callback")
        #expect(try W3CBackendComposition.additionalProfiles().map(\.id) == [
            "vcdm2-jwt-vc-json",
            "ebsi-vcdm11-jwt-vc",
            "ietf-dc-sd-jwt-vc",
            "ebsi-vcdm2-sd-jwt",
        ])
    }

    @Test("Empty wallet never implies readiness or trust")
    func emptyState() {
        let model = WalletAppModel()
        #expect(model.credentialCountDescription == "No credentials")
        #expect(model.scanResult == .idle)
    }

    @Test("Theme defaults to system and persists every user choice across restarts")
    func themePersistence() {
        let suiteName = "WalletAppModelTests.theme.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suiteName)!
        defer { defaults.removePersistentDomain(forName: suiteName) }

        #expect(WalletAppModel(userDefaults: defaults).theme == .system)
        for theme in OariTheme.allCases {
            let model = WalletAppModel(userDefaults: defaults)
            model.theme = theme
            #expect(WalletAppModel(userDefaults: defaults).theme == theme)
        }

        defaults.set("unsupported-theme", forKey: "oari.appearance.theme")
        #expect(WalletAppModel(userDefaults: defaults).theme == .system)
    }

    @Test("App Lock setup persists and authenticates on every foreground")
    func appLockLifecycle() async {
        let suiteName = "WalletAppModelTests.app-lock.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suiteName)!
        defer { defaults.removePersistentDomain(forName: suiteName) }
        let authenticator = FixtureAppLockAuthenticator()
        let model = WalletAppModel(showsOnboarding: true, userDefaults: defaults)
        await model.load(.success(WalletAppDependencies(
            credentials: EmptyMetadataRepository(),
            audit: EmptyAuditRepository(),
            localAuthenticator: FixtureAuthenticator(),
            appLockAuthenticator: authenticator,
            eudiWallet: nil,
            eudiAvailability: .configurationRequired("Unavailable"),
            openID4VCWallet: nil
        )))
        #expect(!model.isAppLockEnabled)
        await model.configureAppLock(enabled: true)
        #expect(model.isAppLockEnabled)
        #expect(model.appLockState == .unlocked)
        #expect(await authenticator.callCount == 1)
        // Face ID itself sends inactive/active; it must not start another prompt.
        await model.handleScenePhase(.inactive)
        #expect(!model.isPrivacyCoverVisible)
        #expect(!model.isAppLockBlocking)
        await model.handleScenePhase(.active)
        #expect(await authenticator.callCount == 1)

        await model.handleScenePhase(.inactive)
        await model.handleScenePhase(.background)
        #expect(model.isAppLockBlocking)
        #expect(model.isPrivacyCoverVisible)
        await model.handleScenePhase(.active)
        #expect(model.appLockState == .unlocked)
        #expect(await authenticator.callCount == 2)
        await model.handleScenePhase(.active)
        #expect(await authenticator.callCount == 2)

        let restartedAuthenticator = FixtureAppLockAuthenticator()
        let restarted = WalletAppModel(userDefaults: defaults)
        await restarted.load(.success(WalletAppDependencies(
            credentials: EmptyMetadataRepository(),
            audit: EmptyAuditRepository(),
            localAuthenticator: FixtureAuthenticator(),
            appLockAuthenticator: restartedAuthenticator,
            eudiWallet: nil,
            eudiAvailability: .configurationRequired("Unavailable"),
            openID4VCWallet: nil
        )))
        await restartedAuthenticator.waitForCallCount(1)
        await Task.yield()
        #expect(restarted.appLockState == .unlocked)
        #expect(await restartedAuthenticator.callCount == 1)
    }

    @Test("Startup reaches loaded before foreground authentication completes")
    func startupDoesNotWaitForAppLockAuthentication() async {
        let suiteName = "WalletAppModelTests.nonblocking-startup-auth.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suiteName)!
        defer { defaults.removePersistentDomain(forName: suiteName) }
        defaults.set(true, forKey: "oari.security.app-lock.enabled")
        let authenticator = SuspendingAppLockAuthenticator()
        let model = WalletAppModel(showsOnboarding: false, userDefaults: defaults)

        await model.load(.success(WalletAppDependencies(
            credentials: EmptyMetadataRepository(), audit: EmptyAuditRepository(),
            localAuthenticator: FixtureAuthenticator(), appLockAuthenticator: authenticator,
            eudiWallet: nil, eudiAvailability: .configurationRequired("Unavailable"), openID4VCWallet: nil
        )))

        #expect(model.loadingState == .loaded)
        #expect(model.isAppLockBlocking)
        await authenticator.waitForCallCount(1)
        await authenticator.completeNext()
        for _ in 0..<20 where model.isAppLockBlocking { await Task.yield() }
        #expect(!model.isAppLockBlocking)
    }

    @Test("Enabling App Lock authentication does not present the foreground lock screen")
    func appLockSetupAuthenticationDoesNotBlock() async {
        let suiteName = "WalletAppModelTests.app-lock-setup-auth.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suiteName)!
        defer { defaults.removePersistentDomain(forName: suiteName) }
        let authenticator = SuspendingAppLockAuthenticator()
        let model = WalletAppModel(showsOnboarding: true, userDefaults: defaults)
        await model.load(.success(WalletAppDependencies(
            credentials: EmptyMetadataRepository(), audit: EmptyAuditRepository(),
            localAuthenticator: FixtureAuthenticator(), appLockAuthenticator: authenticator,
            eudiWallet: nil, eudiAvailability: .configurationRequired("Unavailable"), openID4VCWallet: nil
        )))

        let setup = Task { await model.configureAppLock(enabled: true) }
        await authenticator.waitForCallCount(1)
        #expect(model.appLockState == .authenticating)
        #expect(!model.requiresForegroundUnlock)
        #expect(!model.isAppLockBlocking)
        await model.handleScenePhase(.inactive)
        await model.handleScenePhase(.active)
        #expect(await authenticator.callCount == 1)
        await authenticator.completeNext()
        await setup.value
        #expect(model.appLockState == .unlocked)
        #expect(!model.isAppLockBlocking)
    }

    @Test("Declined or failed App Lock setup never enables the lock")
    func appLockSetupFailure() async {
        let suiteName = "WalletAppModelTests.app-lock-failure.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suiteName)!
        defer { defaults.removePersistentDomain(forName: suiteName) }
        let authenticator = FixtureAppLockAuthenticator(shouldFail: true)
        let model = WalletAppModel(showsOnboarding: true, userDefaults: defaults)
        await model.load(.success(WalletAppDependencies(
            credentials: EmptyMetadataRepository(), audit: EmptyAuditRepository(),
            localAuthenticator: FixtureAuthenticator(), appLockAuthenticator: authenticator,
            eudiWallet: nil, eudiAvailability: .configurationRequired("Unavailable"), openID4VCWallet: nil
        )))
        await model.configureAppLock(enabled: true)
        #expect(!model.isAppLockEnabled)
        #expect(model.appLockState == .disabled)
        #expect(model.appLockSetupError != nil)
        model.declineAppLockSetup()
        #expect(model.hasCompletedAppLockSetup)
        #expect(!model.isAppLockEnabled)
    }

    @Test("Disabling App Lock requires authentication and persists")
    func appLockDisable() async {
        let suiteName = "WalletAppModelTests.app-lock-disable.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suiteName)!
        defer { defaults.removePersistentDomain(forName: suiteName) }
        let authenticator = FixtureAppLockAuthenticator()
        let model = WalletAppModel(showsOnboarding: true, userDefaults: defaults)
        await model.load(.success(WalletAppDependencies(
            credentials: EmptyMetadataRepository(), audit: EmptyAuditRepository(),
            localAuthenticator: FixtureAuthenticator(), appLockAuthenticator: authenticator,
            eudiWallet: nil, eudiAvailability: .configurationRequired("Unavailable"), openID4VCWallet: nil
        )))
        await model.configureAppLock(enabled: true)
        await model.configureAppLock(enabled: false)
        #expect(!model.isAppLockEnabled)
        #expect(model.appLockState == .disabled)
        #expect(await authenticator.callCount == 2)
        #expect(WalletAppModel(userDefaults: defaults).appLockState == .disabled)
    }

    @Test("Existing users receive App Lock migration prompt once")
    func appLockMigrationPrompt() async {
        let suiteName = "WalletAppModelTests.app-lock-migration.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suiteName)!
        defer { defaults.removePersistentDomain(forName: suiteName) }
        let model = WalletAppModel(showsOnboarding: false, userDefaults: defaults)
        await model.load(.success(WalletAppDependencies(
            credentials: EmptyMetadataRepository(), audit: EmptyAuditRepository(),
            localAuthenticator: FixtureAuthenticator(), appLockAuthenticator: FixtureAppLockAuthenticator(),
            eudiWallet: nil, eudiAvailability: .configurationRequired("Unavailable"), openID4VCWallet: nil
        )))
        #expect(model.showsAppLockSetup)
        model.declineAppLockSetup()
        let restarted = WalletAppModel(showsOnboarding: false, userDefaults: defaults)
        await restarted.load(.success(WalletAppDependencies(
            credentials: EmptyMetadataRepository(), audit: EmptyAuditRepository(),
            localAuthenticator: FixtureAuthenticator(), appLockAuthenticator: FixtureAppLockAuthenticator(),
            eudiWallet: nil, eudiAvailability: .configurationRequired("Unavailable"), openID4VCWallet: nil
        )))
        #expect(!restarted.showsAppLockSetup)
    }

    @Test("Authentication completed after background cannot unlock a later foreground")
    func staleAppLockAuthentication() async {
        let suiteName = "WalletAppModelTests.app-lock-stale.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suiteName)!
        defer { defaults.removePersistentDomain(forName: suiteName) }
        defaults.set(true, forKey: "oari.security.app-lock.enabled")
        defaults.set(true, forKey: "oari.security.app-lock.setup-completed")
        let authenticator = SuspendingAppLockAuthenticator()
        let model = WalletAppModel(userDefaults: defaults)
        let load = Task {
            await model.load(.success(WalletAppDependencies(
                credentials: EmptyMetadataRepository(), audit: EmptyAuditRepository(),
                localAuthenticator: FixtureAuthenticator(), appLockAuthenticator: authenticator,
                eudiWallet: nil, eudiAvailability: .configurationRequired("Unavailable"), openID4VCWallet: nil
            )))
        }
        await authenticator.waitForCallCount(1)
        await model.handleScenePhase(.inactive)
        await model.handleScenePhase(.background)
        await authenticator.completeNext()
        await load.value
        #expect(model.appLockState == .locked(nil))

        let foreground = Task { await model.handleScenePhase(.active) }
        await authenticator.waitForCallCount(2)
        await authenticator.completeNext()
        await foreground.value
        #expect(model.appLockState == .unlocked)
        #expect(await authenticator.callCount == 2)
    }

    @Test("Scanner rejects unapproved hosts and classifies approved requests")
    func scanClassification() {
        let model = WalletAppModel()
        model.scanInput = "https://evil.example/present?request=x"
        model.classifyScan()
        guard case .rejected = model.scanResult else {
            Issue.record("Unapproved host must reject")
            return
        }
        model.scanInput = "https://wallet.dev.oari.io/present?request=x"
        model.classifyScan()
        #expect(model.scanResult == .presentation)
    }

    @Test("Incoming URL is classified through the same bounded scanner route")
    func incomingURL() {
        let model = WalletAppModel(allowedHosts: ["verifier.example"])
        model.handleIncomingURL(URL(string: "openid4vp://authorize?request=x")!)
        #expect(model.scanResult == .presentation)
        #expect(model.scanInput.hasPrefix("openid4vp://"))
        #expect(model.selectedTab == .scan)
    }

    @Test("EUDI authorization callback never enters the scanner")
    func eudiAuthorizationCallback() {
        let model = WalletAppModel()
        model.handleIncomingURL(URL(string: "eu.europa.ec.euidi://authorization?code=a%2Bb&state=state")!)
        #expect(model.scanResult == .idle)
        #expect(model.scanInput.isEmpty)
        #expect(model.selectedTab == .wallet)

        model.handleIncomingURL(URL(string: "eu.europa.ec.euidi://unexpected?request=not-a-scan")!)
        #expect(model.scanResult == .idle)
        #expect(model.scanInput.isEmpty)
        #expect(model.selectedTab == .wallet)
    }

    @Test("HAIP links route directly to Wallet Kit and never to native W3C")
    func haipRoutesDirectlyToEudi() async {
        let presentation = fixturePresentationRequest()
        let eudi = FixtureEudiWallet(presentationRequest: presentation)
        let w3c = FixtureOpenID4VCWallet(
            outcome: .allow,
            standalonePresentationRequest: presentation
        )
        let model = WalletAppModel()
        await model.load(.success(WalletAppDependencies(
            credentials: EmptyMetadataRepository(), audit: EmptyAuditRepository(),
            localAuthenticator: FixtureAuthenticator(), eudiWallet: eudi,
            eudiAvailability: .available, openID4VCWallet: w3c
        )))

        model.scanInput = "haip-vci://authorize?credential_offer=fixture"
        await model.reviewScannedRequest()
        #expect(await eudi.lastIssuanceOfferURI?.hasPrefix("haip-vci:") == true)
        #expect(await w3c.resolveCount == 0)

        for scheme in ["haip-vp", "eudi-openid4vp", "mdoc-openid4vp"] {
            model.scanInput = "\(scheme)://authorize?request=fixture"
            await model.reviewScannedRequest()
            #expect(await eudi.lastPresentationRequestURI?.hasPrefix("\(scheme):") == true)
            #expect(await w3c.presentationBeginCount == 0)
        }
    }

    @Test("HAIP waits for one in-progress EUDI initialization without blocking app load")
    func haipWaitsForEudiInitialization() async throws {
        let eudi = FixtureEudiWallet()
        let initializationCalls = InitializationCounter()
        let model = WalletAppModel()
        await model.load(.success(WalletAppDependencies(
            credentials: EmptyMetadataRepository(),
            audit: EmptyAuditRepository(),
            localAuthenticator: FixtureAuthenticator(),
            eudiWallet: nil,
            eudiAvailability: .configurationRequired("Initializing"),
            eudiInitializer: {
                await initializationCalls.recordCall()
                try? await Task.sleep(for: .milliseconds(100))
                return .success(eudi)
            },
            openID4VCWallet: nil
        )))
        #expect(model.loadingState == .loaded)

        model.scanInput = "haip-vci://credential_offer?credential_offer=fixture"
        let review = Task { await model.reviewScannedRequest() }
        try await Task.sleep(for: .milliseconds(20))
        #expect(model.isEudiOperationLoading)
        await review.value

        #expect(!model.isEudiOperationLoading)
        #expect(model.eudiAvailability == .available)
        #expect(await initializationCalls.count == 1)
        #expect(await eudi.lastIssuanceOfferURI?.hasPrefix("haip-vci:") == true)
    }

    @Test("Privacy cover state follows explicit lifecycle input")
    func privacyCover() async {
        let model = WalletAppModel()
        await model.handleScenePhase(.inactive)
        #expect(!model.isPrivacyCoverVisible)
        await model.handleScenePhase(.background)
        #expect(model.isPrivacyCoverVisible)
        await model.handleScenePhase(.active)
        #expect(!model.isPrivacyCoverVisible)
    }

    @Test("Camera and pasted codes share the bounded classification route")
    func scannedCode() {
        let model = WalletAppModel(allowedHosts: ["issuer.example"])
        model.handleScannedCode(
            "https://issuer.example/offer?credential_offer=fixture"
        )
        #expect(model.scanResult == .issuance)
        #expect(model.selectedTab == .scan)
    }

    @Test("Valid scanned offers enter the review flow automatically")
    func scannedOfferAutoEntersReview() async {
        let service = FixtureEudiWallet()
        let model = WalletAppModel(allowedHosts: ["issuer.example"])
        await model.load(.success(testDependencies(service)))
        model.handleScannedCode("https://issuer.example/offer?credential_offer=fixture")
        await model.autoReviewTask?.value
        guard case .issuanceReview = model.eudiFlow else {
            Issue.record("Expected automatic issuance review after a valid scan")
            return
        }
        #expect(await service.lastIssuanceOfferURI?.contains("credential_offer=fixture") == true)
    }

    @Test("Valid scanned presentation requests enter the consent flow automatically")
    func scannedPresentationAutoEntersReview() async {
        let request = fixturePresentationRequest()
        let service = FixtureEudiWallet(presentationRequest: request)
        let model = WalletAppModel()
        await model.load(.success(testDependencies(service)))
        model.handleScannedCode("openid4vp://authorize?request_uri=https%3A%2F%2Fwallet.dev.oari.io%2Frequest")
        await model.autoReviewTask?.value
        #expect(model.eudiFlow == .presentationConsent(request))
        #expect(model.selectedClaimIDs == ["required-pid"])
    }

    @Test("Rejected or unsupported scans never auto-enter a flow")
    func rejectedScanDoesNotAutoEnterReview() async {
        let service = FixtureEudiWallet()
        let model = WalletAppModel(allowedHosts: ["issuer.example"])
        await model.load(.success(testDependencies(service)))
        model.handleScannedCode("https://evil.example/offer?credential_offer=x")
        #expect(model.autoReviewTask == nil)
        #expect(model.eudiFlow == .idle)
        #expect(await service.lastIssuanceOfferURI == nil)
    }

    @Test("Scans without a configured wallet keep the passive scanner guidance")
    func scanWithoutBackendDoesNotAutoEnterReview() async {
        let model = WalletAppModel(allowedHosts: ["issuer.example"])
        await model.load(.success(WalletAppDependencies(
            credentials: EmptyMetadataRepository(), audit: EmptyAuditRepository(),
            localAuthenticator: FixtureAuthenticator(), eudiWallet: nil,
            eudiAvailability: .configurationRequired("fixture"), openID4VCWallet: nil
        )))
        model.handleScannedCode("https://issuer.example/offer?credential_offer=fixture")
        #expect(model.autoReviewTask == nil)
        #expect(model.scanResult == .issuance)
        #expect(model.eudiFlow == .configurationRequired("fixture"))
    }

    @Test("Repository failure is explicit and does not imply an empty loaded wallet")
    func repositoryFailure() async {
        let model = WalletAppModel()
        await model.load(.failure(TestFailure.unavailable))
        guard case let .failed(message) = model.loadingState else {
            Issue.record("Expected explicit loading failure")
            return
        }
        #expect(message.contains("unavailable"))
    }

    @Test("Issuance review delegates to EUDI service and reaches completion")
    func eudiIssuanceFlow() async {
        let service = FixtureEudiWallet()
        let model = WalletAppModel(allowedHosts: ["issuer.example"])
        let dependencies = WalletAppDependencies(
            credentials: EmptyMetadataRepository(),
            audit: EmptyAuditRepository(),
            localAuthenticator: FixtureAuthenticator(),
            eudiWallet: service,
            eudiAvailability: .available,
            openID4VCWallet: nil
        )
        await model.load(.success(dependencies))
        model.scanInput = "https://issuer.example/credential-offer?credential_offer=fixture"
        await model.reviewScannedRequest()
        guard case .issuanceReview = model.eudiFlow else {
            Issue.record("Expected issuance review")
            return
        }
        await model.acceptIssuance(transactionCode: "1234")
        #expect(model.eudiFlow == .idle)
        #expect(model.scanInput.isEmpty)
        #expect(model.selectedTab == .wallet)
        #expect(await service.issueCount == 1)
        #expect(await service.lastIssuedProfileID == "fixture-eudi-profile")
        #expect(await service.lastTransactionCode == "1234")
    }

    @Test("Presentation consent preselects required claims and completes")
    func eudiPresentationFlow() async {
        let required = EudiRequestedClaim(
            id: "required", documentID: "pid", documentType: "pid", displayName: "PID",
            claimPath: ["family_name"], displayValue: "Holder", required: true, intentToRetain: false
        )
        let optional = EudiRequestedClaim(
            id: "optional", documentID: "pid", documentType: "pid", displayName: "PID",
            claimPath: ["age_over_18"], displayValue: "true", required: false, intentToRetain: false
        )
        let service = FixtureEudiWallet(presentationRequest: EudiPresentationRequest(
            id: UUID(), verifierName: "Verifier", verifierLegalName: "Verifier Ltd",
            verifierCertificateValid: true, claims: [required, optional], warningCount: 0
        ))
        let model = WalletAppModel()
        await model.load(.success(testDependencies(service)))
        model.scanInput = "openid4vp://authorize?request_uri=https%3A%2F%2Fwallet.dev.oari.io%2Frequest"
        await model.reviewScannedRequest()
        #expect(model.selectedClaimIDs == ["required"])
        #expect(model.preventsInteractiveFlowDismissal)
        model.selectedClaimIDs.insert("optional")
        await model.submitPresentation(accepted: true)
        #expect(model.eudiFlow == .completed("Approved claims were shared."))
        #expect(await service.lastSelectedClaims == ["required", "optional"])
    }

    @Test("Standalone W3C OpenID4VP presentation is routed to the credential owner")
    func w3cStandalonePresentationFlow() async {
        let request = EudiPresentationRequest(
            id: UUID(), verifierName: "decentralized_identifier:did:key:verifier",
            verifierLegalName: nil, verifierCertificateValid: nil,
            claims: [EudiRequestedClaim(
                id: "credentialSubject.role", documentID: "w3c", documentType: "W3C credential",
                displayName: "Business Wallet User", claimPath: ["credentialSubject", "role"],
                displayValue: "admin", required: true, intentToRetain: false
            )], warningCount: 0
        )
        let backend = FixtureOpenID4VCWallet(
            outcome: .allow,
            standalonePresentationRequest: request
        )
        let model = WalletAppModel()
        await model.load(.success(WalletAppDependencies(
            credentials: EmptyMetadataRepository(), audit: EmptyAuditRepository(),
            localAuthenticator: FixtureAuthenticator(), appLockAuthenticator: FixtureAppLockAuthenticator(),
            eudiWallet: nil, eudiAvailability: .configurationRequired("Unavailable"), openID4VCWallet: backend
        )))
        model.scanInput = "openid4vp://?client_id=decentralized_identifier%3Adid%3Akey%3Averifier&request_uri=https%3A%2F%2Fwallet.dev.oari.io%2Fopenid4vp%2Frequest%2Fid"
        await model.reviewScannedRequest()
        #expect(model.eudiFlow == .presentationConsent(request))
        await model.submitPresentation(accepted: true)
        #expect(model.eudiFlow == .completed("Approved claims were shared."))
        #expect(await backend.completedStandaloneClaimIDs == [["credentialSubject.role"]])
    }

    @Test("Restored pending issuance continues through consent and completion")
    func eudiPendingFlow() async {
        let pending = EudiPendingIssuance(
            id: UUID(),
            document: EudiWalletDocumentSummary(
                id: "wallet-document", documentType: "pid", displayName: "PID upgrade",
                format: "sjwt", status: "pending"
            )
        )
        let request = EudiPresentationRequest(
            id: UUID(), verifierName: "Issuer verifier", verifierLegalName: nil,
            verifierCertificateValid: true,
            claims: [EudiRequestedClaim(
                id: "pid-family", documentID: "pid", documentType: "pid", displayName: "PID",
                claimPath: ["family_name"], displayValue: "Holder", required: true, intentToRetain: false
            )], warningCount: 0
        )
        let service = FixtureEudiWallet(
            pendingAtLoad: [pending],
            presentationRequest: request,
            completion: .issuance(EudiIssuanceResult(
                documents: [], metadata: [], warningCount: 0, pendingIssuances: []
            ))
        )
        let model = WalletAppModel()
        await model.load(.success(testDependencies(service)))
        #expect(model.eudiFlow == .pending(pending))
        #expect(await service.operationCount == 1)
        await model.continuePendingIssuance()
        #expect(model.eudiFlow == .presentationConsent(request))
        await model.submitPresentation(accepted: true)
        #expect(model.eudiFlow == .idle)
    }

    @Test("Audit history is deferred and loaded once on demand")
    func lazyAuditHistory() async {
        let audit = CountingAuditRepository()
        let model = WalletAppModel()
        await model.load(.success(WalletAppDependencies(
            credentials: EmptyMetadataRepository(),
            audit: audit,
            localAuthenticator: FixtureAuthenticator(),
            eudiWallet: nil,
            eudiAvailability: .configurationRequired("Unavailable"),
            openID4VCWallet: nil
        )))
        #expect(await audit.loadCount == 0)
        await model.loadAuditHistoryIfNeeded()
        await model.loadAuditHistoryIfNeeded()
        #expect(await audit.loadCount == 1)
        #expect(model.hasLoadedAuditHistory)
    }

    @Test("Declined or failed PID presentation preserves recoverable pending issuance")
    func pendingDeclineAndFailureRecovery() async {
        let pending = fixturePending()
        let request = fixturePresentationRequest()
        let declinedService = FixtureEudiWallet(
            pendingAtLoad: [pending], presentationRequest: request, completion: .pendingDeclined
        )
        let declinedModel = WalletAppModel()
        await declinedModel.load(.success(testDependencies(declinedService)))
        await declinedModel.continuePendingIssuance()
        await declinedModel.submitPresentation(accepted: false)
        #expect(declinedModel.eudiFlow == .pending(pending))

        let failingService = FixtureEudiWallet(
            pendingAtLoad: [pending], presentationRequest: request, failCompletion: true
        )
        let failingModel = WalletAppModel()
        await failingModel.load(.success(testDependencies(failingService)))
        await failingModel.continuePendingIssuance()
        await failingModel.submitPresentation(accepted: true)
        #expect(failingModel.hasRecoverablePendingIssuance)
        guard case .failed = failingModel.eudiFlow else {
            Issue.record("Expected redacted pending failure")
            return
        }
        failingModel.dismissEudiFlow()
        #expect(failingModel.eudiFlow == .idle)
        failingModel.returnToPendingIssuance()
        #expect(failingModel.eudiFlow == .pending(pending))
    }

    @Test("Missing production EUDI profile is explicit")
    func configurationRequired() async {
        let model = WalletAppModel()
        let dependencies = WalletAppDependencies(
            credentials: EmptyMetadataRepository(), audit: EmptyAuditRepository(),
            localAuthenticator: FixtureAuthenticator(), eudiWallet: nil,
            eudiAvailability: .configurationRequired("Install approved profile"),
            openID4VCWallet: nil
        )
        await model.load(.success(dependencies))
        #expect(model.eudiFlow == .configurationRequired("Install approved profile"))
        #expect(!model.isEudiOperational)

        let service = FixtureEudiWallet()
        let inconsistent = WalletAppModel()
        let record = CredentialRecord(
            configurationID: "pid", walletDocumentID: "wallet-pid", displayName: "PID",
            format: .sdJWTVC, profileID: "profile", issuerIdentifier: "https://issuer.example",
            createdAt: Date()
        )
        await inconsistent.load(.success(WalletAppDependencies(
            credentials: FixedMetadataRepository(records: [record]), audit: EmptyAuditRepository(),
            localAuthenticator: FixtureAuthenticator(), eudiWallet: service,
            eudiAvailability: .configurationRequired("Profile disabled"),
            openID4VCWallet: nil
        )))
        #expect(await service.operationCount == 0)
        inconsistent.scanInput = "https://issuer.example/offer?credential_offer=fixture"
        await inconsistent.reviewScannedRequest()
        #expect(await service.operationCount == 0)
        inconsistent.selectCredential(record)
        await inconsistent.deleteSelectedCredential()
        #expect(await service.lastDeleted == nil)
        #expect(await service.operationCount == 0)
    }

    @Test("Credential lifecycle delegates deletion with Wallet Kit document status")
    func credentialDeletion() async {
        let record = CredentialRecord(
            configurationID: "pid", walletDocumentID: "wallet-pid", displayName: "PID",
            format: .sdJWTVC, profileID: "eudi-final-1", issuerIdentifier: "https://issuer.example",
            createdAt: Date(timeIntervalSince1970: 1_700_000_000)
        )
        let service = FixtureEudiWallet(summaries: [EudiWalletDocumentSummary(
            id: "wallet-pid", documentType: "pid", displayName: "PID",
            format: "sjwt", status: "issued"
        )])
        let authenticator = FixtureAppLockAuthenticator()
        let model = WalletAppModel()
        await model.load(.success(WalletAppDependencies(
            credentials: FixedMetadataRepository(records: [record]),
            audit: EmptyAuditRepository(), localAuthenticator: FixtureAuthenticator(),
            appLockAuthenticator: authenticator,
            eudiWallet: service, eudiAvailability: .available, openID4VCWallet: nil
        )))
        model.selectCredential(record)
        await model.deleteSelectedCredential()
        #expect(model.selectedCredential == nil)
        #expect(model.credentialActionState == .completed("Credential removed."))
        #expect(await service.lastDeleted == "wallet-pid:issued")
        #expect(await authenticator.callCount == 1)
    }

    @Test("W3C credential deletion authenticates and does not require Wallet Kit")
    func w3cCredentialDeletion() async {
        let backendID = UUID()
        let record = CredentialRecord(
            configurationID: "example-vcdm2-jwt-vc", backendID: W3CBackendComposition.backendID,
            backendDocumentID: backendID.uuidString, displayName: "Legal Person ID",
            format: .jwtVC, profileID: "openid4vc-final-vcdm2-jwt-vc-ebsi-1",
            issuerIdentifier: "https://issuer.example", createdAt: Date()
        )
        let service = FixtureOpenID4VCWallet(outcome: .allow)
        let authenticator = FixtureAppLockAuthenticator()
        let model = WalletAppModel()
        await model.load(.success(WalletAppDependencies(
            credentials: FixedMetadataRepository(records: [record]),
            audit: EmptyAuditRepository(), localAuthenticator: FixtureAuthenticator(),
            appLockAuthenticator: authenticator, eudiWallet: nil,
            eudiAvailability: .configurationRequired("Unavailable"), openID4VCWallet: service
        )))
        model.selectCredential(record)
        #expect(model.canDeleteCredential(record))
        await model.deleteSelectedCredential()
        #expect(model.credentialActionState == .completed("Credential removed."))
        #expect(await service.deletedCredentials.first?.0 == backendID)
        #expect(await service.deletedCredentials.first?.1 == record.id)
        #expect(await authenticator.callCount == 1)
    }

    @Test("Credential deletion Face ID inactivity does not show the lock shield")
    func credentialDeletionSuppressesTransientPrivacyShield() async {
        let backendID = UUID()
        let record = CredentialRecord(
            configurationID: "vc", backendID: W3CBackendComposition.backendID,
            backendDocumentID: backendID.uuidString, displayName: "Credential",
            format: .jwtVC, profileID: "vcdm2-vc-jwt",
            issuerIdentifier: "https://issuer.example", createdAt: Date()
        )
        let service = FixtureOpenID4VCWallet(outcome: .allow)
        let authenticator = SuspendingAppLockAuthenticator()
        let model = WalletAppModel()
        await model.load(.success(WalletAppDependencies(
            credentials: FixedMetadataRepository(records: [record]),
            audit: EmptyAuditRepository(), localAuthenticator: FixtureAuthenticator(),
            appLockAuthenticator: authenticator, eudiWallet: nil,
            eudiAvailability: .configurationRequired("Unavailable"), openID4VCWallet: service
        )))
        model.selectCredential(record)

        let deletion = Task { await model.deleteSelectedCredential() }
        await authenticator.waitForCallCount(1)
        #expect(model.suppressesInactivePrivacyShield)
        await model.handleScenePhase(.inactive)
        #expect(!model.shouldShowInactivePrivacyShield)
        #expect(!model.isAppLockBlocking)
        await model.handleScenePhase(.active)
        #expect(!model.suppressesInactivePrivacyShield)
        await authenticator.completeNext()
        await deletion.value

        #expect(model.credentialActionState == .completed("Credential removed."))
        #expect(await service.deletedCredentials.count == 1)
    }

    @Test("Credential deletion cancellation mutates no backend")
    func credentialDeletionAuthenticationFailure() async {
        let record = CredentialRecord(
            configurationID: "pid", walletDocumentID: "wallet-pid", displayName: "PID",
            format: .sdJWTVC, profileID: "eudi-final-1",
            issuerIdentifier: "https://issuer.example", createdAt: Date()
        )
        let service = FixtureEudiWallet(summaries: [EudiWalletDocumentSummary(
            id: "wallet-pid", documentType: "pid", displayName: "PID",
            format: "sjwt", status: "issued"
        )])
        let authenticator = FixtureAppLockAuthenticator(shouldFail: true)
        let model = WalletAppModel()
        await model.load(.success(WalletAppDependencies(
            credentials: FixedMetadataRepository(records: [record]), audit: EmptyAuditRepository(),
            localAuthenticator: FixtureAuthenticator(), appLockAuthenticator: authenticator,
            eudiWallet: service, eudiAvailability: .available, openID4VCWallet: nil
        )))
        model.selectCredential(record)
        await model.deleteSelectedCredential()
        #expect(model.credentialActionState == .failed("Authentication is required to remove this credential."))
        #expect(await service.lastDeleted == nil)
        #expect(await authenticator.callCount == 1)
    }

    @Test("Onboarding completion is explicit and persisted")
    func onboardingCompletion() {
        let suiteName = "WalletAppModelTests.onboarding.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suiteName)!
        defer { defaults.removePersistentDomain(forName: suiteName) }
        let key = "oari.onboarding.completed"
        let model = WalletAppModel(showsOnboarding: true, userDefaults: defaults)
        #expect(model.showsOnboarding)
        model.declineAppLockSetup()
        model.completeOnboarding()
        #expect(!model.showsOnboarding)
        #expect(defaults.bool(forKey: key))
    }

    @Test("Untrusted EBSI flow requires explicit continue or cancel")
    func openID4VCDevelopmentWarning() async {
        let warning = EbsiTrustWarning(
            counterpartyIdentifier: "did:ebsi:unregistered-issuer",
            role: .issuer,
            reasons: [.issuerNotAccredited],
            evidenceSources: ["https://ebsi.oari.io"],
            nextAction: "Continue credential issuance. Nothing is stored yet."
        )
        let service = FixtureOpenID4VCWallet(outcome: .requireExplicitWarning(warning))
        let model = WalletAppModel()
        await model.load(.success(WalletAppDependencies(
            credentials: EmptyMetadataRepository(), audit: EmptyAuditRepository(),
            localAuthenticator: FixtureAuthenticator(), eudiWallet: nil,
            eudiAvailability: .configurationRequired("EUDI unavailable"), openID4VCWallet: service
        )))
        let offerInput = "openid-credential-offer://?credential_offer=fixture"
        model.scanInput = offerInput
        await model.reviewScannedRequest()
        #expect(model.openID4VCTrustWarning == warning)
        #expect(await service.continueCalls == [])
        await model.continueAfterOpenID4VCTrustWarning()
        #expect(await service.continueCalls.isEmpty)
        await model.issueReviewedOpenID4VCCredential(transactionCode: "123456")
        #expect(await service.continueCalls == [true])
        #expect(model.eudiFlow == .idle)
        #expect(model.scanInput.isEmpty)
        #expect(model.selectedTab == .wallet)

        let cancelService = FixtureOpenID4VCWallet(outcome: .requireExplicitWarning(warning))
        let cancelModel = WalletAppModel()
        await cancelModel.load(.success(WalletAppDependencies(
            credentials: EmptyMetadataRepository(), audit: EmptyAuditRepository(),
            localAuthenticator: FixtureAuthenticator(), eudiWallet: nil,
            eudiAvailability: .configurationRequired("EUDI unavailable"), openID4VCWallet: cancelService
        )))
        cancelModel.scanInput = offerInput
        await cancelModel.reviewScannedRequest()
        await cancelModel.cancelOpenID4VCTrustWarning()
        #expect(await cancelService.cancelCount == 1)
        #expect(await cancelService.continueCalls.isEmpty)

        let replayService = FixtureOpenID4VCWallet(
            outcome: .requireExplicitWarning(warning),
            continuationDelayNanoseconds: 50_000_000
        )
        let replayModel = WalletAppModel()
        await replayModel.load(.success(WalletAppDependencies(
            credentials: EmptyMetadataRepository(), audit: EmptyAuditRepository(),
            localAuthenticator: FixtureAuthenticator(), eudiWallet: nil,
            eudiAvailability: .configurationRequired("EUDI unavailable"), openID4VCWallet: replayService
        )))
        replayModel.scanInput = offerInput
        await replayModel.reviewScannedRequest()
        async let first: Void = replayModel.continueAfterOpenID4VCTrustWarning()
        async let second: Void = replayModel.continueAfterOpenID4VCTrustWarning()
        _ = await (first, second)
        await replayModel.issueReviewedOpenID4VCCredential(transactionCode: "123456")
        #expect(await replayService.continueCalls == [true])
    }

    @Test("Post-issuance signer warning Continue resumes staged storage exactly once")
    func openID4VCCredentialSignerWarning() async {
        let warning = EbsiTrustWarning(
            counterpartyIdentifier: "did:key:zSigner",
            role: .issuer,
            reasons: [.issuerNotAccredited],
            evidenceSources: [],
            nextAction: "Continue to store the validated credential."
        )
        let service = FixtureOpenID4VCWallet(
            outcome: .allow,
            continuation: .credentialSignerTrustWarning(warning)
        )
        let model = WalletAppModel()
        await model.load(.success(WalletAppDependencies(
            credentials: EmptyMetadataRepository(), audit: EmptyAuditRepository(),
            localAuthenticator: FixtureAuthenticator(), eudiWallet: nil,
            eudiAvailability: .configurationRequired("EUDI unavailable"), openID4VCWallet: service
        )))
        model.scanInput = "openid-credential-offer://?credential_offer=fixture"
        await model.reviewScannedRequest()
        await model.issueReviewedOpenID4VCCredential()
        #expect(model.openID4VCTrustWarning == warning)
        #expect(await service.continueCalls == [false])

        await model.continueAfterOpenID4VCTrustWarning()
        #expect(await service.continueCalls == [false, true])
        #expect(model.openID4VCTrustWarning == nil)
        #expect(model.selectedTab == .wallet)
    }

    @Test("Signed OpenID4VP PID challenge reaches consent and retains authorization transaction")
    func openID4VCPIDPresentationBridge() async {
        let request = fixturePresentationRequest()
        let interactionID = UUID()
        let challenge = OpenID4VPPresentationRequest(
            id: interactionID,
            authorizationChallengeEndpoint: URL(string: "https://wallet.dev.oari.io/openid/authorize")!,
            authSession: "auth-session",
            interactionType: "openid4vp_presentation",
            responseMode: "direct_post",
            responseURI: URL(string: "https://wallet.dev.oari.io/openid/authorize")!,
            nonce: "nonce",
            state: "auth-session",
            dcqlQuery: ["credentials": .array([.object([
                "id": .string("pid"),
                "format": .string("mso_mdoc"),
                "meta": .object([
                    "vct_values": .array([.string("urn:eu.europa.ec.eudi:pid:1")]),
                ]),
            ])])],
            signedRequest: "header.payload.signature"
        )
        let openID4VC = FixtureOpenID4VCWallet(
            outcome: .allow,
            interactionID: interactionID,
            continuation: .presentationRequired(challenge)
        )
        let eudi = FixtureEudiWallet(
            presentationRequest: request,
            completion: .externalAuthorization("authorization-code"),
            summaries: [EudiWalletDocumentSummary(
                id: "pid-document",
                documentType: "urn:eu.europa.ec.eudi:pid:1",
                displayName: "PID",
                format: "sdjwt",
                status: "issued"
            )]
        )
        let model = WalletAppModel()
        await model.load(.success(WalletAppDependencies(
            credentials: EmptyMetadataRepository(), audit: EmptyAuditRepository(),
            localAuthenticator: FixtureAuthenticator(), eudiWallet: eudi,
            eudiAvailability: .available, openID4VCWallet: openID4VC
        )))
        model.scanInput = "openid-credential-offer://?credential_offer=fixture"
        await model.reviewScannedRequest()
        await model.issueReviewedOpenID4VCCredential()
        guard case let .openID4VPPresentationRequired(received) = model.eudiFlow else {
            Issue.record("Expected PID presentation challenge")
            return
        }
        await model.startEudiCredentialPresentation(received)
        #expect(model.eudiFlow == .presentationConsent(request))
        #expect((await eudi.lastPresentationRequestURI)?.contains("request=header.payload.signature") == true)
        await model.submitPresentation(accepted: true)
        #expect(await openID4VC.completedAuthorizationCodes == ["authorization-code"])
        #expect(model.eudiFlow == .idle)
    }

    @Test("OpenID4VP PID challenge presents a credential from the W3C backend")
    func openID4VCW3CPIDPresentation() async {
        let interactionID = UUID()
        let challenge = OpenID4VPPresentationRequest(
            id: interactionID,
            authorizationChallengeEndpoint: URL(string: "https://wallet.dev.oari.io/openid/authorize")!,
            authSession: "auth-session",
            interactionType: "openid4vp_presentation",
            responseMode: "direct_post",
            responseURI: URL(string: "https://wallet.dev.oari.io/openid/authorize")!,
            nonce: "nonce",
            state: "auth-session",
            dcqlQuery: ["credentials": .array([.object([
                "id": .string("pid"),
                "format": .string("dc+sd-jwt"),
                "meta": .object(["vct_values": .array([.string("urn:eu.europa.ec.eudi:pid:1")])]),
            ])])],
            signedRequest: "header.payload.signature"
        )
        let consent = fixturePresentationRequest()
        let openID4VC = FixtureOpenID4VCWallet(
            outcome: .allow,
            interactionID: interactionID,
            continuation: .presentationRequired(challenge),
            pidPresentationRequest: consent
        )
        let eudi = FixtureEudiWallet()
        let model = WalletAppModel()
        await model.load(.success(WalletAppDependencies(
            credentials: EmptyMetadataRepository(), audit: EmptyAuditRepository(),
            localAuthenticator: FixtureAuthenticator(), eudiWallet: eudi,
            eudiAvailability: .available, openID4VCWallet: openID4VC
        )))
        model.scanInput = "openid-credential-offer://?credential_offer=fixture"
        await model.reviewScannedRequest()
        await model.issueReviewedOpenID4VCCredential()
        await model.startEudiCredentialPresentation(challenge)
        #expect(model.eudiFlow == .presentationConsent(consent))
        await model.submitPresentation(accepted: true)
        #expect(await openID4VC.completedPIDClaimIDs == [Set(["required-pid"])])
        #expect(model.eudiFlow == .idle)
    }

    @Test("PID completion routes a follow-up web interaction and starts polling")
    func openID4VCPIDPresentationContinuesInBrowser() async {
        await confirmation("Web authorization was polled") { polled in
            let interactionID = UUID()
            let presentation = OpenID4VPPresentationRequest(
                id: interactionID,
                authorizationChallengeEndpoint: URL(string: "https://issuer.example/authorize-challenge")!,
                authSession: "vp-session",
                interactionType: "urn:openid:dcp:ia:openid4vp_presentation",
                responseMode: "ia_post",
                responseURI: URL(string: "https://issuer.example/authorize-challenge")!,
                nonce: "nonce",
                state: "state",
                dcqlQuery: ["credentials": .array([.object([
                    "id": .string("pid"),
                    "format": .string("dc+sd-jwt"),
                ])])],
                signedRequest: nil
            )
            let web = WebAuthorizationChallenge(
                id: interactionID,
                authSession: "web-session",
                authorizationURL: URL(string: "https://login.example/session")!,
                authorizationChallengeEndpoint: URL(string: "https://issuer.example/authorize-challenge")!
            )
            let openID4VC = FixtureOpenID4VCWallet(
                outcome: .allow,
                interactionID: interactionID,
                continuation: .presentationRequired(presentation),
                pidPresentationRequest: fixturePresentationRequest(),
                pidCompletion: .webAuthorizationRequired(web),
                onWebAuthorizationPoll: { polled() }
            )
            let model = WalletAppModel()
            await model.load(.success(WalletAppDependencies(
                credentials: EmptyMetadataRepository(), audit: EmptyAuditRepository(),
                localAuthenticator: FixtureAuthenticator(), eudiWallet: FixtureEudiWallet(),
                eudiAvailability: .available, openID4VCWallet: openID4VC
            )))
            model.scanInput = "openid-credential-offer://?credential_offer=fixture"
            await model.reviewScannedRequest()
            await model.issueReviewedOpenID4VCCredential()
            await model.startEudiCredentialPresentation(presentation)
            await model.submitPresentation(accepted: true)
            await openID4VC.waitForWebAuthorizationPoll()

            #expect(model.webAuthorizationURL == web.authorizationURL)
            await model.cancelOpenID4VCTrustWarning()
        }
    }

    @Test("Deferred credential retry forwards issuer and document and reports outcome")
    func deferredCredentialRetry() async {
        let record = CredentialRecord(
            configurationID: "deferred", walletDocumentID: "deferred-document", displayName: "Deferred credential",
            format: .sdJWTVC, profileID: "eudi-final-1", issuerIdentifier: "https://issuer.example",
            createdAt: Date(timeIntervalSince1970: 1_700_000_000)
        )
        let deferred = EudiWalletDocumentSummary(
            id: "deferred-document", documentType: "credential", displayName: "Deferred credential",
            format: "sjwt", status: "deferred"
        )
        let issued = EudiWalletDocumentSummary(
            id: "deferred-document", documentType: "credential", displayName: "Deferred credential",
            format: "sjwt", status: "issued"
        )
        let service = FixtureEudiWallet(summaries: [deferred], retryResult: issued)
        let model = WalletAppModel()
        await model.load(.success(WalletAppDependencies(
            credentials: FixedMetadataRepository(records: [record]), audit: EmptyAuditRepository(),
            localAuthenticator: FixtureAuthenticator(), eudiWallet: service, eudiAvailability: .available, openID4VCWallet: nil
        )))
        model.selectCredential(record)
        await model.retrySelectedDeferredCredential()
        #expect(await service.lastRetried == "https://issuer.example:deferred-document")
        #expect(model.documentStatus(for: record) == "issued")
        #expect(model.credentialActionState == .completed("Credential issuance completed."))

        let pendingService = FixtureEudiWallet(summaries: [deferred], retryResult: deferred)
        let pendingModel = WalletAppModel()
        await pendingModel.load(.success(WalletAppDependencies(
            credentials: FixedMetadataRepository(records: [record]), audit: EmptyAuditRepository(),
            localAuthenticator: FixtureAuthenticator(), eudiWallet: pendingService, eudiAvailability: .available, openID4VCWallet: nil
        )))
        pendingModel.selectCredential(record)
        await pendingModel.retrySelectedDeferredCredential()
        #expect(pendingModel.documentStatus(for: record) == "deferred")
        #expect(pendingModel.credentialActionState == .completed("Credential is still pending at the issuer."))
    }

    private func testDependencies(_ service: FixtureEudiWallet) -> WalletAppDependencies {
        WalletAppDependencies(
            credentials: EmptyMetadataRepository(), audit: EmptyAuditRepository(),
            localAuthenticator: FixtureAuthenticator(), eudiWallet: service, eudiAvailability: .available, openID4VCWallet: nil
        )
    }


    private func fixturePending() -> EudiPendingIssuance {
        EudiPendingIssuance(
            id: UUID(),
            document: EudiWalletDocumentSummary(
                id: "pending-wallet-document", documentType: "pid", displayName: "PID upgrade",
                format: "sjwt", status: "pending"
            )
        )
    }

    private func fixturePresentationRequest() -> EudiPresentationRequest {
        EudiPresentationRequest(
            id: UUID(), verifierName: "Issuer verifier", verifierLegalName: nil,
            verifierCertificateValid: true,
            claims: [EudiRequestedClaim(
                id: "required-pid", documentID: "pid", documentType: "pid", displayName: "PID",
                claimPath: ["family_name"], displayValue: "Holder", required: true, intentToRetain: false
            )], warningCount: 0
        )
    }
}

private enum TestFailure: Error { case unavailable }

private actor FixtureOpenID4VCWallet: OpenID4VCOperating {
    func backfillCredentialValidity() async {}
    let interactionID: UUID
    let outcome: EbsiTrustGateOutcome
    private(set) var continueCalls: [Bool] = []
    private(set) var cancelCount = 0
    let continuationDelayNanoseconds: UInt64
    let continuation: OpenID4VCInteractionCompletion
    let pidCompletion: OpenID4VCInteractionCompletion
    let onWebAuthorizationPoll: (@Sendable () -> Void)?
    private(set) var completedAuthorizationCodes: [String] = []
    private(set) var completedPIDClaimIDs: [Set<String>] = []
    private(set) var completedStandaloneClaimIDs: [Set<String>] = []
    private(set) var deletedCredentials: [(UUID, CredentialID)] = []
    private(set) var resolveCount = 0
    private(set) var presentationBeginCount = 0
    private(set) var deferredResumeCount = 0
    private(set) var deferredCheckCount = 0
    private var didPollWebAuthorization = false
    private var webAuthorizationPollWaiters: [CheckedContinuation<Void, Never>] = []
    private var deferred: [DeferredIssuance]
    let pidPresentationRequest: EudiPresentationRequest?
    let standalonePresentationRequest: EudiPresentationRequest?
    init(
        outcome: EbsiTrustGateOutcome,
        interactionID: UUID = UUID(),
        continuationDelayNanoseconds: UInt64 = 0,
        continuation: OpenID4VCInteractionCompletion = .completed("EBSI development flow completed."),
        pidPresentationRequest: EudiPresentationRequest? = nil,
        standalonePresentationRequest: EudiPresentationRequest? = nil,
        deferred: [DeferredIssuance] = [],
        pidCompletion: OpenID4VCInteractionCompletion = .completed("W3C PID submitted"),
        onWebAuthorizationPoll: (@Sendable () -> Void)? = nil
    ) {
        self.outcome = outcome
        self.interactionID = interactionID
        self.continuationDelayNanoseconds = continuationDelayNanoseconds
        self.continuation = continuation
        self.pidPresentationRequest = pidPresentationRequest
        self.standalonePresentationRequest = standalonePresentationRequest
        self.deferred = deferred
        self.pidCompletion = pidCompletion
        self.onWebAuthorizationPoll = onWebAuthorizationPoll
    }
    func resolveInteraction(uri: String) async throws -> OpenID4VCResolvedInteraction {
        resolveCount += 1
        return OpenID4VCResolvedInteraction(
            id: interactionID, kind: .issuance,
            counterpartyIdentifier: "did:ebsi:unregistered-issuer",
            displayName: "Development issuer", trustOutcome: outcome,
            transactionCodeRequired: true,
            transactionCodeLength: 6,
            transactionCodeDescription: "Enter test PIN",
            configurationIDs: ["example-vcdm2-jwt-vc"], authorizationRequired: true,
            representations: ["application/vc+jwt"], credentialDisplay: [:]
        )
    }
    func beginPresentation(uri: String) async throws -> EudiPresentationRequest {
        presentationBeginCount += 1
        guard let standalonePresentationRequest else { throw EbsiCredentialError.unsupportedRepresentation }
        return standalonePresentationRequest
    }
    func completePresentation(
        id: UUID,
        selectedOptionID: String?,
        selectedClaimIDs: Set<String>,
        userAccepted: Bool
    ) async throws -> URL? {
        completedStandaloneClaimIDs.append(selectedClaimIDs)
        return nil
    }
    func continueInteraction(
        id: UUID,
        allowUntrusted: Bool,
        transactionCode: String?
    ) async throws -> OpenID4VCInteractionCompletion {
        continueCalls.append(allowUntrusted)
        if continuationDelayNanoseconds > 0 {
            try await Task.sleep(nanoseconds: continuationDelayNanoseconds)
        }
        if allowUntrusted, case .credentialSignerTrustWarning = continuation {
            return .completed("Staged credential stored.")
        }
        return continuation
    }
    func cancelInteraction(id: UUID) async { cancelCount += 1 }
    func deferredIssuances() async throws -> [DeferredIssuance] { deferred }
    func checkDeferredIssuance(
        id: UUID,
        allowUntrustedSigner: Bool
    ) async throws -> OpenID4VCInteractionCompletion {
        deferredCheckCount += 1
        return .pending("Credential is still pending at the issuer.")
    }
    func removeDeferredIssuance(id: UUID) async throws { deferred.removeAll { $0.id == id } }
    func resumeEligibleDeferredIssuances() async { deferredResumeCount += 1 }
    func preparePIDPresentation(id: UUID) async throws -> EudiPresentationRequest {
        guard let pidPresentationRequest else { throw TestFailure.unavailable }
        return pidPresentationRequest
    }
    func completePIDPresentation(
        id: UUID,
        selectedOptionID: String?,
        selectedClaimIDs: Set<String>,
        userAccepted: Bool
    ) async throws -> OpenID4VCInteractionCompletion {
        completedPIDClaimIDs.append(selectedClaimIDs)
        return userAccepted ? pidCompletion : .completed("PID request declined")
    }
    func completeAuthorization(id: UUID, code: String) async throws -> OpenID4VCInteractionCompletion {
        completedAuthorizationCodes.append(code)
        return .completed("Authorization completed")
    }
    func continueWebAuthorization(
        id: UUID,
        authSession: String
    ) async throws -> OpenID4VCInteractionCompletion {
        .completed("Authorization completed")
    }
    func pollWebAuthorization(id: UUID) async throws -> WebAuthorizationPollResult {
        didPollWebAuthorization = true
        let waiters = webAuthorizationPollWaiters
        webAuthorizationPollWaiters.removeAll()
        waiters.forEach { $0.resume() }
        onWebAuthorizationPoll?()
        return .pending
    }
    func waitForWebAuthorizationPoll() async {
        if didPollWebAuthorization { return }
        await withCheckedContinuation { continuation in
            webAuthorizationPollWaiters.append(continuation)
        }
    }
    func deleteCredential(
        backendID: UUID,
        metadataID: CredentialID,
        issuerIdentifier: String
    ) async throws {
        deletedCredentials.append((backendID, metadataID))
    }
    func canRefreshCredential(id: CredentialID) async -> Bool { false }
    func refreshCredential(
        id: CredentialID, allowUntrustedSigner: Bool
    ) async throws -> W3CCredentialRefreshCompletion { throw TestFailure.unavailable }
    func setAutomaticRefresh(id: CredentialID, enabled: Bool) async throws -> CredentialRecord {
        throw TestFailure.unavailable
    }
    func refreshContinuations() async throws -> [CredentialRefreshContinuation] { [] }
    func resumeEligibleAutomaticRefreshes() async {}
}

private actor FixtureEudiWallet: EudiWalletOperating {
    let profileID = "fixture-eudi-profile"
    private(set) var issueCount = 0
    private(set) var operationCount = 0
    private(set) var lastSelectedClaims: Set<String> = []
    private let pendingAtLoad: [EudiPendingIssuance]
    private let presentationRequest: EudiPresentationRequest?
    private let completion: EudiPresentationCompletion
    private let failCompletion: Bool
    private let summaries: [EudiWalletDocumentSummary]
    private let retryResult: EudiWalletDocumentSummary?
    private(set) var lastDeleted: String?
    private(set) var lastRetried: String?
    private(set) var lastPresentationRequestURI: String?
    private(set) var lastIssuanceOfferURI: String?
    private(set) var lastIssuedProfileID: String?
    private(set) var lastTransactionCode: String?

    init(
        pendingAtLoad: [EudiPendingIssuance] = [],
        presentationRequest: EudiPresentationRequest? = nil,
        completion: EudiPresentationCompletion = .presentation,
        failCompletion: Bool = false,
        summaries: [EudiWalletDocumentSummary] = [],
        retryResult: EudiWalletDocumentSummary? = nil
    ) {
        self.pendingAtLoad = pendingAtLoad
        self.presentationRequest = presentationRequest
        self.completion = completion
        self.failCompletion = failCompletion
        self.summaries = summaries
        self.retryResult = retryResult
    }
    func resolveIssuanceOffer(uri: String) async throws -> EudiIssuanceOffer {
        operationCount += 1
        lastIssuanceOfferURI = uri
        return EudiIssuanceOffer(
            id: UUID(),
            issuerName: "Fixture issuer",
            issuerLogoURL: nil,
            documents: [EudiIssuanceOfferDocument(
                configurationID: "pid",
                documentType: "urn:eu.europa.ec.eudi:pid:1",
                displayName: "PID",
                supportedAlgorithms: ["ES256"]
            )],
            transactionCode: nil
        )
    }
    func issueResolvedOffer(
        id: UUID,
        profileID: String,
        selectedConfigurationIDs: Set<String>,
        transactionCode: String?,
        promptMessage: String
    ) async throws -> EudiIssuanceResult {
        operationCount += 1
        issueCount += 1
        lastIssuedProfileID = profileID
        lastTransactionCode = transactionCode
        return EudiIssuanceResult(documents: [], metadata: [], warningCount: 0, pendingIssuances: [])
    }
    func beginOpenID4VPPresentation(requestURI: String) async throws -> EudiPresentationRequest {
        operationCount += 1
        lastPresentationRequestURI = requestURI
        guard let presentationRequest else { throw TestFailure.unavailable }
        return presentationRequest
    }
    func submitPresentation(
        id: UUID,
        selectedOptionID: String?,
        selectedClaimIDs: Set<String>,
        userAccepted: Bool
    ) async throws -> EudiPresentationResult { throw TestFailure.unavailable }
    func beginPendingIssuancePresentation(id: UUID) async throws -> EudiPresentationRequest {
        operationCount += 1
        guard let presentationRequest else { throw TestFailure.unavailable }
        return presentationRequest
    }
    func completePresentation(
        id: UUID,
        pendingIssuanceID: UUID?,
        selectedOptionID: String?,
        selectedClaimIDs: Set<String>,
        userAccepted: Bool
    ) async throws -> EudiPresentationCompletion {
        operationCount += 1
        if failCompletion { throw TestFailure.unavailable }
        lastSelectedClaims = selectedClaimIDs
        return completion
    }
    func loadDocumentSummaries() async throws -> [EudiWalletDocumentSummary] { operationCount += 1; return summaries }
    func loadStartupSnapshot() async throws -> EudiWalletStartupSnapshot {
        operationCount += 1
        return EudiWalletStartupSnapshot(
            metadata: [],
            documents: summaries,
            pendingIssuances: pendingAtLoad
        )
    }
    func deleteDocument(id: String, status: String) async throws {
        operationCount += 1; lastDeleted = "\(id):\(status)"
    }
    func retryDeferredIssuance(issuerName: String, documentID: String) async throws -> EudiWalletDocumentSummary {
        operationCount += 1; lastRetried = "\(issuerName):\(documentID)"
        guard let retryResult else { throw TestFailure.unavailable }
        return retryResult
    }
}

private actor EmptyMetadataRepository: CredentialMetadataRepository {
    func credentials() async throws -> [CredentialRecord] { [] }
    func saveMetadata(_ credential: CredentialRecord) async throws {}
    func replaceMetadata(_ credential: CredentialRecord) async throws {}
    func deleteMetadata(id: CredentialID) async throws {}
}

private actor FixedMetadataRepository: CredentialMetadataRepository {
    private var records: [CredentialRecord]
    init(records: [CredentialRecord]) { self.records = records }
    func credentials() async throws -> [CredentialRecord] { records }
    func saveMetadata(_ credential: CredentialRecord) async throws { records.append(credential) }
    func replaceMetadata(_ credential: CredentialRecord) async throws {
        records.removeAll { $0.id == credential.id }; records.append(credential)
    }
    func deleteMetadata(id: CredentialID) async throws { records.removeAll { $0.id == id } }
}

private actor EmptyAuditRepository: AuditRepository {
    func events() async throws -> [AuditEvent] { [] }
    func append(_ event: AuditEvent) async throws {}
    func deleteAll() async throws {}
}

private actor CountingAuditRepository: AuditRepository {
    private(set) var loadCount = 0
    func events() async throws -> [AuditEvent] { loadCount += 1; return [] }
    func append(_ event: AuditEvent) async throws {}
    func deleteAll() async throws {}
}

private struct FixtureAuthenticator: LocalAuthenticator {
    func authenticate(reason: String) async throws {}
}

private actor FixtureAppLockAuthenticator: AppLockAuthenticating {
    nonisolated let kind: DeviceAuthenticationKind
    private let shouldFail: Bool
    private(set) var callCount = 0

    init(kind: DeviceAuthenticationKind = .faceID, shouldFail: Bool = false) {
        self.kind = kind
        self.shouldFail = shouldFail
    }

    nonisolated func availability() -> DeviceAuthenticationKind { kind }

    func authenticateAppLock(reason: String) async throws {
        callCount += 1
        if shouldFail { throw TestFailure.unavailable }
    }

    func waitForCallCount(_ expected: Int) async {
        while callCount < expected { await Task.yield() }
    }
}

private actor InitializationCounter {
    private(set) var count = 0
    func recordCall() { count += 1 }
}

private actor SuspendingAppLockAuthenticator: AppLockAuthenticating {
    nonisolated func availability() -> DeviceAuthenticationKind { .faceID }
    private(set) var callCount = 0
    private var continuations: [CheckedContinuation<Void, Error>] = []

    func authenticateAppLock(reason: String) async throws {
        callCount += 1
        try await withCheckedThrowingContinuation { continuation in
            continuations.append(continuation)
        }
    }

    func completeNext() {
        guard !continuations.isEmpty else { return }
        continuations.removeFirst().resume()
    }

    func waitForCallCount(_ expected: Int) async {
        while callCount < expected { await Task.yield() }
    }
}
