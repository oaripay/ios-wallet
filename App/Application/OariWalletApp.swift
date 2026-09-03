import SwiftUI
import OariDesignSystem

@main
@MainActor
struct OariWalletApp: App {
    @Environment(\.scenePhase) private var scenePhase
    @StateObject private var model: WalletAppModel
    private let configuration: AppConfiguration

    init() {
#if os(iOS) && canImport(BackgroundTasks)
        CredentialMaintenanceCoordinator.shared.register()
#endif
        let configuration = AppConfiguration.current()
        if configuration.isUITesting {
            UserDefaults.standard.set(false, forKey: "oari.security.app-lock.enabled")
            UserDefaults.standard.set(true, forKey: "oari.security.app-lock.setup-completed")
        }
        self.configuration = configuration
        _model = StateObject(
            wrappedValue: WalletAppModel(
                allowedHosts: configuration.allowedHosts,
                showsOnboarding: configuration.fixture == .production &&
                    !UserDefaults.standard.bool(forKey: "oari.onboarding.completed")
            )
        )
    }

    var body: some Scene {
        WindowGroup {
            ZStack {
                if showsStartupSplash {
                    WalletLoadingOverlay(accessibilityLabel: "Oari Wallet is preparing your secure wallet")
                        .task { await bootstrapWallet() }
                        .transition(.opacity)
                        .zIndex(10)
                } else {
                    WalletRootView(model: model)
                }
            }
            .preferredColorScheme(model.theme.colorScheme)
            .onOpenURL(perform: model.handleIncomingURL)
            .overlay {
                if model.isEudiOperationLoading {
                    WalletLoadingOverlay(accessibilityLabel: "Preparing your wallet")
                        .transition(.identity)
                        .zIndex(110)
                } else if model.shouldShowInactivePrivacyShield || model.isAppLockBlocking {
                    WalletPrivacyShield(
                        model: model,
                        isSpinning: model.shouldShowInactivePrivacyShield || model.appLockState == .authenticating
                    )
                        .transition(.identity)
                        .zIndex(100)
                }
            }
            .sheet(isPresented: $model.showsAppLockSetup) {
                WalletAppLockSetupView(model: model, allowsDismissal: false)
                    .interactiveDismissDisabled()
                    .presentationDetents([.medium])
            }
            .onChange(of: scenePhase) { _, phase in
                Task {
                    await model.handleScenePhase(appLifecyclePhase(phase))
#if os(iOS) && canImport(BackgroundTasks)
                    if phase == .background {
                        await CredentialMaintenanceCoordinator.shared.schedule()
                    }
#endif
                }
            }
            .transaction { transaction in
                if configuration.disablesAnimations { transaction.disablesAnimations = true }
            }
            .animation(.easeOut(duration: 0.28), value: showsStartupSplash)
        }
    }

    private var showsStartupSplash: Bool {
        switch model.loadingState {
        case .idle, .loading: true
        case .loaded, .failed: false
        }
    }

    private func bootstrapWallet() async {
        await Task.yield()
        let task = Task.detached(priority: .userInitiated) {
            switch WalletAppDependencies.make(configuration: configuration) {
            case let .success(dependencies): WalletBootstrapResult.success(dependencies)
            case let .failure(error): WalletBootstrapResult.failure(WalletBootstrapError(message: String(describing: error)))
            }
        }
        let bootstrap = await withCheckedContinuation { continuation in
            let gate = ContinuationGate<WalletBootstrapResult>()
            Task { gate.resume(continuation, returning: await task.value) }
            Task {
                try? await Task.sleep(for: .seconds(12))
                gate.resume(continuation, returning: .failure(WalletBootstrapError(
                    message: "Wallet startup is taking longer than expected. Try again."
                )))
            }
        }
        let dependencies: Result<WalletAppDependencies, Error> = switch bootstrap {
        case let .success(value): .success(value)
        case let .failure(error): .failure(error)
        }
#if os(iOS) && canImport(BackgroundTasks)
        if case let .success(value) = dependencies, let maintenance = value.deferredIssuanceMaintenance {
            CredentialMaintenanceCoordinator.shared.installDeferredIssuance(
                nextDeadline: maintenance.nextDeadline,
                operation: maintenance.operation
            )
        }
        if case let .success(value) = dependencies, let maintenance = value.automaticRefreshMaintenance {
            CredentialMaintenanceCoordinator.shared.installAutomaticRefresh(
                nextDeadline: maintenance.nextDeadline,
                operation: maintenance.operation
            )
        }
#endif
        await model.handleScenePhase(appLifecyclePhase(scenePhase))
        await model.load(dependencies)
        if let incomingURL = configuration.incomingURL { model.handleIncomingURL(incomingURL) }
    }

    private func appLifecyclePhase(_ phase: ScenePhase) -> WalletAppModel.AppLifecyclePhase {
        switch phase {
        case .active: .active
        case .inactive: .inactive
        case .background: .background
        @unknown default: .inactive
        }
    }
}

private final class ContinuationGate<Value: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var didResume = false

    func resume(_ continuation: CheckedContinuation<Value, Never>, returning value: Value) {
        lock.lock()
        guard !didResume else {
            lock.unlock()
            return
        }
        didResume = true
        lock.unlock()
        continuation.resume(returning: value)
    }
}

private enum WalletBootstrapResult: Sendable {
    case success(WalletAppDependencies)
    case failure(WalletBootstrapError)
}

private struct WalletBootstrapError: LocalizedError, Sendable {
    let message: String
    var errorDescription: String? { message }
}

struct WalletLoadingOverlay: View {
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var rotation: Double = 0
    let accessibilityLabel: String

    var body: some View {
        ZStack {
            Color("LaunchBackground").ignoresSafeArea()
            Image("OariMark")
                .resizable()
                .opacity(0.5)
                .scaledToFit()
                .frame(width: 180, height: 180)
                .rotationEffect(.degrees(rotation))
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel(accessibilityLabel)
        .onAppear {
            guard !reduceMotion else { return }
            withAnimation(.linear(duration: 2).repeatForever(autoreverses: false)) { rotation = 360 }
        }
    }
}
