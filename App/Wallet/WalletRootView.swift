import OariDesignSystem
import SwiftUI

struct WalletRootView: View {
    @Environment(\.openURL) private var openURL
    @ObservedObject var model: WalletAppModel
    @State private var isCameraPresented = false

    var body: some View {
        TabView(selection: $model.selectedTab) {
            WalletVaultView(model: model)
                .tag(WalletAppModel.Tab.wallet)
                .tabItem {
                    Label("Wallet", systemImage: "wallet.pass")
                        .accessibilityIdentifier("tab.wallet")
                }
            WalletScannerView(model: model)
                .tag(WalletAppModel.Tab.scan)
                .tabItem {
                    Label("Scan", systemImage: "qrcode.viewfinder")
                        .accessibilityIdentifier("tab.scan")
                }
            WalletHistoryView(model: model)
                .tag(WalletAppModel.Tab.history)
                .tabItem {
                    Label("History", systemImage: "clock.arrow.circlepath")
                        .accessibilityIdentifier("tab.history")
                }
            WalletSettingsView(model: model)
                .tag(WalletAppModel.Tab.settings)
                .tabItem {
                    Label("Settings", systemImage: "gearshape")
                        .accessibilityIdentifier("tab.settings")
                }
        }
        .tint(OariColor.action)
        .overlay(alignment: .bottomTrailing) {
            Button {
                isCameraPresented = true
            } label: {
                Image(systemName: "qrcode.viewfinder")
                    .font(.system(size: 22, weight: .semibold))
                    .foregroundStyle(OariColor.textOnAction)
                    .frame(width: 60, height: 60)
                    .oariGlassAction()
            }
            .accessibilityLabel("Scan QR code")
            .accessibilityHint("Opens the camera to scan a credential offer or presentation request")
            .accessibilityIdentifier("root.scan-camera")
            .padding(.trailing, OariSpacing.x5)
            .padding(.bottom, 92)
        }
        .fullScreenCover(isPresented: $isCameraPresented) {
            CameraQRScannerSheet(onCode: model.handleScannedCode)
        }
        .sheet(isPresented: Binding(
            get: {
                switch model.eudiFlow {
                case .issuanceReview, .openID4VCIssuanceReview, .openID4VPPresentationRequired, .presentationConsent, .pending, .completed, .failed, .working:
                    true
                case .idle, .configurationRequired:
                    false
                }
            },
            set: { if !$0 { model.dismissEudiFlow() } }
        )) {
            EudiFlowView(model: model)
                .presentationDetents([.large])
                .presentationDragIndicator(.visible)
                .interactiveDismissDisabled(model.preventsInteractiveFlowDismissal)
        }
        .fullScreenCover(isPresented: $model.showsOnboarding) {
            WalletOnboardingView(model: model)
                .interactiveDismissDisabled()
        }
        .sheet(item: $model.openID4VCTrustWarning) { warning in
            TrustWarningView(warning: warning) {
                Task { await model.continueAfterOpenID4VCTrustWarning() }
            } cancel: {
                Task { await model.cancelOpenID4VCTrustWarning() }
            }
            .presentationDetents([.medium, .large])
            .interactiveDismissDisabled()
        }
        .onChange(of: model.pendingExternalURL) { _, url in
            guard let url else { return }
            openURL(url)
            model.clearPendingExternalURL()
        }
    }
}

struct WalletPrivacyShield: View {
    @Environment(\.colorScheme) private var scheme
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @ObservedObject var model: WalletAppModel
    let isSpinning: Bool

    var body: some View {
        ZStack {
            OariColor.background(scheme).ignoresSafeArea()
            Image("OariMark")
                .resizable()
                .scaledToFit()
                .opacity(0.5)
                .frame(width: 180, height: 180)
        }
        .contentShape(Rectangle())
        .onTapGesture {
            guard model.requiresForegroundUnlock,
                  model.appLockState != .authenticating else { return }
            Task { await model.unlockApp() }
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel(model.requiresForegroundUnlock ? "Oari Wallet locked" : "Wallet content hidden")
        .accessibilityHint(canRetry ? "Double tap to authenticate" : "")
        .accessibilityAddTraits(canRetry ? .isButton : [])
        .accessibilityIdentifier("privacy.cover")
    }

    private var canRetry: Bool {
        model.requiresForegroundUnlock && model.appLockState != .authenticating
    }

}
