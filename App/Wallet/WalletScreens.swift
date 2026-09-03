import OariDesignSystem
import EudiWalletKitAdapter
import SwiftUI
import UIKit
import WalletDomain

private extension CredentialStatusState {
    var displayText: String {
        switch self {
        case .valid: "Valid"
        case .suspended: "Suspended"
        case .revoked: "Revoked"
        case .indeterminate: "Status unavailable"
        case .notProvided: "No status mechanism provided"
        case .notEvaluated: "Status not checked"
        }
    }
}

private extension CredentialRecord {
    var cardStatusText: String {
        switch status {
        case .revoked: return "Revoked"
        case .suspended: return "Suspended"
        case .indeterminate: return "Status unavailable"
        case .valid, .notProvided, .notEvaluated: break
        }
        switch issuerTrust {
        case .trusted: return "Trusted issuer"
        case .untrusted: return "Issuer warning"
        case .invalid: return "Invalid issuer"
        case .indeterminate: return "Issuer status unavailable"
        case .notEvaluated: return "Issuer not evaluated"
        }
    }
}

struct WalletVaultView: View {
    @Environment(\.colorScheme) private var scheme
    @ObservedObject var model: WalletAppModel
    @State private var searchText = ""
    @State private var filter: CredentialFilter = .all
    @State private var deferredRemovalID: UUID?

    private enum CredentialFilter: String, CaseIterable, Identifiable {
        case all = "All"
        case valid = "Valid"
        case pending = "Pending"
        case warnings = "Warnings"
        var id: String { rawValue }
    }

    var body: some View {
        NavigationStack {
            List {
                if case let .failed(message) = model.loadingState {
                    Section {
                        Label("Wallet services unavailable", systemImage: "exclamationmark.triangle.fill")
                            .foregroundStyle(.red)
                        Text(message).font(.caption).foregroundStyle(.secondary)
                    }
                    .accessibilityIdentifier("wallet.storage-error")
                }
                if !model.deferredIssuances.isEmpty {
                    Section("Issuing credentials") {
                        ForEach(model.deferredIssuances) { issuance in
                            DeferredCredentialCard(
                                issuance: issuance,
                                isChecking: model.checkingDeferredIssuanceIDs.contains(issuance.id),
                                onCheck: { Task { await model.checkDeferredIssuance(id: issuance.id) } },
                                onRemove: { deferredRemovalID = issuance.id }
                            )
                            .listRowInsets(EdgeInsets(top: 5, leading: 16, bottom: 5, trailing: 16))
                            .listRowBackground(Color.clear)
                            .listRowSeparator(.hidden)
                            .accessibilityIdentifier("wallet.deferred.\(issuance.id.uuidString)")
                        }
                    }
                }
                if model.credentials.isEmpty && model.deferredIssuances.isEmpty {
                    ContentUnavailableView(
                        "Your wallet is empty",
                        systemImage: "wallet.pass",
                        description: Text("Scan a credential offer to add your first credential.")
                    )
                    .listRowBackground(Color.clear)
                } else {
                    Section {
                        ForEach(filteredCredentials) { credential in
                            Button { model.selectCredential(credential) } label: {
                                CredentialListRow(credential: credential)
                            }
                            .buttonStyle(.plain)
                            .listRowInsets(EdgeInsets(top: 5, leading: 16, bottom: 5, trailing: 16))
                            .listRowBackground(Color.clear)
                            .listRowSeparator(.hidden)
                        }
                    } header: {
                        HStack {
                            Text("Credentials")
                            Spacer()
                            Text("\(filteredCredentials.count)").foregroundStyle(.secondary)
                        }
                    }
                }
            }
            .listStyle(.insetGrouped)
            .scrollContentBackground(.hidden)
            .background(OariColor.background(scheme).ignoresSafeArea())
            .searchable(text: $searchText, prompt: "Search credentials")
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Menu {
                        Picker("Filter", selection: $filter) {
                            ForEach(CredentialFilter.allCases) { Text($0.rawValue).tag($0) }
                        }
                    } label: { Image(systemName: "line.3.horizontal.decrease.circle") }
                    .accessibilityLabel("Filter credentials")
                }
            }
            .navigationTitle("Wallet")
        }
        .sheet(item: $model.selectedCredential) { credential in
            CredentialDetailView(model: model, credential: credential)
                .presentationDetents([.medium, .large])
        }
        .alert("Remove pending transaction?", isPresented: Binding(
            get: { deferredRemovalID != nil },
            set: { if !$0 { deferredRemovalID = nil } }
        )) {
            Button("Remove locally", role: .destructive) {
                guard let id = deferredRemovalID else { return }
                deferredRemovalID = nil
                Task { await model.removeDeferredIssuance(id: id) }
            }
            Button("Keep", role: .cancel) { deferredRemovalID = nil }
        } message: {
            Text("This removes only the wallet's local pending transaction. It does not cancel processing at the issuer.")
        }
    }

    private var filteredCredentials: [CredentialRecord] {
        model.credentials.filter { credential in
            let matchesSearch = searchText.isEmpty || [credential.displayName, credential.issuerIdentifier, credential.profileID, credential.format.rawValue]
                .contains { $0.localizedCaseInsensitiveContains(searchText) }
            let matchesFilter: Bool
            switch filter {
            case .all: matchesFilter = true
            case .valid: matchesFilter = credential.status == .valid
            case .pending: matchesFilter = model.documentStatus(for: credential) == "pending" || model.documentStatus(for: credential) == "deferred"
            case .warnings: matchesFilter = credential.issuerTrust != .trusted || credential.status == .indeterminate
            }
            return matchesSearch && matchesFilter
        }
    }

}

private struct DeferredCredentialCard: View {
    @Environment(\.colorScheme) private var scheme
    let issuance: DeferredIssuance
    let isChecking: Bool
    let onCheck: () -> Void
    let onRemove: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .top, spacing: 12) {
                Image(systemName: statusIcon)
                    .font(.title2)
                    .foregroundStyle(statusColor)
                    .frame(width: 30)
                VStack(alignment: .leading, spacing: 3) {
                    Text(issuance.displayName)
                        .font(.headline)
                    Text(issuance.issuerIdentifier)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(2)
                }
                Spacer(minLength: 8)
                Menu {
                    Button("Remove local transaction", role: .destructive, action: onRemove)
                } label: {
                    Image(systemName: "ellipsis.circle")
                        .font(.title3)
                }
                .accessibilityLabel("More options for \(issuance.displayName)")
            }

            Text(statusText)
                .font(.subheadline.weight(.semibold))
            if let guidanceText {
                Text(guidanceText)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            if showsCheckButton {
                Button(action: onCheck) {
                    HStack {
                        if isChecking { ProgressView().controlSize(.small) }
                        Text(isChecking ? "Checking…" : checkButtonTitle)
                            .frame(maxWidth: .infinity)
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled(isChecking || !canCheck)
                .accessibilityHint("Checks whether the issuer has finished creating this credential")
            }
        }
        .padding(16)
        .background(OariColor.surface(scheme), in: RoundedRectangle(cornerRadius: OariRadius.large, style: .continuous))
    }

    private var canCheck: Bool {
        issuance.state == .signerTrustRequired || issuance.state == .completing
            || (issuance.state == .pending && issuance.nextAttemptAt <= Date())
    }

    private var showsCheckButton: Bool {
        isChecking || canCheck
    }

    private var checkButtonTitle: String {
        issuance.state == .signerTrustRequired ? "Review issuer" : "Check now"
    }

    private var statusText: String {
        if isChecking { return "Checking with the issuer…" }
        switch issuance.state {
        case .pending:
            return issuance.nextAttemptAt > Date()
                ? "We’ll check automatically after \(issuance.nextAttemptAt.formatted(date: .omitted, time: .shortened))"
                : "Ready to check"
        case .authorizationRequired: return "Authorization needed"
        case .signerTrustRequired: return "Issuer review needed"
        case .completing: return "Ready to finish secure storage"
        case .failed: return "The credential could not be completed"
        }
    }

    private var guidanceText: String? {
        switch issuance.state {
        case .authorizationRequired:
            "Scan a new offer from the issuer to authorize this request again."
        case .failed:
            "Remove this request, then scan a new credential offer to try again."
        case .pending where issuance.nextAttemptAt > Date():
            "You can leave this screen. The wallet will continue while the app is active."
        default: nil
        }
    }

    private var statusIcon: String {
        if isChecking { return "arrow.triangle.2.circlepath" }
        return switch issuance.state {
        case .pending: "clock.arrow.circlepath"
        case .authorizationRequired: "person.badge.key"
        case .signerTrustRequired: "checkmark.shield"
        case .completing: "lock.open"
        case .failed: "exclamationmark.triangle"
        }
    }

    private var statusColor: Color {
        switch issuance.state {
        case .failed, .authorizationRequired: .orange
        default: OariColor.action
        }
    }
}

private struct CredentialListRow: View {
    @Environment(\.colorScheme) private var scheme
    let credential: CredentialRecord
    var body: some View {
        ZStack {
            OariColor.safeColor(credential.display?.backgroundColor, fallback: OariColor.surface(scheme))
            if let image = credential.display?.backgroundImage {
                LocalCredentialImage(image: image, contentMode: .fill)
                    .opacity(0.72)
                LinearGradient(
                    colors: [.black.opacity(0.08), .black.opacity(0.48)],
                    startPoint: .topLeading,
                    endPoint: .bottomTrailing
                )
            }
            HStack(spacing: 12) {
                credentialLogo(size: 42)
                VStack(alignment: .leading, spacing: 3) {
                    Text(credential.displayName).font(.body.weight(.semibold)).lineLimit(1)
                    Text(credential.issuerIdentifier).font(.caption).opacity(0.78).lineLimit(1)
                }
                Spacer(minLength: 6)
                VStack(alignment: .trailing, spacing: 4) {
                    if credential.issuerTrust == .untrusted {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .font(.caption.weight(.semibold))
                            .foregroundStyle(.orange)
                            .accessibilityLabel("Development warning")
                    } else {
                        Label(statusText, systemImage: statusIcon)
                            .font(.caption2.weight(.semibold))
                            .padding(.horizontal, 8)
                            .padding(.vertical, 5)
                            .background(.ultraThinMaterial, in: Capsule())
                    }
                    Image(systemName: "chevron.right").font(.caption.weight(.semibold)).opacity(0.7)
                }
                .frame(maxHeight: .infinity, alignment: .topTrailing)
            }
            .padding(12)
        }
        .foregroundStyle(cardTextColor)
        .clipShape(RoundedRectangle(cornerRadius: OariRadius.large, style: .continuous))
        .padding(.vertical, 3)
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(credential.displayName), \(statusText)")
        .accessibilityIdentifier("wallet.credential.row.\(credential.configurationID)")
    }

    @ViewBuilder
    private func credentialLogo(size: CGFloat) -> some View {
        if let logo = credential.display?.logo {
            LocalCredentialImage(image: logo, contentMode: .fit)
                .padding(7)
                .frame(width: size, height: size)
                .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 11, style: .continuous))
                .accessibilityLabel(logo.alternativeText ?? "Credential logo")
        } else {
            Image(systemName: credential.format == .mdoc ? "person.text.rectangle.fill" : "doc.text.fill")
                .font(.title3)
                .frame(width: size, height: size)
                .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 11, style: .continuous))
                .accessibilityHidden(true)
        }
    }

    private var cardTextColor: Color {
        OariColor.safeColor(
            credential.display?.textColor,
            fallback: credential.display?.backgroundImage == nil ? OariColor.textPrimary(scheme) : .white
        )
    }

    private var statusText: String {
        credential.cardStatusText
    }

    private var statusIcon: String {
        switch credential.issuerTrust {
        case .trusted: "checkmark.shield.fill"
        case .untrusted: "exclamationmark.triangle.fill"
        case .invalid: "xmark.octagon.fill"
        default: "questionmark.diamond.fill"
        }
    }
}

private struct CredentialDetailView: View {
    @Environment(\.colorScheme) private var scheme
    @ObservedObject var model: WalletAppModel
    let credential: CredentialRecord
    @State private var confirmsDeletion = false
    @State private var supportsRefresh = false

    private var displayedCredential: CredentialRecord {
        model.credentials.first(where: { $0.id == credential.id }) ?? credential
    }

    var body: some View {
        NavigationStack {
            List {
                Section {
                    CredentialHeroCard(credential: displayedCredential)
                        .listRowInsets(EdgeInsets())
                        .listRowBackground(Color.clear)
                }
                Section("Status") {
                    detailRow("Current status", model.documentStatus(for: displayedCredential) ?? "Unavailable")
                    detailRow("Credential status", displayedCredential.status.displayText)
                    detailRow("Issuer trust", displayedCredential.issuerTrust.rawValue)
                    if let issuedAt = displayedCredential.issuedAt { detailRow("Issued", issuedAt.formatted(date: .abbreviated, time: .omitted)) }
                    if let expiresAt = displayedCredential.expiresAt { detailRow("Expires", expiresAt.formatted(date: .abbreviated, time: .omitted)) }
                }
                Section("Credential") {
                    detailRow("Format", displayedCredential.format.rawValue)
                    detailRow("Profile", displayedCredential.profileID)
                    detailRow("Legal profile", displayedCredential.legalClassification.rawValue)
                    NavigationLink("Technical details") {
                        technicalDetails
                    }
                }
                if !displayedCredential.displayClaims.isEmpty {
                    Section("Claims") {
                        ForEach(displayedCredential.displayClaims) { claim in
                            LabeledContent(claim.label, value: claim.value)
                        }
                    }
                }
                Section("Actions") {
                    if supportsRefresh {
                        Button {
                            Task { await model.refreshSelectedCredential() }
                        } label: {
                            Label("Refresh credential", systemImage: "arrow.triangle.2.circlepath")
                        }
                        .disabled(model.credentialActionIsWorking)
                        Toggle("Automatic refresh", isOn: Binding(
                            get: { displayedCredential.refresh.mode == .automatic },
                            set: { enabled in
                                Task { await model.setAutomaticRefresh(enabled, for: displayedCredential) }
                            }
                        ))
                        .disabled(model.credentialActionIsWorking)
                        LabeledContent("Refresh state", value: refreshStateText)
                        if let date = displayedCredential.refresh.lastSuccessfulRefreshAt {
                            LabeledContent("Last refreshed", value: date.formatted(date: .abbreviated, time: .shortened))
                        }
                    }
                    if model.documentStatus(for: displayedCredential) == "deferred" {
                        Button {
                            Task { await model.retrySelectedDeferredCredential() }
                        } label: {
                            Label("Check deferred issuance", systemImage: "arrow.clockwise")
                        }
                        .disabled(model.credentialActionIsWorking || !model.isEudiOperational)
                    }
                    Button(role: .destructive) { confirmsDeletion = true } label: {
                        Label("Remove credential", systemImage: "minus.circle")
                    }
                        .disabled(model.credentialActionIsWorking || !model.canDeleteCredential(displayedCredential))
                    if !model.canDeleteCredential(displayedCredential) {
                        Label(deletionUnavailableMessage, systemImage: "lock.shield")
                            .font(.caption)
                            .foregroundStyle(OariColor.textSecondary(scheme))
                            .accessibilityIdentifier("credential.operationsUnavailable")
                    }
                }
                if model.credentialActionState != .idle {
                    Section { actionStatus }
                }
            }
            .listStyle(.insetGrouped)
            .navigationTitle("Credential details")
            .navigationBarTitleDisplayMode(.inline)
        }
        .alert("Remove credential?", isPresented: $confirmsDeletion) {
            Button("Remove credential", role: .destructive) {
                Task { await model.deleteSelectedCredential() }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text(deletionConfirmationMessage)
        }
        .task(id: credential.id) {
            supportsRefresh = await model.canRefreshCredential(credential)
        }
    }

    private var refreshStateText: String {
        switch displayedCredential.refresh.state {
        case .idle: "Manual"
        case .scheduled:
            displayedCredential.refresh.nextRefreshAt.map {
                "Scheduled \($0.formatted(date: .abbreviated, time: .shortened))"
            } ?? "Scheduled"
        case .refreshing: "Refreshing"
        case .failed: "Paused after a failed attempt"
        }
    }

    private var deletionConfirmationMessage: String {
        if W3CBackendComposition.ownsCredential(backendID: displayedCredential.backendID) {
            return "This removes the credential from encrypted W3C storage and Oari Wallet. Face ID or your device passcode will be required."
        }
        return "This removes the credential from Wallet Kit and Oari Wallet. Face ID or your device passcode will be required."
    }

    private var deletionUnavailableMessage: String {
        W3CBackendComposition.ownsCredential(backendID: displayedCredential.backendID)
            ? "The encrypted W3C credential reference is unavailable."
            : "Install an approved EUDI profile to manage this credential."
    }

    private func detailRow(_ label: String, _ value: String) -> some View {
        LabeledContent(label) { Text(value).foregroundStyle(.secondary).multilineTextAlignment(.trailing) }
    }

    private var technicalDetails: some View {
        List {
            Section("Identifiers") {
                detailRow("Issuer", displayedCredential.issuerIdentifier)
                detailRow("Backend document", displayedCredential.backendDocumentID ?? displayedCredential.walletDocumentID ?? "Unavailable")
                detailRow("Wallet document", displayedCredential.walletDocumentID ?? "Unavailable")
            }
            Section("Processing") {
                detailRow("Backend", displayedCredential.backendID ?? "EUDI Wallet Kit")
                detailRow("Configuration", displayedCredential.configurationID)
            }
        }
        .listStyle(.insetGrouped)
        .navigationTitle("Technical details")
    }

    @ViewBuilder
    private var actionStatus: some View {
        switch model.credentialActionState {
        case .idle: EmptyView()
        case let .working(message): ProgressView(message)
        case let .completed(message):
            Label(message, systemImage: "checkmark.circle.fill").foregroundStyle(.green)
            Button("Done") { model.acknowledgeCredentialAction() }
                .buttonStyle(OariPrimaryButtonStyle())
        case let .failed(message):
            Label(message, systemImage: "exclamationmark.triangle.fill").foregroundStyle(.red)
            Button("Dismiss") { model.dismissCredentialAction() }
        }
    }
}

private struct CredentialHeroCard: View {
    @Environment(\.colorScheme) private var scheme
    let credential: CredentialRecord

    var body: some View {
        VStack(alignment: .leading, spacing: OariSpacing.x3) {
            HStack(alignment: .top) {
                logo
                Spacer()
                Label(statusLabel, systemImage: statusIcon)
                    .font(.caption.weight(.bold))
                    .padding(.horizontal, 10)
                    .padding(.vertical, 6)
                    .background(.ultraThinMaterial, in: Capsule())
            }
            Spacer(minLength: 20)
            Text(credential.displayName)
                .font(.title2.weight(.bold))
                .lineLimit(3)
                .minimumScaleFactor(0.82)
                .fixedSize(horizontal: false, vertical: true)
                .layoutPriority(1)
            Text(issuerLabel)
                .font(.caption)
                .opacity(0.82)
                .lineLimit(2)
                .fixedSize(horizontal: false, vertical: true)
            HStack(spacing: 6) {
                OariBackendBadge(W3CBackendComposition.ownsCredential(backendID: credential.backendID) ? "W3C Verifiable Credential" : "EUDI Wallet Kit")
                Text(credential.format.rawValue)
                    .font(.caption2.weight(.semibold))
                    .padding(.horizontal, 8)
                    .padding(.vertical, 5)
                    .background(.ultraThinMaterial, in: Capsule())
            }
        }
        .padding(OariSpacing.x5)
        .foregroundStyle(textColor)
        .frame(maxWidth: .infinity, minHeight: 260, alignment: .bottomLeading)
        .background { artworkBackground }
        .clipShape(RoundedRectangle(cornerRadius: OariRadius.extraLarge, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: OariRadius.extraLarge, style: .continuous)
                .stroke(.white.opacity(scheme == .dark ? 0.12 : 0.25))
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(credential.displayName), issued by \(credential.issuerIdentifier), \(statusLabel)")
    }

    @ViewBuilder private var artworkBackground: some View {
        ZStack {
            OariColor.safeColor(
                credential.display?.backgroundColor,
                fallback: OariColor.action.opacity(0.13)
            )
            if let background = credential.display?.backgroundImage {
                GeometryReader { geometry in
                    LocalCredentialImage(image: background, contentMode: .fill)
                        .frame(width: geometry.size.width, height: geometry.size.height)
                        .clipped()
                }
                LinearGradient(
                    colors: [.black.opacity(0.02), .black.opacity(0.62)],
                    startPoint: .top,
                    endPoint: .bottom
                )
            }
        }
    }

    @ViewBuilder private var logo: some View {
        if let image = credential.display?.logo {
            LocalCredentialImage(image: image, contentMode: .fit)
                .padding(9)
                .frame(width: 58, height: 58)
                .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 15, style: .continuous))
                .accessibilityLabel(image.alternativeText ?? "Credential logo")
        } else {
            Image(systemName: credential.format == .mdoc ? "person.text.rectangle.fill" : "doc.text.fill")
                .font(.title2)
                .frame(width: 58, height: 58)
                .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 15, style: .continuous))
                .accessibilityHidden(true)
        }
    }

    private var textColor: Color {
        OariColor.safeColor(
            credential.display?.textColor,
            fallback: credential.display?.backgroundImage == nil ? OariColor.textPrimary(scheme) : .white
        )
    }

    private var issuerLabel: String {
        if let url = URL(string: credential.issuerIdentifier), let host = url.host {
            return host
        }
        guard credential.issuerIdentifier.count > 52 else { return credential.issuerIdentifier }
        return "\(credential.issuerIdentifier.prefix(36))...\(credential.issuerIdentifier.suffix(10))"
    }

    private var statusLabel: String {
        credential.cardStatusText
    }

    private var statusIcon: String {
        switch credential.issuerTrust {
        case .trusted: "checkmark.shield.fill"
        case .untrusted: "exclamationmark.triangle.fill"
        case .invalid: "xmark.octagon.fill"
        default: "questionmark.diamond.fill"
        }
    }
}

private struct LocalCredentialImage: View {
    let image: CredentialDisplayImage
    let contentMode: ContentMode

    var body: some View {
        if let uiImage = UIImage(data: image.data) {
            Image(uiImage: uiImage)
                .resizable()
                .aspectRatio(contentMode: contentMode)
        }
    }
}

struct WalletScannerView: View {
    @Environment(\.colorScheme) private var scheme
    @ObservedObject var model: WalletAppModel
    @State private var isCameraPresented = false
    @State private var showsPasteEntry = false
    @FocusState private var inputFocused: Bool

    private var primaryActionTitle: String {
        let trimmed = model.scanInput.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.lowercased().hasPrefix("openid4vp://") ? "Interact" : "Redeem"
    }

    var body: some View {
        NavigationStack {
            OariScreen {
                OariCard {
                    VStack(alignment: .leading, spacing: OariSpacing.x4) {
                        Label("Add or present a credential", systemImage: "qrcode.viewfinder")
                            .font(OariTypography.heading)
                        Text("Scan a QR code from an issuer or verifier.")
                            .foregroundStyle(OariColor.textSecondary(scheme))
                        Button {
                            inputFocused = false
                            isCameraPresented = true
                        } label: {
                            Label("Scan QR code", systemImage: "camera.viewfinder")
                                .frame(maxWidth: .infinity)
                        }
                        .buttonStyle(.borderedProminent)
                        .controlSize(.large)
                        .accessibilityIdentifier("scanner.camera")

                        DisclosureGroup("Paste code instead", isExpanded: $showsPasteEntry) {
                            VStack(alignment: .leading, spacing: OariSpacing.x3) {
                                TextField("Credential offer or presentation URL", text: $model.scanInput, axis: .vertical)
                                    .textInputAutocapitalization(.never)
                                    .autocorrectionDisabled()
                                    .keyboardType(.URL)
                                    .padding(OariSpacing.x3)
                                    .background(OariColor.surfaceInset(scheme))
                                    .clipShape(RoundedRectangle(cornerRadius: OariRadius.medium))
                                    .accessibilityLabel("Wallet code")
                                    .accessibilityIdentifier("scanner.input")
                                    .focused($inputFocused)
                                    .onSubmit { inputFocused = false }
                                Button(primaryActionTitle) {
                                    inputFocused = false
                                    Task { await model.reviewScannedRequest() }
                                }
                                .buttonStyle(.bordered)
                                .controlSize(.large)
                                .disabled(model.scanInput.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                                .accessibilityHint("Paste a credential offer or presentation URL first")
                                .accessibilityIdentifier("scanner.redeem")
                            }
                            .padding(.top, OariSpacing.x3)
                        }
                        .tint(OariColor.action)
                    }
                }
                .onTapGesture { inputFocused = false }
                if case let .configurationRequired(message) = model.eudiFlow {
                    OariCard {
                        VStack(alignment: .leading, spacing: OariSpacing.x3) {
                            Label("Wallet setup required", systemImage: "wrench.and.screwdriver.fill")
                                .font(OariTypography.heading)
                            Text(message).foregroundStyle(OariColor.textSecondary(scheme))
                            Text("Credential operations remain disabled until an approved trust and attestation profile is installed.")
                                .font(.caption)
                                .foregroundStyle(OariColor.textSecondary(scheme))
                        }
                    }
                    .accessibilityIdentifier("scanner.configurationRequired")
                }
                if model.hasRecoverablePendingIssuance {
                    OariCard {
                        VStack(alignment: .leading, spacing: OariSpacing.x3) {
                            Label("Pending credential", systemImage: "hourglass.circle.fill")
                                .font(OariTypography.heading)
                            Text("Identity verification is still required before the issuer can finish this credential.")
                                .foregroundStyle(OariColor.textSecondary(scheme))
                            Button("Continue pending credential") {
                                model.returnToPendingIssuance()
                            }
                            .buttonStyle(OariPrimaryButtonStyle())
                        }
                    }
                    .accessibilityIdentifier("scanner.pendingCredential")
                }
                ScanResultView(result: model.scanResult)
            }
            .scrollDismissesKeyboard(.interactively)
            .navigationTitle("Scan")
            .fullScreenCover(isPresented: $isCameraPresented) {
                CameraQRScannerSheet(onCode: model.handleScannedCode)
            }
        }
    }
}

private struct ScanResultView: View {
    let result: WalletAppModel.ScanResult

    var body: some View {
        switch result {
        case .idle: EmptyView()
        case .presentation:
            detectedRequest("Presentation request detected", icon: "person.badge.shield.checkmark")
                .accessibilityIdentifier("scanner.result.presentation")
        case .issuance:
            detectedRequest("Credential offer detected", icon: "person.text.rectangle")
                .accessibilityIdentifier("scanner.result.issuance")
        case .unsupported:
            OariStatusBadge("Unsupported wallet request", kind: .indeterminate)
                .accessibilityIdentifier("scanner.result.unsupported")
        case let .rejected(reason):
            OariStatusBadge(reason, kind: .invalid)
                .accessibilityIdentifier("scanner.result.rejected")
        }
    }

    private func detectedRequest(_ title: String, icon: String) -> some View {
        Label(title, systemImage: icon)
            .font(OariTypography.label)
            .foregroundStyle(OariColor.action)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal, OariSpacing.x3)
            .padding(.vertical, OariSpacing.x2)
            .background(OariColor.action.opacity(0.08), in: RoundedRectangle(cornerRadius: OariRadius.medium))
    }
}

struct WalletHistoryView: View {
    @Environment(\.colorScheme) private var scheme
    @ObservedObject var model: WalletAppModel
    @State private var selectedEvent: AuditEvent?
    @State private var confirmsClearAllActivity = false

    var body: some View {
        NavigationStack {
            List {
                ForEach(historySections) { section in
                    Section(section.title) {
                        ForEach(section.events) { event in
                            Button { selectedEvent = event } label: {
                                HStack(alignment: .center, spacing: OariSpacing.x3) {
                                    Image(systemName: event.operation.historyIcon)
                                        .font(.body.weight(.semibold))
                                        .foregroundStyle(event.outcome.historyColor)
                                        .frame(width: 28, height: 28)
                                        .background(event.outcome.historyColor.opacity(0.12), in: Circle())
                                        .accessibilityHidden(true)
                                    VStack(alignment: .leading, spacing: OariSpacing.x1) {
                                        Text(event.operation.historyTitle)
                                            .font(.body.weight(.semibold))
                                            .foregroundStyle(.primary)
                                        if event.outcome.showsHistoryLabel {
                                            Text(event.outcome.historyTitle)
                                                .font(.subheadline)
                                                .foregroundStyle(event.outcome.historyColor)
                                        }
                                    }
                                    Spacer(minLength: OariSpacing.x2)
                                    Text(event.occurredAt.formatted(date: .omitted, time: .shortened))
                                        .font(.caption)
                                        .foregroundStyle(OariColor.textSecondary(scheme))
                                    Image(systemName: "chevron.right")
                                        .font(.caption.weight(.semibold))
                                        .foregroundStyle(.tertiary)
                                        .accessibilityHidden(true)
                                }
                            }
                            .buttonStyle(.plain)
                            .padding(.vertical, OariSpacing.x1)
                            .accessibilityElement(children: .combine)
                            .accessibilityLabel("\(event.operation.historyTitle), \(event.outcome.historyTitle)")
                            .accessibilityValue(event.occurredAt.formatted(date: .complete, time: .shortened))
                            .disabled(model.deletingAuditEventIDs.contains(event.id) || model.isClearingAuditHistory)
                        }
                    }
                }
                Section {
                    Text("Activity stays on this device and does not include credential values.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            .accessibilityIdentifier("history.list")
            .overlay {
                if model.isAuditHistoryLoading {
                    ProgressView("Loading activity…")
                } else if model.auditEvents.isEmpty {
                    ContentUnavailableView("No activity", systemImage: "clock", description: Text("Completed wallet actions appear here without credential values."))
                        .accessibilityIdentifier("history.empty")
                }
            }
            .scrollContentBackground(.hidden)
            .background(OariColor.background(scheme))
            .navigationTitle("History")
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Menu {
                        Button("Clear All Activity", systemImage: "trash", role: .destructive) {
                            confirmsClearAllActivity = true
                        }
                        .disabled(model.auditEvents.isEmpty || model.isClearingAuditHistory)
                    } label: {
                        if model.isClearingAuditHistory {
                            ProgressView()
                        } else {
                            Image(systemName: "ellipsis.circle")
                        }
                    }
                    .accessibilityLabel("History options")
                }
            }
            .alert(
                "Clear All Activity?",
                isPresented: $confirmsClearAllActivity,
            ) {
                Button("Clear All Activity", role: .destructive) {
                    Task { await model.clearAllActivity() }
                }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text("This removes activity history from this device. Credentials and wallet keys are not removed.")
            }
            .alert(
                "History Error",
                isPresented: Binding(
                    get: { model.auditHistoryError != nil },
                    set: { if !$0 { model.dismissAuditHistoryError() } }
                )
            ) {
                Button("OK") { model.dismissAuditHistoryError() }
            } message: {
                Text(model.auditHistoryError ?? "The activity history could not be updated.")
            }
            .sheet(item: $selectedEvent) { event in
                HistoryEventDetailView(
                    model: model,
                    event: event,
                    credentialName: credentialName(for: event)
                )
            }
        }
        .task { await model.loadAuditHistoryIfNeeded() }
    }

    private var historySections: [HistorySection] {
        let calendar = Calendar.autoupdatingCurrent
        let grouped = Dictionary(grouping: model.auditEvents) { calendar.startOfDay(for: $0.occurredAt) }
        return grouped.keys.sorted(by: >).map { date in
            HistorySection(
                date: date,
                title: sectionTitle(for: date, calendar: calendar),
                events: grouped[date, default: []].sorted { $0.occurredAt > $1.occurredAt }
            )
        }
    }

    private func sectionTitle(for date: Date, calendar: Calendar) -> String {
        if calendar.isDateInToday(date) { return "Today" }
        if calendar.isDateInYesterday(date) { return "Yesterday" }
        return date.formatted(date: .abbreviated, time: .omitted)
    }

    private func credentialName(for event: AuditEvent) -> String? {
        if event.credentialIDs.count > 1 {
            return "\(event.credentialIDs.count) credentials"
        }
        guard let credentialID = event.credentialIDs.first else { return nil }
        return model.credentials.first(where: { $0.id == credentialID })?.displayName
            ?? "Credential no longer in wallet"
    }
}

private struct HistoryEventDetailView: View {
    @Environment(\.dismiss) private var dismiss
    @ObservedObject var model: WalletAppModel
    let event: AuditEvent
    let credentialName: String?
    @State private var confirmsRemoval = false

    var body: some View {
        NavigationStack {
            Form {
                Section("Activity") {
                    LabeledContent("Action", value: event.operation.historyTitle)
                    LabeledContent("Result", value: event.outcome.historyTitle)
                    LabeledContent("Date", value: event.occurredAt.formatted(date: .long, time: .shortened))
                }
                if let credentialName {
                    Section("Credential") {
                        Text(credentialName)
                    }
                }
                if event.operation.isPresentation, !event.disclosedClaimDigests.isEmpty {
                    Section("Disclosure") {
                        LabeledContent("Attributes shared", value: "\(event.disclosedClaimDigests.count)")
                        Text("Credential values are not stored in activity history.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
                if let reasonCode = event.reasonCode {
                    Section("Reason") {
                        Text(reasonCode.historyDescription)
                    }
                }
                Section {
                    Text("This activity record contains operational metadata only. It does not include credential values, tokens, or cryptographic material.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Section("Actions") {
                    Button(role: .destructive) { confirmsRemoval = true } label: {
                        if model.deletingAuditEventIDs.contains(event.id) {
                            HStack {
                                ProgressView()
                                Text("Removing Activity…")
                            }
                        } else {
                            Label("Remove Activity", systemImage: "trash")
                        }
                    }
                    .disabled(model.deletingAuditEventIDs.contains(event.id) || model.isClearingAuditHistory)
                }
            }
            .navigationTitle("Activity details")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                }
            }
            .alert(
                "Remove Activity?",
                isPresented: $confirmsRemoval,
            ) {
                Button("Remove Activity", role: .destructive) {
                    Task {
                        if await model.deleteAuditEvent(id: event.id) {
                            dismiss()
                        }
                    }
                }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text("This removes only this activity record. Credentials and wallet keys are not removed.")
            }
            .alert(
                "History Error",
                isPresented: Binding(
                    get: { model.auditHistoryError != nil },
                    set: { if !$0 { model.dismissAuditHistoryError() } }
                )
            ) {
                Button("OK") { model.dismissAuditHistoryError() }
            } message: {
                Text(model.auditHistoryError ?? "The activity could not be removed.")
            }
        }
    }
}

private struct HistorySection: Identifiable {
    let date: Date
    let title: String
    let events: [AuditEvent]
    var id: Date { date }
}

private extension AuditOperation {
    var isPresentation: Bool {
        if case .presentation = self { return true }
        return false
    }

    var historyTitle: String {
        switch self {
        case .issuance: "Credential issued"
        case .presentation: "Credential presented"
        case .credentialDeletion: "Credential removed"
        case .credentialRefresh: "Credential refreshed"
        case .keyDeletion: "Wallet key removed"
        }
    }

    var historyIcon: String {
        switch self {
        case .issuance: "person.text.rectangle"
        case .presentation: "person.badge.shield.checkmark"
        case .credentialDeletion: "trash"
        case .credentialRefresh: "arrow.triangle.2.circlepath"
        case .keyDeletion: "key.slash"
        }
    }
}

private extension AuditOutcome {
    var showsHistoryLabel: Bool {
        if case .completed = self { return false }
        return true
    }

    var historyTitle: String {
        switch self {
        case .completed: "Completed"
        case .cancelled: "Cancelled"
        case .rejected: "Rejected"
        case .failed: "Failed"
        }
    }

    var historyColor: Color {
        switch self {
        case .completed: OariColor.action
        case .cancelled: .secondary
        case .rejected, .failed: .red
        }
    }
}

private extension AuditReasonCode {
    var historyDescription: String {
        switch self {
        case .userCancelled: "Cancelled by the user."
        case .userRejected: "Rejected by the user."
        case .trustRejected: "The issuer or verifier could not be trusted."
        case .unsupportedProfile: "The credential or request format is not supported."
        case .expired: "The credential or request expired."
        case .replayDetected: "The wallet blocked a repeated request."
        case .localAuthenticationFailed: "Device authentication was not completed."
        case .deliveryFailed: "The wallet could not deliver the response."
        case .storageFailed: "The wallet could not store the credential securely."
        }
    }
}

struct WalletSettingsView: View {
    @Environment(\.colorScheme) private var scheme
    @ObservedObject var model: WalletAppModel
    private let sourceURL = URL(string: "https://github.com/oaripay/eudi-wallet")!

    var body: some View {
        NavigationStack {
            Form {
                Section("Appearance") {
                    Picker("Theme", selection: $model.theme) {
                        ForEach(OariTheme.allCases) { theme in
                            Text(theme.rawValue.capitalized).tag(theme)
                        }
                    }
                    .pickerStyle(.segmented)
                    .accessibilityIdentifier("settings.theme")
                }
                Section("Security") {
                    Toggle("App Lock", isOn: Binding(
                        get: { model.isAppLockEnabled },
                        set: { value in Task { await model.configureAppLock(enabled: value) } }
                    ))
                    .disabled(model.appLockState == .authenticating)
                    .accessibilityIdentifier("settings.app-lock")
                    LabeledContent("Authentication", value: model.appLockAuthenticationName)
                    if model.isAppLockEnabled {
                        Text("Required when the wallet returns from the background. Device passcode remains available as a fallback.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    LabeledContent("Private keys", value: "On this device")
                    LabeledContent("Credential backup", value: "Excluded")
                }
                Section("Wallet environments") {
                    NavigationLink {
                        EudiReferenceDemoSettingsView(availability: model.eudiAvailability)
                    } label: {
                        WalletEnvironmentRow(
                            title: "EUDI Reference Demo",
                            subtitle: "Official reference services",
                            icon: "person.text.rectangle",
                            status: model.eudiAvailability.isAvailable ? "Interop" : "Unavailable",
                            statusColor: model.eudiAvailability.isAvailable ? .orange : .red
                        )
                    }
                    .accessibilityIdentifier("settings.eudi")

                    NavigationLink {
                        EbsiOpenID4VCSettingsView()
                    } label: {
                        WalletEnvironmentRow(
                            title: "EBSI / OpenID4VC",
                            subtitle: "W3C credential backend",
                            icon: "network.badge.shield.half.filled",
                            status: "Interop",
                            statusColor: .orange
                        )
                    }
                    .accessibilityIdentifier("settings.ebsi")
                    Text("Interoperability environments, not certified")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .accessibilityIdentifier("settings.certification")
                }
                Section("About") {
                    LabeledContent("Oari Wallet", value: appVersion)
                        .accessibilityIdentifier("settings.version")
                    Link(destination: sourceURL) {
                        Label("Open Source", systemImage: "chevron.left.forwardslash.chevron.right")
                    }
                    .accessibilityIdentifier("settings.opensource")
                }
            }
            .scrollContentBackground(.hidden)
            .background(OariColor.background(scheme))
            .navigationTitle("Settings")
        }
    }

    private var appVersion: String {
        let version = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "-"
        let build = Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "-"
        return "\(version) (\(build))"
    }
}

private extension EudiWalletAvailability {
    var isAvailable: Bool {
        if case .available = self { return true }
        return false
    }
}

private struct WalletEnvironmentRow: View {
    let title: String
    let subtitle: String
    let icon: String
    let status: String
    let statusColor: Color

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: icon)
                .foregroundStyle(OariColor.action)
                .frame(width: 24)
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                Text(subtitle).font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            Text(status)
                .font(.caption.weight(.semibold))
                .foregroundStyle(statusColor)
                .padding(.horizontal, 8)
                .padding(.vertical, 4)
                .background(statusColor.opacity(0.12), in: Capsule())
        }
    }
}

private struct EudiReferenceDemoSettingsView: View {
    @Environment(\.colorScheme) private var scheme
    let availability: EudiWalletAvailability

    var body: some View {
        Form {
            Section {
                OariCard {
                    Label {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("Interoperability environment").font(.headline)
                            Text("Uses official EUDI reference services and development trust infrastructure. It is not a production identity environment.")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                    } icon: {
                        Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange)
                    }
                }
                .listRowInsets(EdgeInsets())
                .listRowBackground(Color.clear)
            }
            Section("Status") {
                LabeledContent("Environment", value: "Reference Demo")
                LabeledContent("Wallet Kit", value: EudiWalletKitBaseline.selectedVersion)
                LabeledContent("Trust policy", value: "Warning")
                LabeledContent("Signed metadata", value: "Required")
                LabeledContent("Unregistered parties", value: "Allowed")
                LabeledContent("Availability", value: availability.isAvailable ? "Available" : "Unavailable")
            }
            Section("Services") {
                TechnicalValueRow("Issuer", value: "issuer.eudiw.dev")
                TechnicalValueRow("Backend issuer", value: "issuer-backend.eudiw.dev")
                TechnicalValueRow("Wallet Provider", value: EudiReferenceDemoConfiguration.walletProviderURL.host ?? "-")
                TechnicalValueRow("Verifier", value: EudiReferenceDemoConfiguration.verifierURL.host ?? "-")
            }
            Section("Protocol") {
                TechnicalValueRow("Client ID", value: EudiReferenceDemoConfiguration.clientID)
                TechnicalValueRow("Callback", value: EudiReferenceDemoConfiguration.redirectURI.absoluteString)
                LabeledContent("PAR", value: "Required")
                LabeledContent("DPoP", value: "Required")
            }
        }
        .scrollContentBackground(.hidden)
        .background(OariColor.background(scheme))
        .navigationTitle("EUDI Reference Demo")
        .navigationBarTitleDisplayMode(.inline)
    }
}

private struct EbsiOpenID4VCSettingsView: View {
    @Environment(\.colorScheme) private var scheme
    private let composition = try? W3CBackendComposition.make()

    var body: some View {
        Form {
            Section {
                OariCard {
                    Label {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("Standards interoperability").font(.headline)
                            Text("Uses pinned EBSI registries with cryptographic verification and explicit warnings when signer accreditation is unavailable.")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                    } icon: {
                        Image(systemName: "network.badge.shield.half.filled").foregroundStyle(OariColor.action)
                    }
                }
                .listRowInsets(EdgeInsets())
                .listRowBackground(Color.clear)
            }
            Section("Status") {
                LabeledContent("Environment", value: composition?.environmentPolicy == .production ? "Production registries" : "Unavailable")
                LabeledContent("Unknown signer", value: "Warning")
                LabeledContent("Signature checks", value: "Required")
                LabeledContent("Transport", value: W3CBackendComposition.issuanceProfiles)
            }
            Section("Registries") {
                TechnicalValueRow("DID Registry", value: composition?.endpoint.didRegistryURL.absoluteString ?? "Unavailable")
                TechnicalValueRow("Trusted Issuers", value: composition?.endpoint.trustedIssuersRegistryURL.absoluteString ?? "Unavailable")
                TechnicalValueRow("Trusted Schemas", value: composition?.endpoint.trustedSchemasRegistryURL.absoluteString ?? "Unavailable")
            }
            Section("OpenID4VC") {
                TechnicalValueRow("Client ID", value: W3CBackendComposition.authorizationClientID)
                TechnicalValueRow("Callback", value: W3CBackendComposition.authorizationRedirectURI.absoluteString)
                LabeledContent("Credentials", value: W3CBackendComposition.credentialModels)
                LabeledContent("Presentation", value: W3CBackendComposition.presentationProfile)
            }
        }
        .scrollContentBackground(.hidden)
        .background(OariColor.background(scheme))
        .navigationTitle("EBSI / OpenID4VC")
        .navigationBarTitleDisplayMode(.inline)
    }
}

private struct TechnicalValueRow: View {
    let label: String
    let value: String

    init(_ label: String, value: String) {
        self.label = label
        self.value = value
    }

    var body: some View {
        LabeledContent(label) {
            Text(value)
                .font(.caption.monospaced())
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.trailing)
                .lineLimit(2)
        }
        .contextMenu { Button("Copy") { UIPasteboard.general.string = value } }
    }
}

struct WalletOnboardingView: View {
    @Environment(\.colorScheme) private var scheme
    @ObservedObject var model: WalletAppModel

    var body: some View {
        NavigationStack {
            OariScreen {
                VStack(spacing: OariSpacing.x4) {
                    Image("OariMark")
                        .resizable()
                        .scaledToFit()
                        .frame(width: 92, height: 92)
                        .accessibilityHidden(true)

                    VStack(spacing: OariSpacing.x2) {
                        Text("Oari Digital Credentials Wallet")
                            .font(OariTypography.title)
                            .multilineTextAlignment(.center)
                        Text("Store and share digital credentials with clear consent every time.")
                            .font(OariTypography.body)
                            .foregroundStyle(OariColor.textSecondary(scheme))
                            .multilineTextAlignment(.center)
                    }
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, OariSpacing.x3)

                OariCard {
                    VStack(alignment: .leading, spacing: OariSpacing.x4) {
                        onboardingRow("You approve every share", icon: "checkmark.shield.fill")
                        onboardingRow("Private keys stay on this device", icon: "key.fill")
                        onboardingRow("Trusted connections are checked", icon: "network.badge.shield.half.filled")
                    }
                }

                if case let .configurationRequired(message) = model.eudiAvailability {
                    OariCard {
                        HStack(alignment: .top, spacing: OariSpacing.x3) {
                            Image(systemName: "wrench.and.screwdriver.fill")
                                .foregroundStyle(.orange)
                            VStack(alignment: .leading, spacing: OariSpacing.x2) {
                                Text("Wallet profile required")
                                    .font(OariTypography.heading)
                                Text(message)
                                    .font(.caption)
                                    .foregroundStyle(OariColor.textSecondary(scheme))
                            }
                        }
                    }
                }

                OariCard {
                    VStack(alignment: .leading, spacing: OariSpacing.x4) {
                        HStack(spacing: OariSpacing.x3) {
                            Image(systemName: model.appLockAuthenticationIcon)
                                .font(.title2)
                                .foregroundStyle(OariColor.action)
                                .frame(width: 36)
                            VStack(alignment: .leading, spacing: 3) {
                                Text("Protect your wallet")
                                    .font(OariTypography.heading)
                                Text("Unlock with \(model.appLockAuthenticationName), with device passcode fallback.")
                                    .font(.caption)
                                    .foregroundStyle(OariColor.textSecondary(scheme))
                            }
                        }

                        if let error = model.appLockSetupError {
                            Text(error)
                                .font(.caption)
                                .foregroundStyle(.red)
                        }

                        if model.hasCompletedAppLockSetup {
                            Button("Continue to wallet") { model.completeOnboarding() }
                                .buttonStyle(OariPrimaryButtonStyle())
                                .accessibilityIdentifier("onboarding.continue")
                        } else {
                            Button("Continue with \(model.appLockAuthenticationName)") {
                                Task {
                                    await model.configureAppLock(enabled: true)
                                    if model.isAppLockEnabled { model.completeOnboarding() }
                                }
                            }
                            .buttonStyle(OariPrimaryButtonStyle())
                            .disabled(
                                model.appLockAuthenticationKind == .unavailable ||
                                    model.appLockState == .authenticating
                            )
                            .accessibilityIdentifier("onboarding.app-lock.enable")

                            Button("Continue without App Lock") {
                                model.declineAppLockSetup()
                                model.completeOnboarding()
                            }
                            .frame(maxWidth: .infinity)
                            .buttonStyle(.plain)
                            .disabled(model.appLockState == .authenticating)
                            .accessibilityIdentifier("onboarding.app-lock.skip")
                        }
                    }
                }
            }
            .navigationBarHidden(true)
        }
    }

    private func onboardingRow(_ text: String, icon: String) -> some View {
        Label {
            Text(text).font(OariTypography.body)
        } icon: {
            Image(systemName: icon)
                .foregroundStyle(OariColor.action)
                .frame(width: 24)
        }
    }
}

struct WalletAppLockSetupView: View {
    @Environment(\.colorScheme) private var scheme
    @ObservedObject var model: WalletAppModel
    let allowsDismissal: Bool

    var body: some View {
        VStack(spacing: OariSpacing.x4) {
            Image(systemName: model.appLockAuthenticationIcon)
                .font(.system(size: 42, weight: .medium))
                .foregroundStyle(OariColor.action)
            Text("Protect Oari Wallet")
                .font(OariTypography.heading)
            Text("Use \(model.appLockAuthenticationName) whenever you open the wallet. Your device passcode remains available as a secure fallback.")
                .multilineTextAlignment(.center)
                .foregroundStyle(OariColor.textSecondary(scheme))
            if let error = model.appLockSetupError {
                Text(error)
                    .font(.caption)
                    .foregroundStyle(.red)
                    .multilineTextAlignment(.center)
            }
            if model.hasCompletedAppLockSetup {
                Label(
                    model.isAppLockEnabled ? "App Lock is enabled" : "App Lock setup skipped",
                    systemImage: model.isAppLockEnabled ? "checkmark.shield.fill" : "shield.slash"
                )
                .foregroundStyle(model.isAppLockEnabled ? .green : .secondary)
            } else {
                Button("Set Up \(model.appLockAuthenticationName)") {
                    Task { await model.configureAppLock(enabled: true) }
                }
                .buttonStyle(OariPrimaryButtonStyle())
                .disabled(model.appLockAuthenticationKind == .unavailable || model.appLockState == .authenticating)

                Button("Not Now") { model.declineAppLockSetup() }
                    .buttonStyle(.plain)
                    .disabled(model.appLockState == .authenticating)
            }
        }
        .padding(OariSpacing.x5)
        .frame(maxWidth: .infinity)
        .background(OariColor.background(scheme))
        .accessibilityElement(children: .contain)
    }
}
