import OariDesignSystem
import SwiftUI
import EudiWalletKitAdapter

struct EudiFlowView: View {
    @ObservedObject var model: WalletAppModel
    @Environment(\.colorScheme) private var scheme

    var body: some View {
        NavigationStack {
            OariScreen { content }
            .scrollDismissesKeyboard(.interactively)
            .navigationTitle("Wallet request")
            .navigationBarTitleDisplayMode(.inline)
        }
    }

    @ViewBuilder
    private var content: some View {
        switch model.eudiFlow {
        case let .working(message):
            VStack(spacing: OariSpacing.x4) {
                ProgressView()
                Text(message).font(OariTypography.heading).multilineTextAlignment(.center)
            }
            .frame(maxWidth: .infinity, minHeight: 220)

        case let .issuanceReview(offer):
            Label("Credential offer", systemImage: "person.text.rectangle")
                .font(OariTypography.heading)
            HStack(spacing: 10) {
                if let issuerLogoURL = offer.issuerLogoURL {
                    OfferArtworkImage(url: issuerLogoURL, contentMode: .fit)
                        .frame(width: 44, height: 44)
                        .padding(5)
                        .background(OariColor.surface(scheme), in: RoundedRectangle(cornerRadius: 10))
                }
                Text(offer.issuerName).foregroundStyle(OariColor.textSecondary(scheme))
            }
            ForEach(offer.documents, id: \.configurationID) { document in
                Toggle(isOn: Binding(
                    get: { model.selectedIssuanceConfigurationIDs.contains(document.configurationID) },
                    set: { selected in
                        if selected { model.selectedIssuanceConfigurationIDs.insert(document.configurationID) }
                        else { model.selectedIssuanceConfigurationIDs.remove(document.configurationID) }
                    }
                )) {
                    ZStack(alignment: .leading) {
                        OariColor.safeColor(document.display?.backgroundColor, fallback: OariColor.surface(scheme))
                        if let backgroundURL = document.display?.backgroundImageURL {
                            OfferArtworkImage(url: backgroundURL, contentMode: .fill)
                            .opacity(0.72)
                            LinearGradient(
                                colors: [.black.opacity(0.04), .black.opacity(0.48)],
                                startPoint: .topLeading,
                                endPoint: .bottomTrailing
                            )
                        }
                        HStack(spacing: 12) {
                            if let logoURL = document.display?.logoURL {
                                OfferArtworkImage(url: logoURL, contentMode: .fit)
                                .padding(6)
                                .frame(width: 42, height: 42)
                                .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 10))
                            }
                            VStack(alignment: .leading, spacing: 3) {
                                Text(document.displayName)
                                    .font(.headline)
                                    .lineLimit(2)
                                    .minimumScaleFactor(0.82)
                                    .fixedSize(horizontal: false, vertical: true)
                                Text(document.documentType)
                                    .font(.caption)
                                    .opacity(0.78)
                                    .lineLimit(2)
                                    .fixedSize(horizontal: false, vertical: true)
                            }
                        }
                        .padding(12)
                        .frame(maxWidth: .infinity, minHeight: 72, alignment: .leading)
                    }
                    .foregroundStyle(OariColor.safeColor(
                        document.display?.textColor,
                        fallback: document.display?.backgroundImageURL == nil ? OariColor.textPrimary(scheme) : .white
                    ))
                    .clipShape(RoundedRectangle(cornerRadius: 14, style: .continuous))
                }
            }
            EudiTransactionCodeEntry(requirement: offer.transactionCode) { transactionCode in
                await model.acceptIssuance(transactionCode: transactionCode)
            }

        case let .openID4VCIssuanceReview(interaction):
            Label("W3C credential", systemImage: "network.badge.shield.half.filled")
                .font(OariTypography.heading)
            Text(interaction.displayName ?? interaction.counterpartyIdentifier)
                .foregroundStyle(OariColor.textSecondary(scheme))
                .lineLimit(3)
                .fixedSize(horizontal: false, vertical: true)
            ForEach(interaction.configurationIDs, id: \.self) { configurationID in
                if let display = interaction.credentialDisplay[configurationID] {
                    ZStack(alignment: .leading) {
                        OariColor.safeColor(display.backgroundColor, fallback: OariColor.surface(scheme))
                        if let backgroundURL = display.backgroundImageURL {
                            AsyncImage(url: backgroundURL) { image in
                                image.resizable().scaledToFill()
                            } placeholder: { Color.clear }
                            .opacity(0.72)
                            LinearGradient(
                                colors: [.black.opacity(0.04), .black.opacity(0.48)],
                                startPoint: .topLeading,
                                endPoint: .bottomTrailing
                            )
                        }
                        VStack(alignment: .leading, spacing: 6) {
                            if let logoURL = display.logoURL {
                                AsyncImage(url: logoURL) { image in
                                    image.resizable().scaledToFit()
                                } placeholder: { ProgressView() }
                                .padding(6)
                                .frame(width: 48, height: 48)
                                .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 11))
                            }
                            Spacer(minLength: 12)
                            Text(display.name)
                                .font(.headline)
                                .lineLimit(2)
                                .minimumScaleFactor(0.82)
                                .fixedSize(horizontal: false, vertical: true)
                            if let description = display.description ?? display.claims.first?.description {
                                Text(description)
                                    .font(.caption)
                                    .lineLimit(3)
                                    .fixedSize(horizontal: false, vertical: true)
                            }
                            Text(display.claims.count == 1 ? "1 attribute" : "\(display.claims.count) attributes")
                                .font(.caption.weight(.semibold))
                        }
                        .padding(14)
                        .frame(maxWidth: .infinity, minHeight: 190, alignment: .bottomLeading)
                    }
                    .foregroundStyle(OariColor.safeColor(
                        display.textColor,
                        fallback: display.backgroundImageURL == nil ? OariColor.textPrimary(scheme) : .white
                    ))
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .clipShape(RoundedRectangle(cornerRadius: 14, style: .continuous))
                }
            }
            OpenID4VCTransactionCodeEntry(interaction: interaction) { transactionCode in
                await model.issueReviewedOpenID4VCCredential(transactionCode: transactionCode)
            } onCancel: {
                await model.cancelOpenID4VCTrustWarning()
            }

        case let .openID4VPPresentationRequired(challenge):
            Label("Present your Credential", systemImage: "person.badge.shield.checkmark")
                .font(OariTypography.heading)
            Text("The issuer requires an OpenID4VP presentation before it can issue this W3C credential.")
            Text("DCQL request: \(challenge.dcqlQuery.keys.sorted().joined(separator: ", "))")
                .font(.caption).foregroundStyle(.secondary)
            primaryButton("Review PID claims", icon: "person.text.rectangle") {
                await model.startEudiCredentialPresentation(challenge)
            }

        case let .presentationConsent(request):
            Label("Share identity information", systemImage: "person.badge.shield.checkmark")
                .font(OariTypography.heading)
            Text(request.verifierLegalName ?? request.verifierName ?? "Unknown verifier")
                .font(.headline)
            if request.verifierCertificateValid == false {
                Label("Verifier certificate was not validated", systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
            }
            if !request.transactionData.isEmpty {
                Text("Transaction details")
                    .font(.subheadline.weight(.semibold))
                ForEach(Array(request.transactionData.enumerated()), id: \.offset) { _, fields in
                    VStack(alignment: .leading, spacing: 6) {
                        ForEach(fields) { field in
                            LabeledContent(field.key) {
                                Text(field.value)
                                    .foregroundStyle(.secondary)
                                    .multilineTextAlignment(.trailing)
                            }
                            .font(.caption)
                        }
                    }
                    .padding(10)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(Color.secondary.opacity(0.08), in: RoundedRectangle(cornerRadius: 8))
                }
            }
            ForEach(request.claims, id: \.id) { claim in
                Toggle(isOn: Binding(
                    get: { model.selectedClaimIDs.contains(claim.id) },
                    set: { selected in
                        guard !claim.required || selected else { return }
                        if selected { model.selectedClaimIDs.insert(claim.id) }
                        else { model.selectedClaimIDs.remove(claim.id) }
                    }
                )) {
                    VStack(alignment: .leading) {
                        Text(claim.claimPath.last ?? "Claim")
                        Text(claim.displayValue ?? "Value hidden").font(.caption).foregroundStyle(.secondary)
                        if claim.required { Text("Required").font(.caption2).foregroundStyle(.secondary) }
                    }
                }
                .disabled(claim.required)
            }
            primaryButton("Approve and continue", icon: "checkmark.shield.fill") {
                await model.submitPresentation(accepted: true)
            }
            Button("Decline") { Task { await model.submitPresentation(accepted: false) } }
                .frame(maxWidth: .infinity)
                .buttonStyle(OariSecondaryButtonStyle())

        case let .pending(pending):
            Label("Identity verification required", systemImage: "hourglass.circle")
                .font(OariTypography.heading)
            Text(pending.document.displayName ?? pending.document.documentType).font(.headline)
            Text("The issuer needs a PID presentation before issuing this credential. You will review every requested claim before anything is shared.")
                .foregroundStyle(OariColor.textSecondary(scheme))
            primaryButton("Review PID request", icon: "person.badge.shield.checkmark") {
                await model.continuePendingIssuance()
            }

        case let .completed(message):
            Label("Completed", systemImage: "checkmark.circle.fill")
                .font(OariTypography.heading).foregroundStyle(.green)
            Text(message)
            Button("Done") { model.dismissEudiFlow() }
                .buttonStyle(OariPrimaryButtonStyle())

        case let .failed(message):
            Label("Request stopped", systemImage: "xmark.shield.fill")
                .font(OariTypography.heading).foregroundStyle(.red)
            Text(message)
            Text("No unapproved data was shared.").font(.caption).foregroundStyle(.secondary)
            if model.hasRecoverablePendingIssuance {
                Button("Return to pending credential") { model.returnToPendingIssuance() }
                    .buttonStyle(OariPrimaryButtonStyle())
            }
            Button("Close") { model.dismissEudiFlow() }
                .frame(maxWidth: .infinity)
                .buttonStyle(OariSecondaryButtonStyle())

        case .idle, .configurationRequired:
            EmptyView()
        }
    }

    private func primaryButton(
        _ title: String,
        icon: String,
        disabled: Bool = false,
        action: @escaping @MainActor () async -> Void
    ) -> some View {
        Button {
            Task { await action() }
        } label: {
            Label(title, systemImage: icon).frame(maxWidth: .infinity)
        }
        .buttonStyle(OariPrimaryButtonStyle())
        .disabled(disabled)
    }

}

private struct OfferArtworkImage: View {
    let url: URL
    let contentMode: ContentMode

    var body: some View {
        AsyncImage(url: url) { phase in
            switch phase {
            case let .success(image):
                image.resizable().aspectRatio(contentMode: contentMode)
            case .empty:
                ProgressView()
            case .failure:
                Image(systemName: "person.text.rectangle")
                    .resizable()
                    .scaledToFit()
                    .padding(8)
                    .foregroundStyle(.secondary)
            @unknown default:
                Color.clear
            }
        }
    }
}

private struct EudiTransactionCodeEntry: View {
    private enum Field { case code }

    let requirement: EudiTransactionCodeRequirement?
    let onSubmit: @MainActor (String?) async -> Void

    @State private var value = ""
    @FocusState private var focusedField: Field?

    var body: some View {
        if let requirement {
            if requirement.inputMode == "numeric" {
                SecurePINCodeField(
                    value: $value,
                    length: requirement.length ?? 4,
                    label: "Transaction code",
                    focus: $focusedField,
                    focusValue: .code
                )
            } else {
                SecureField("Transaction code", text: $value)
                    .textContentType(.oneTimeCode)
                    .keyboardType(.asciiCapable)
                    .textFieldStyle(.roundedBorder)
                    .focused($focusedField, equals: .code)
            }
        }

        Button {
            focusedField = nil
            Task { await onSubmit(value.isEmpty ? nil : value) }
        } label: {
            Label("Add to wallet", systemImage: "plus.circle.fill")
                .frame(maxWidth: .infinity)
        }
        .buttonStyle(OariPrimaryButtonStyle())
        .disabled(!isValid)
    }

    private var isValid: Bool {
        guard let requirement else { return true }
        guard !value.isEmpty else { return false }
        if let length = requirement.length, value.count != length { return false }
        return requirement.inputMode != "numeric" || value.unicodeScalars.allSatisfy {
            $0.value >= 48 && $0.value <= 57
        }
    }
}

private struct OpenID4VCTransactionCodeEntry: View {
    private enum Field { case pin }

    let interaction: OpenID4VCResolvedInteraction
    let onSubmit: @MainActor (String?) async -> Void
    let onCancel: @MainActor () async -> Void

    @State private var value = ""
    @FocusState private var focusedField: Field?

    var body: some View {
        if interaction.transactionCodeRequired {
            Text(interaction.transactionCodeDescription ?? "Enter the PIN supplied by the issuer.")
                .font(.caption)
                .foregroundStyle(.secondary)
            if let length = interaction.transactionCodeLength {
                SecurePINCodeField(
                    value: $value,
                    length: length,
                    label: "PIN",
                    focus: $focusedField,
                    focusValue: .pin
                )
            } else {
                SecureField("PIN / transaction code", text: $value)
                    .textContentType(.oneTimeCode)
                    .keyboardType(.numberPad)
                    .textFieldStyle(.roundedBorder)
                    .focused($focusedField, equals: .pin)
            }
        }
        Button {
            focusedField = nil
            Task { await onSubmit(value.isEmpty ? nil : value) }
        } label: {
            Label("Issue and store credential", systemImage: "plus.circle.fill")
                .frame(maxWidth: .infinity)
        }
        .buttonStyle(OariPrimaryButtonStyle())
        .disabled(!isValid)

        Button("Cancel") {
            focusedField = nil
            Task { await onCancel() }
        }
        .frame(maxWidth: .infinity)
        .buttonStyle(OariSecondaryButtonStyle())
    }

    private var isValid: Bool {
        guard interaction.transactionCodeRequired else { return true }
        guard !value.isEmpty else { return false }
        if let length = interaction.transactionCodeLength, value.count != length { return false }
        return value.unicodeScalars.allSatisfy { $0.value >= 48 && $0.value <= 57 }
    }
}

private struct SecurePINCodeField<FocusValue: Hashable>: View {
    @Binding var value: String
    let length: Int
    let label: String
    let focus: FocusState<FocusValue?>.Binding
    let focusValue: FocusValue

    @Environment(\.colorScheme) private var scheme

    var body: some View {
        ZStack {
            Button { focus.wrappedValue = focusValue } label: {
                HStack(spacing: 10) {
                    ForEach(0..<length, id: \.self) { index in
                        ZStack {
                            RoundedRectangle(cornerRadius: 12, style: .continuous)
                                .fill(OariColor.surface(scheme))
                            RoundedRectangle(cornerRadius: 12, style: .continuous)
                                .stroke(
                                    index == activeIndex && isFocused
                                        ? OariColor.action
                                        : Color.secondary.opacity(0.25),
                                    lineWidth: isFocused && index == activeIndex ? 2 : 1
                                )
                            if index < value.count {
                                Circle()
                                    .fill(OariColor.textPrimary(scheme))
                                    .frame(width: 10, height: 10)
                            }
                        }
                        .frame(maxWidth: .infinity)
                        .frame(height: 54)
                    }
                }
            }
            .buttonStyle(.plain)
            TextField("", text: $value)
                .textContentType(.oneTimeCode)
                .keyboardType(.numberPad)
                .focused(focus, equals: focusValue)
                .frame(width: 1, height: 1)
                .opacity(0.01)
                .accessibilityHidden(true)
                .onChange(of: value) { _, newValue in
                    let digits = newValue.filter { $0 >= "0" && $0 <= "9" }
                    let normalized = String(digits.prefix(length))
                    if value != normalized { value = normalized }
                    if normalized.count == length { focus.wrappedValue = nil }
                }
        }
        .onAppear { focus.wrappedValue = focusValue }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(label)
        .accessibilityValue("\(value.count) of \(length) digits entered")
        .accessibilityHint("Double tap to enter the code")
    }

    private var activeIndex: Int {
        max(0, min(value.count, length - 1))
    }

    private var isFocused: Bool { focus.wrappedValue == focusValue }
}
