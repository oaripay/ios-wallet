import OariDesignSystem
import SwiftUI
import EudiWalletKitAdapter
import UIKit
import WalletDomain

struct EudiFlowView: View {
    @ObservedObject var model: WalletAppModel
    @Environment(\.colorScheme) private var scheme

    var body: some View {
        NavigationStack {
            if case let .presentationConsent(request) = model.eudiFlow {
                PresentationConsentView(model: model, request: request)
            } else {
                OariScreen { content }
                    .scrollDismissesKeyboard(.interactively)
                    .navigationTitle("Wallet request")
                    .navigationBarTitleDisplayMode(.inline)
            }
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

        case .presentationConsent:
            EmptyView()

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

private struct PresentationConsentView: View {
    @ObservedObject var model: WalletAppModel
    let request: EudiPresentationRequest
    @Environment(\.colorScheme) private var scheme
    @State private var showsCredentialPicker = false

    var body: some View {
        ScrollView {
            LazyVStack(alignment: .leading, spacing: OariSpacing.x5) {
                if request.verifierCertificateValid == false {
                    Label("Verifier certificate was not validated", systemImage: "exclamationmark.triangle.fill")
                        .foregroundStyle(.orange)
                }

                if !selectedCredentials.isEmpty {
                    ForEach(selectedCredentials) { credential in
                        PresentationCredentialCard(credential: credential, selected: true, scheme: scheme)
                    }
                    if request.options.count > 1 {
                        Button {
                            showsCredentialPicker = true
                        } label: {
                            Label("Change credential", systemImage: "rectangle.2.swap")
                                .frame(maxWidth: .infinity)
                        }
                        .buttonStyle(.bordered)
                    }
                }

                VStack(alignment: .leading, spacing: OariSpacing.x1) {
                    Text("Requested by")
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(.secondary)
                    Text(verifierLabel)
                        .font(.headline)
                    if let identifier = verifierIdentifier, identifier != verifierLabel {
                        DisclosureGroup("Verifier details") {
                            Text(identifier)
                                .font(.caption.monospaced())
                                .foregroundStyle(OariColor.textSecondary(scheme))
                                .textSelection(.enabled)
                                .padding(.top, OariSpacing.x1)
                        }
                        .font(.subheadline)
                    }
                }
                .padding(.horizontal, OariSpacing.x1)

                if !request.transactionData.isEmpty {
                    ForEach(request.transactionData) { transaction in
                        TransactionDetailsCard(transaction: transaction, scheme: scheme)
                    }
                }

                if !selectedClaims.isEmpty {
                    sectionTitle("Information to share")
                    ForEach(selectedClaims, id: \.id) { claim in
                        ClaimConsentRow(model: model, claim: claim, scheme: scheme)
                    }
                }
            }
            .padding(OariSpacing.x5)
            .padding(.bottom, OariSpacing.x3)
        }
        .background(OariColor.background(scheme).ignoresSafeArea())
        .safeAreaInset(edge: .bottom, spacing: 0) {
            consentActions
        }
        .navigationTitle("Review Request")
        .navigationBarTitleDisplayMode(.inline)
        .accessibilityIdentifier("presentation-consent")
        .sheet(isPresented: $showsCredentialPicker) {
            PresentationCredentialPicker(
                request: request,
                selectedOptionID: model.selectedPresentationOptionID,
                onSelect: { option in
                    model.selectPresentationOption(option)
                    showsCredentialPicker = false
                }
            )
            .presentationDetents([.large])
        }
    }

    private func sectionTitle(_ title: String) -> some View {
        Text(title)
            .font(OariTypography.section)
            .accessibilityAddTraits(.isHeader)
    }

    private var verifierIdentifier: String? {
        request.verifierLegalName ?? request.verifierName
    }

    private var selectedOption: EudiPresentationOption? {
        request.options.first { $0.id == model.selectedPresentationOptionID } ?? request.options.first
    }

    private var selectedCredentials: [EudiPresentationCredential] {
        guard let selectedOption else { return request.credentials }
        let ids = Set(selectedOption.credentialIDs)
        return request.credentials.filter { ids.contains($0.id) }
    }

    private var selectedClaims: [EudiRequestedClaim] {
        selectedOption?.claims ?? request.claims
    }

    private var verifierLabel: String {
        if let legalName = request.verifierLegalName, !legalName.isEmpty { return legalName }
        guard let identifier = request.verifierName, !identifier.isEmpty else { return "Unknown verifier" }
        if let url = URL(string: identifier), let host = url.host { return host }
        if identifier.contains("did:") { return "Credential verifier" }
        return identifier
    }

    @ViewBuilder
    private var consentActions: some View {
        let actions = VStack(spacing: OariSpacing.x2) {
            Button {
                Task { await model.submitPresentation(accepted: true) }
            } label: {
                Label("Approve and continue", systemImage: "checkmark.shield.fill")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(OariPrimaryButtonStyle())
            .disabled(!request.options.isEmpty && model.selectedPresentationOptionID == nil)
            .accessibilityIdentifier("presentation-consent.approve")

            Button("Decline") {
                Task { await model.submitPresentation(accepted: false) }
            }
            .frame(maxWidth: .infinity)
            .buttonStyle(OariSecondaryButtonStyle())
            .accessibilityIdentifier("presentation-consent.decline")
        }
        .padding(.horizontal, OariSpacing.x5)
        .padding(.vertical, OariSpacing.x3)

        if #available(iOS 26.0, *) {
            actions
                .background(.clear)
                .glassEffect(.regular, in: .rect(cornerRadius: 24))
                .padding(.horizontal, OariSpacing.x2)
                .padding(.bottom, OariSpacing.x1)
        } else {
            actions
                .background(.ultraThinMaterial)
                .overlay(alignment: .top) { Divider() }
        }
    }
}

private struct PresentationCredentialPicker: View {
    let request: EudiPresentationRequest
    let selectedOptionID: String?
    let onSelect: (EudiPresentationOption) -> Void
    @Environment(\.dismiss) private var dismiss
    @Environment(\.colorScheme) private var scheme

    var body: some View {
        NavigationStack {
            ScrollView {
                LazyVStack(spacing: OariSpacing.x4) {
                    ForEach(request.options) { option in
                        Button {
                            onSelect(option)
                        } label: {
                            VStack(spacing: OariSpacing.x3) {
                                ForEach(credentials(for: option)) { credential in
                                    PresentationCredentialCard(
                                        credential: credential,
                                        selected: option.id == selectedOptionID,
                                        scheme: scheme
                                    )
                                }
                            }
                        }
                        .buttonStyle(.plain)
                        .accessibilityLabel(option.id == selectedOptionID ? "Selected credential option" : "Choose credential option")
                    }
                }
                .padding(OariSpacing.x5)
            }
            .navigationTitle("Choose Credential")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
            }
        }
    }

    private func credentials(for option: EudiPresentationOption) -> [EudiPresentationCredential] {
        let ids = Set(option.credentialIDs)
        return request.credentials.filter { ids.contains($0.id) }
    }
}

private struct ClaimConsentRow: View {
    @ObservedObject var model: WalletAppModel
    let claim: EudiRequestedClaim
    let scheme: ColorScheme

    var body: some View {
        HStack(alignment: .top, spacing: OariSpacing.x3) {
            Image(systemName: claim.required ? "checkmark.circle.fill" : selectionIcon)
                .foregroundStyle(OariColor.action)
                .font(.title3)
            VStack(alignment: .leading, spacing: OariSpacing.x1) {
                HStack {
                    Text(claim.displayName ?? claim.claimPath.last ?? "Claim")
                        .font(.body.weight(.semibold))
                    Spacer()
                    Text(claim.required ? "Required" : "Optional")
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(.secondary)
                }
                Text(claim.displayValue ?? "Value hidden")
                    .foregroundStyle(OariColor.textSecondary(scheme))
                    .fixedSize(horizontal: false, vertical: true)
                if claim.intentToRetain {
                    Label("The verifier intends to retain this information", systemImage: "archivebox")
                        .font(.caption)
                        .foregroundStyle(.orange)
                }
            }
        }
        .padding(OariSpacing.x4)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(OariColor.surface(scheme), in: RoundedRectangle(cornerRadius: 16, style: .continuous))
        .contentShape(Rectangle())
        .onTapGesture {
            guard !claim.required else { return }
            if model.selectedClaimIDs.contains(claim.id) { model.selectedClaimIDs.remove(claim.id) }
            else { model.selectedClaimIDs.insert(claim.id) }
        }
        .accessibilityElement(children: .combine)
        .accessibilityAddTraits(claim.required ? [] : .isButton)
    }

    private var selectionIcon: String {
        model.selectedClaimIDs.contains(claim.id) ? "checkmark.circle.fill" : "circle"
    }
}

private struct TransactionDetailsCard: View {
    let transaction: EudiTransactionDataPresentation
    let scheme: ColorScheme

    var body: some View {
        VStack(alignment: .leading, spacing: OariSpacing.x4) {
            VStack(alignment: .leading, spacing: OariSpacing.x1) {
                Text(transaction.type.localizedCaseInsensitiveContains("payment") ? "Payment authorization" : "Purpose")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.secondary)
                Text(primaryDescription)
                    .font(.headline)
                    .fixedSize(horizontal: false, vertical: true)
            }

            if let reference = transaction.reference {
                TransactionScalarRow(label: "Reference", value: reference, technical: true, scheme: scheme)
            }

            if let configuration = credentialConfiguration {
                TransactionScalarRow(
                    label: "Credential configuration",
                    value: friendlyConfiguration(configuration),
                    technical: false,
                    scheme: scheme
                )
            }

            if hasTechnicalDetails {
                DisclosureGroup("Technical details") {
                    VStack(alignment: .leading, spacing: OariSpacing.x3) {
                        TransactionScalarRow(label: "Transaction type", value: transaction.type, technical: true, scheme: scheme)
                        if !transaction.credentialIDs.isEmpty {
                            TransactionValueView(
                                label: "Credential identifiers",
                                value: .array(transaction.credentialIDs.map(EudiTransactionDataValue.string)),
                                path: "\(transaction.id).credential_ids",
                                depth: 0,
                                scheme: scheme
                            )
                        }
                    ForEach(transaction.fields) { field in
                        TransactionValueView(
                            label: field.key,
                            value: field.value,
                            path: field.id,
                            depth: 0,
                            scheme: scheme
                        )
                    }
                    }
                    .padding(.top, OariSpacing.x2)
                }
                .font(.subheadline)
            }
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(OariColor.surface(scheme), in: RoundedRectangle(cornerRadius: 18, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: 18, style: .continuous)
                .stroke(Color.secondary.opacity(0.18), lineWidth: 1)
        }
        .accessibilityElement(children: .contain)
    }

    private var primaryDescription: String {
        guard let purpose = transaction.purpose?.trimmingCharacters(in: .whitespacesAndNewlines), !purpose.isEmpty else {
            return transaction.type.localizedCaseInsensitiveContains("payment") ? transaction.title : "Credential presentation"
        }
        return purpose
    }

    private var credentialConfiguration: String? {
        transaction.fields.first {
            $0.key.caseInsensitiveCompare("Credential Configuration Id") == .orderedSame
        }.flatMap {
            if case let .string(value) = $0.value { return value }
            return nil
        }
    }

    private var hasTechnicalDetails: Bool {
        !transaction.type.isEmpty || !transaction.credentialIDs.isEmpty || !transaction.fields.isEmpty
    }

    private func friendlyConfiguration(_ value: String) -> String {
        value
            .replacingOccurrences(of: "oari-rtao-", with: "", options: [.caseInsensitive])
            .replacingOccurrences(of: "-", with: " ")
            .split(separator: " ")
            .map { $0.capitalized }
            .joined(separator: " ")
    }
}

private struct TransactionValueView: View {
    let label: String
    let value: EudiTransactionDataValue
    let path: String
    let depth: Int
    let scheme: ColorScheme

    var body: some View {
        switch value {
        case let .string(value): TransactionScalarRow(label: label, value: value, technical: isTechnical(value), scheme: scheme)
        case let .number(value): TransactionScalarRow(label: label, value: value, technical: false, scheme: scheme)
        case let .bool(value): TransactionScalarRow(label: label, value: value ? "Yes" : "No", technical: false, scheme: scheme)
        case .null: TransactionScalarRow(label: label, value: "Not provided", technical: false, scheme: scheme)
        case let .object(object):
            transactionGroup(label: label, count: object.count) {
                ForEach(object.keys.sorted(), id: \.self) { key in
                    TransactionValueView(
                        label: humanized(key),
                        value: object[key] ?? .null,
                        path: "\(path).\(key)",
                        depth: depth + 1,
                        scheme: scheme
                    )
                }
            }
        case let .array(values):
            if values.count == 1, let value = values.first {
                TransactionValueView(
                    label: label,
                    value: value,
                    path: "\(path)[0]",
                    depth: depth + 1,
                    scheme: scheme
                )
            } else {
                transactionGroup(label: label, count: values.count) {
                ForEach(Array(values.enumerated()), id: \.offset) { index, value in
                    TransactionValueView(
                        label: "Item \(index + 1)",
                        value: value,
                        path: "\(path)[\(index)]",
                        depth: depth + 1,
                        scheme: scheme
                    )
                }
                }
            }
        }
    }

    private func transactionGroup<Content: View>(
        label: String,
        count: Int,
        @ViewBuilder content: () -> Content
    ) -> some View {
        VStack(alignment: .leading, spacing: OariSpacing.x2) {
            HStack {
                Text(label).font(.subheadline.weight(.semibold))
                Spacer()
                Text("\(count)").font(.caption.monospacedDigit()).foregroundStyle(.secondary)
            }
            if count == 0 {
                Text("Empty").font(.subheadline).foregroundStyle(.secondary)
            } else {
                VStack(alignment: .leading, spacing: OariSpacing.x3) { content() }
                    .padding(.leading, OariSpacing.x3)
                    .overlay(alignment: .leading) {
                        Rectangle().fill(OariColor.action.opacity(0.22)).frame(width: 2)
                    }
            }
        }
    }

    private func humanized(_ key: String) -> String {
        key.split(separator: "_").map { $0.capitalized }.joined(separator: " ")
    }

    private func isTechnical(_ value: String) -> Bool {
        value.count > 30 || value.contains("://") || value.hasPrefix("did:")
    }
}

private struct TransactionScalarRow: View {
    let label: String
    let value: String
    let technical: Bool
    let scheme: ColorScheme

    var body: some View {
        VStack(alignment: .leading, spacing: OariSpacing.x1) {
            Text(label)
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)
            Text(value)
                .font(technical ? .footnote.monospaced() : .body)
                .foregroundStyle(OariColor.textPrimary(scheme))
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

private struct PresentationCredentialCard: View {
    let credential: EudiPresentationCredential
    let selected: Bool
    let scheme: ColorScheme

    var body: some View {
        ZStack(alignment: .bottomLeading) {
            OariColor.safeColor(credential.display?.backgroundColor, fallback: OariColor.action.opacity(0.13))
            if let background = credential.display?.backgroundImage {
                presentationImage(background, contentMode: .fill)
                    .opacity(0.82)
                LinearGradient(
                    colors: [.black.opacity(0.02), .black.opacity(0.62)],
                    startPoint: .top,
                    endPoint: .bottom
                )
            }
            VStack(alignment: .leading, spacing: OariSpacing.x3) {
                HStack(alignment: .top) {
                    credentialLogo
                    Spacer()
                    Label(selected ? "Selected" : "Choose", systemImage: selected ? "checkmark.circle.fill" : "circle")
                        .font(.caption.weight(.semibold))
                        .padding(.horizontal, 9)
                        .padding(.vertical, 6)
                        .background(.ultraThinMaterial, in: Capsule())
                }
                Spacer(minLength: OariSpacing.x4)
                Text(credential.displayName)
                    .font(.title2.weight(.bold))
                    .fixedSize(horizontal: false, vertical: true)
                if let issuer = credential.issuerIdentifier {
                    Text(issuerLabel(issuer))
                        .font(.caption)
                        .opacity(0.82)
                }
                Text(credential.format.rawValue)
                    .font(.caption)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 5)
                    .background(.ultraThinMaterial, in: Capsule())
            }
            .padding(OariSpacing.x5)
        }
        .foregroundStyle(cardTextColor)
        .frame(maxWidth: .infinity, minHeight: 210, alignment: .bottomLeading)
        .clipShape(RoundedRectangle(cornerRadius: OariRadius.extraLarge, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: OariRadius.extraLarge, style: .continuous)
                .stroke(.white.opacity(scheme == .dark ? 0.12 : 0.25))
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("Selected credential: \(credential.displayName)")
    }

    @ViewBuilder private var credentialLogo: some View {
        if let logo = credential.display?.logo {
            presentationImage(logo, contentMode: .fit)
                .padding(8)
                .frame(width: 54, height: 54)
                .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 14, style: .continuous))
                .accessibilityLabel(logo.alternativeText ?? "Credential logo")
        } else {
            Image(systemName: credential.format == .mdoc ? "person.text.rectangle.fill" : "doc.text.fill")
                .font(.title2)
                .frame(width: 54, height: 54)
                .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 14, style: .continuous))
                .accessibilityHidden(true)
        }
    }

    private var cardTextColor: Color {
        OariColor.safeColor(
            credential.display?.textColor,
            fallback: credential.display?.backgroundImage == nil ? OariColor.textPrimary(scheme) : .white
        )
    }

    private func issuerLabel(_ value: String) -> String {
        if let url = URL(string: value), let host = url.host { return host }
        if value.contains("did:") { return "Verified credential issuer" }
        return value
    }

    @ViewBuilder
    private func presentationImage(_ image: CredentialDisplayImage, contentMode: ContentMode) -> some View {
        if let uiImage = UIImage(data: image.data) {
            Image(uiImage: uiImage)
                .resizable()
                .aspectRatio(contentMode: contentMode)
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
