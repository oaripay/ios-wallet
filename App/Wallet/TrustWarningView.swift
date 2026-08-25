import EbsiW3CBackend
import OariDesignSystem
import SwiftUI

struct TrustWarningView: View {
    let warning: EbsiTrustWarning
    let continueAction: () -> Void
    let cancel: () -> Void
    @Environment(\.colorScheme) private var scheme

    var body: some View {
        OariScreen {
            Image(systemName: "exclamationmark.shield.fill")
                .font(.system(size: 44))
                .foregroundStyle(.orange)
                .accessibilityHidden(true)
            OariSectionHeader(
                "Development trust warning",
                subtitle: "This request is valid enough to inspect, but its trust registration was not confirmed."
            )
            OariCard {
                VStack(alignment: .leading, spacing: OariSpacing.x3) {
                    detail("Role", warning.role.rawValue.capitalized)
                    detail("Counterparty", warning.counterpartyIdentifier)
                    detail("Evidence", warning.evidenceSources.isEmpty ? "No registry evidence" : warning.evidenceSources.joined(separator: ", "))
                    detail("Reasons", warning.reasons.map(\.rawValue).joined(separator: ", "))
                    if !warning.diagnostic.isEmpty {
                        detail("Diagnostic", warning.diagnostic)
                    }
                }
            }
            Label(warning.nextAction, systemImage: "info.circle")
                .font(OariTypography.body)
                .foregroundStyle(OariColor.textSecondary(scheme))
            Text("Nothing has been shared or stored yet. Continue only if you recognize and trust this issuer or verifier.")
                .font(.caption)
                .foregroundStyle(OariColor.textSecondary(scheme))
            OariFlowFooter {
                Button("Continue anyway", action: continueAction)
                    .buttonStyle(OariDestructiveButtonStyle())
            } secondary: {
                Button("Cancel", action: cancel)
                    .buttonStyle(OariSecondaryButtonStyle())
            }
        }
        .accessibilityIdentifier("ebsi.trustWarning")
    }

    private func detail(_ label: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: OariSpacing.x1) {
            Text(label).font(.caption).foregroundStyle(.secondary)
            Text(value).font(OariTypography.body).textSelection(.enabled)
        }
    }
}
