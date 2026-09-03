import Foundation
import Testing
import WalletDomain

struct CredentialRefreshTests {
    @Test("Refresh continuation round trips opaque protocol and scheduling state")
    func roundTrip() throws {
        let now = Date(timeIntervalSince1970: 1_800_000_000)
        let value = CredentialRefreshContinuation(
            credentialID: CredentialID(), continuation: Data([0, 1, 2, 255]),
            dueAt: now, attempts: 2, state: .authorizationRequired,
            createdAt: now.addingTimeInterval(-60), updatedAt: now
        )
        #expect(try JSONDecoder().decode(
            CredentialRefreshContinuation.self, from: JSONEncoder().encode(value)
        ) == value)
    }
}
