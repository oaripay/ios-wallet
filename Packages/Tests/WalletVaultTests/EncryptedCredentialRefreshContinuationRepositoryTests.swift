import CryptoKit
import Foundation
import Testing
import WalletDomain
@testable import WalletVault

struct EncryptedCredentialRefreshContinuationRepositoryTests {
    @Test("Refresh continuation survives restart, replacement, and deletion encrypted")
    func lifecycle() async throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let keyStore = StaticVaultKeyStore(key: SymmetricKey(size: .bits256))
        let now = Date(timeIntervalSince1970: 1_800_000_000)
        let original = CredentialRefreshContinuation(
            credentialID: CredentialID(), continuation: Data("secret-refresh-token".utf8),
            dueAt: now, createdAt: now, updatedAt: now
        )
        var repository = try EncryptedCredentialRefreshContinuationRepository(
            directory: root, keyStore: keyStore
        )
        try await repository.saveRefreshContinuation(original)
        let file = try #require(FileManager.default.contentsOfDirectory(
            at: root, includingPropertiesForKeys: nil
        ).first)
        #expect(!(try Data(contentsOf: file)).contains(original.continuation))

        repository = try EncryptedCredentialRefreshContinuationRepository(
            directory: root, keyStore: keyStore
        )
        #expect(try await repository.refreshContinuations() == [original])
        let updated = CredentialRefreshContinuation(
            id: original.id, credentialID: original.credentialID,
            continuation: Data("new-secret".utf8), dueAt: now.addingTimeInterval(60),
            attempts: 1, state: .failed, createdAt: now,
            updatedAt: now.addingTimeInterval(1)
        )
        try await repository.replaceRefreshContinuation(updated)
        #expect(try await repository.refreshContinuations() == [updated])
        try await repository.deleteRefreshContinuation(id: original.id)
        #expect(try await repository.refreshContinuations().isEmpty)
    }
}
