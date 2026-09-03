import CryptoKit
import EbsiW3CBackend
import Foundation
import Testing
import WalletDomain
@testable import WalletVault

struct EncryptedEbsiCredentialStoreTests {
    @Test("Raw W3C credential survives restart encrypted and deletes")
    func restartAndDelete() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let keyStore = StaticVaultKeyStore(key: SymmetricKey(size: .bits256))
        let credential = StoredEbsiCredential(
            profileID: "ebsi-vcdm2-jwt-vc",
            representation: .vcdm2Jwt,
            rawCredential: Data("header.payload.signature".utf8),
            holderKeyReference: "ebsi-holder-key-1",
            receivedAt: Date(timeIntervalSince1970: 1_700_000_000)
        )
        var store = try EncryptedEbsiCredentialStore(directory: directory, keyStore: keyStore)
        try await store.save(credential)
        let file = try #require(FileManager.default.contentsOfDirectory(
            at: directory,
            includingPropertiesForKeys: nil
        ).first)
        let disk = try Data(contentsOf: file)
        #expect(!disk.contains(credential.rawCredential))
        #expect(!disk.contains(Data(credential.holderKeyReference.utf8)))

        store = try EncryptedEbsiCredentialStore(directory: directory, keyStore: keyStore)
        #expect(try await store.credentials() == [credential])
        try await store.delete(id: credential.id)
        #expect(try await store.credentials().isEmpty)
    }

    @Test("Saving the same credential is idempotent")
    func idempotentSave() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = try EncryptedEbsiCredentialStore(
            directory: directory,
            keyStore: StaticVaultKeyStore(key: SymmetricKey(size: .bits256))
        )
        let credential = StoredEbsiCredential(
            profileID: "ebsi-vcdm2-jwt-vc",
            representation: .vcdm2Jwt,
            rawCredential: Data("header.payload.signature".utf8),
            holderKeyReference: "holder-key"
        )

        try await store.save(credential)
        try await store.save(credential)

        #expect(try await store.credentials() == [credential])
    }

    @Test("Replacement updates encrypted content while preserving ID")
    func replacement() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = try EncryptedEbsiCredentialStore(
            directory: directory,
            keyStore: StaticVaultKeyStore(key: SymmetricKey(size: .bits256))
        )
        let original = StoredEbsiCredential(
            profileID: "w3c", representation: .vcdm2Jwt,
            rawCredential: Data("old.jwt".utf8), holderKeyReference: "holder"
        )
        let replacement = StoredEbsiCredential(
            id: original.id, profileID: "w3c", representation: .vcdm2Jwt,
            rawCredential: Data("refreshed.jwt".utf8), holderKeyReference: "holder"
        )
        try await store.save(original)
        try await store.replace(id: original.id, with: replacement)
        #expect(try await store.credentials() == [replacement])

        let wrongID = StoredEbsiCredential(
            profileID: "w3c", representation: .vcdm2Jwt,
            rawCredential: Data("wrong.jwt".utf8), holderKeyReference: "holder"
        )
        await #expect(throws: WalletRepositoryError.credentialNotFound) {
            try await store.replace(id: original.id, with: wrongID)
        }
        #expect(try await store.credentials() == [replacement])
    }
}
