import EbsiW3CBackend
import Foundation
import WalletDomain

public actor EncryptedEbsiCredentialStore: EbsiCredentialStore {
    private let files: ProtectedFileStore
    private let cipher: VaultCipher
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()

    public init(directory: URL, keyStore: any VaultKeyStore) throws {
        files = ProtectedFileStore(directory: directory)
        cipher = VaultCipher(keyStore: keyStore)
        try files.prepare()
    }

    public func credentials() async throws -> [StoredEbsiCredential] {
        try files.files(withExtension: "ebsi-vc").map { file in
            guard let id = UUID(uuidString: file.deletingPathExtension().lastPathComponent) else {
                throw VaultError.corruptCiphertext
            }
            let plaintext = try cipher.open(files.read(file), authenticating: context(id))
            let credential = try decoder.decode(StoredEbsiCredential.self, from: plaintext)
            guard credential.id == id else { throw VaultError.corruptCiphertext }
            return credential
        }.sorted { $0.receivedAt > $1.receivedAt }
    }

    public func save(_ credential: StoredEbsiCredential) async throws {
        let file = fileURL(credential.id)
        if files.exists(file) {
            do {
                let plaintext = try cipher.open(files.read(file), authenticating: context(credential.id))
                let existing = try decoder.decode(StoredEbsiCredential.self, from: plaintext)
                guard existing == credential else { throw WalletRepositoryError.duplicateCredential }
                return
            } catch let error as WalletRepositoryError {
                throw error
            } catch let error as VaultError {
                throw error
            } catch {
                throw WalletRepositoryError.storageFailure
            }
        }
        do {
            try files.write(
                cipher.seal(try encoder.encode(credential), authenticating: context(credential.id)),
                to: file
            )
        } catch let error as WalletRepositoryError {
            throw error
        } catch {
            throw WalletRepositoryError.storageFailure
        }
    }

    public func replace(id: UUID, with credential: StoredEbsiCredential) async throws {
        guard credential.id == id else { throw WalletRepositoryError.credentialNotFound }
        let file = fileURL(id)
        guard files.exists(file) else { throw WalletRepositoryError.credentialNotFound }
        try write(credential, to: file)
    }

    public func delete(id: UUID) async throws {
        let file = fileURL(id)
        guard files.exists(file) else { throw WalletRepositoryError.credentialNotFound }
        do { try files.remove(file) } catch { throw WalletRepositoryError.storageFailure }
    }

    private func fileURL(_ id: UUID) -> URL {
        files.directory.appendingPathComponent(id.uuidString).appendingPathExtension("ebsi-vc")
    }

    private func write(_ credential: StoredEbsiCredential, to file: URL) throws {
        do {
            try files.write(
                cipher.seal(try encoder.encode(credential), authenticating: context(credential.id)),
                to: file
            )
        } catch {
            throw WalletRepositoryError.storageFailure
        }
    }

    private func context(_ id: UUID) -> Data {
        Data("oari.ebsi-credential.v1:\(id.uuidString)".utf8)
    }
}
