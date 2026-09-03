import CryptoKit
import Foundation
import WalletDomain

public actor EncryptedCredentialRefreshContinuationRepository: CredentialRefreshContinuationRepository {
    private let files: ProtectedFileStore
    private let cipher: VaultCipher
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()

    public init(directory: URL, keyStore: any VaultKeyStore) throws {
        files = ProtectedFileStore(directory: directory)
        cipher = VaultCipher(keyStore: keyStore)
        try files.prepare()
    }

    public func refreshContinuations() async throws -> [CredentialRefreshContinuation] {
        try files.files(withExtension: "credential-refresh").map { file in
            let digest = file.deletingPathExtension().lastPathComponent
            do {
                let plaintext = try cipher.open(files.read(file), authenticating: context(digest))
                let continuation = try decoder.decode(CredentialRefreshContinuation.self, from: plaintext)
                guard continuationDigest(continuation.id) == digest else {
                    throw VaultError.corruptCiphertext
                }
                return continuation
            } catch let error as VaultError {
                throw error
            } catch {
                throw WalletRepositoryError.storageFailure
            }
        }.sorted { $0.dueAt < $1.dueAt }
    }

    public func saveRefreshContinuation(_ continuation: CredentialRefreshContinuation) async throws {
        let file = fileURL(continuation.id)
        guard !files.exists(file) else { throw WalletRepositoryError.duplicateRefreshContinuation }
        try write(continuation, to: file)
    }

    public func replaceRefreshContinuation(_ continuation: CredentialRefreshContinuation) async throws {
        let file = fileURL(continuation.id)
        guard files.exists(file) else { throw WalletRepositoryError.refreshContinuationNotFound }
        try write(continuation, to: file)
    }

    public func deleteRefreshContinuation(id: UUID) async throws {
        let file = fileURL(id)
        guard files.exists(file) else { throw WalletRepositoryError.refreshContinuationNotFound }
        do { try files.remove(file) } catch { throw WalletRepositoryError.storageFailure }
    }

    private func write(_ continuation: CredentialRefreshContinuation, to file: URL) throws {
        do {
            let digest = continuationDigest(continuation.id)
            try files.write(
                cipher.seal(try encoder.encode(continuation), authenticating: context(digest)),
                to: file
            )
        } catch let error as WalletRepositoryError {
            throw error
        } catch {
            throw WalletRepositoryError.storageFailure
        }
    }

    private func fileURL(_ id: UUID) -> URL {
        files.directory.appendingPathComponent(continuationDigest(id))
            .appendingPathExtension("credential-refresh")
    }

    private func continuationDigest(_ id: UUID) -> String {
        SHA256.hash(data: Data(id.uuidString.utf8)).map { String(format: "%02x", $0) }.joined()
    }

    private func context(_ digest: String) -> Data {
        Data("oari.credential-refresh.v1:\(digest)".utf8)
    }
}
