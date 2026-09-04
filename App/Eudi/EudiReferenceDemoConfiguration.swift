import EudiWalletKit
import EudiWalletKitAdapter
import Foundation
import MdocDataModel18013
import MdocSecurity18013
import OpenID4VCI
import WalletDomain

enum EudiReferenceDemoConfiguration {
    static let profileID = "eudi-reference-demo"
    static let clientID = "eudiw-abca"
    static let issuerOrigins: Set<String> = [
        "https://issuer.eudiw.dev",
        "https://issuer-backend.eudiw.dev",
    ]
    static let redirectURI = URL(string: "eu.europa.ec.euidi://authorization")!
    static let walletProviderURL = URL(string: "https://wallet-provider.eudiw.dev")!
    static let verifierURL = URL(string: "https://verifier.eudiw.dev")!

    struct WalletConfiguration {
        let baseline: EudiWalletKitBaseline
    }

    static func makeWalletConfiguration(
        attestationProvider: any EudiWalletAttestationProviding
    ) throws -> WalletConfiguration {
        let trustConfiguration = TrustConfiguration(
            trustSource: .etsi(.eudiRef),
            defaultPolicy: .warning,
            requireSignedMetadata: true,
            statusTrustPolicy: .warning,
            wrprcTrustPolicy: .warning
        )
        let nativeProvider = EudiWalletAttestationsProviderAdapter(provider: attestationProvider)
        let keyAttestationConfiguration = KeyAttestationConfiguration(
            walletAttestationsProvider: nativeProvider,
            popKeyOptions: KeyOptions(
                curve: .P256,
                secureAreaName: SecureEnclaveSecureArea.name,
                accessControl: []
            )
        )
        func issuer(_ url: String) -> OpenId4VciConfiguration {
            OpenId4VciConfiguration(
                credentialIssuerURL: url,
                clientId: clientID,
                keyAttestationsConfig: keyAttestationConfiguration,
                authFlowRedirectionURI: redirectURI,
                parUsage: .required(authorizationCodeDPoPBinding: true),
                requireDpop: true,
                issuerMetadataPolicy: trustConfiguration.issuerMetadataPolicy,
                cacheIssuerMetadata: true
            )
        }
        let vciConfigurations = Dictionary(uniqueKeysWithValues: issuerOrigins.map { origin in
            (URL(string: origin)!.host!, issuer(origin))
        })
        let baseline = try EudiWalletKitBaseline(
            serviceName: "io.oari.wallet.documents",
            trustConfiguration: trustConfiguration,
            openID4VciConfigurations: vciConfigurations,
            openID4VpConfiguration: OpenId4VpConfiguration(
                clientIdSchemes: [.x509SanDns, .x509Hash],
                supportedTransactionDataTypes: [.default()]
            )
        )
        return WalletConfiguration(baseline: baseline)
    }
}

struct ReferenceDemoWalletAttestationsProvider: EudiWalletAttestationProviding {
    static let baseURL = URL(string: "https://wallet-provider.eudiw.dev")!
    private let transport: any EudiNetworkTransport

    init(transport: any EudiNetworkTransport = ReferenceDemoAttestationURLSessionTransport()) {
        self.transport = transport
    }

    func walletAttestation(publicJWK: String) async throws -> String {
        let jwk = try Self.publicJWK(from: publicJWK)
        return try await post(
            path: "/wallet-instance-attestation/jwk",
            payload: ["jwk": jwk],
            responseKey: "walletInstanceAttestation"
        )
    }

    func keyAttestation(publicJWKs: [String], nonce: String?) async throws -> String {
        guard (1...16).contains(publicJWKs.count), nonce?.utf8.count ?? 0 <= 1_024 else {
            throw ReferenceDemoAttestationError.invalidRequest
        }
        let keys = try publicJWKs.map(Self.publicJWK)
        var payload: [String: Any] = ["jwkSet": ["keys": keys]]
        if let nonce { payload["nonce"] = nonce }
        return try await post(
            path: "/key-attestation/jwk-set",
            payload: payload,
            responseKey: "keyAttestation"
        )
    }

    private func post(path: String, payload: [String: Any], responseKey: String) async throws -> String {
        let body = try JSONSerialization.data(withJSONObject: payload)
        guard body.count <= 65_536 else { throw ReferenceDemoAttestationError.invalidRequest }
        var request = URLRequest(url: Self.baseURL.appendingPathComponent(String(path.dropFirst())))
        request.httpMethod = "POST"
        request.httpBody = body
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.timeoutInterval = 15

        let response = try await transport.data(for: request)
        guard response.statusCode == 200,
              response.body.count <= 65_536,
              Self.contentType(in: response.headers) == "application/json" else {
            throw ReferenceDemoAttestationError.invalidResponse
        }
        guard let object = try? JSONSerialization.jsonObject(with: response.body) as? [String: Any],
              object.count == 1,
              let attestation = object[responseKey] as? String,
              (1...32_768).contains(attestation.utf8.count),
              Self.isCompactJWS(attestation) else {
            throw ReferenceDemoAttestationError.invalidResponse
        }
        return attestation
    }

    private static func publicJWK(from encoded: String) throws -> [String: Any] {
        guard (1...16_384).contains(encoded.utf8.count), let data = encoded.data(using: .utf8),
              let jwk = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let keyType = jwk["kty"] as? String,
              !keyType.isEmpty else {
            throw ReferenceDemoAttestationError.invalidJWK
        }
        let privateMembers: Set<String> = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"]
        guard privateMembers.isDisjoint(with: jwk.keys),
              JSONSerialization.isValidJSONObject(jwk) else {
            throw ReferenceDemoAttestationError.invalidJWK
        }
        return jwk
    }

    private static func contentType(in headers: [String: String]) -> String? {
        headers.first { $0.key.caseInsensitiveCompare("Content-Type") == .orderedSame }?
            .value.split(separator: ";", maxSplits: 1).first.map {
                $0.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            }
    }

    private static func isCompactJWS(_ value: String) -> Bool {
        let parts = value.split(separator: ".", omittingEmptySubsequences: false)
        let allowed = CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
        return parts.count == 3 && parts.allSatisfy {
            !$0.isEmpty && $0.unicodeScalars.allSatisfy(allowed.contains)
        }
    }
}

enum ReferenceDemoAttestationError: Error, Equatable {
    case invalidJWK
    case invalidRequest
    case invalidResponse
}

private final class ReferenceDemoRedirectRejectingDelegate: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping (URLRequest?) -> Void
    ) {
        completionHandler(nil)
    }
}

struct ReferenceDemoAttestationURLSessionTransport: EudiNetworkTransport {
    private let session: URLSession

    init() {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.urlCache = nil
        configuration.httpShouldSetCookies = false
        configuration.httpMaximumConnectionsPerHost = 2
        session = URLSession(
            configuration: configuration,
            delegate: ReferenceDemoRedirectRejectingDelegate(),
            delegateQueue: nil
        )
    }

    func data(for request: URLRequest) async throws -> EudiHTTPResponse {
        let (body, response) = try await session.data(for: request)
        guard let response = response as? HTTPURLResponse else {
            throw ReferenceDemoAttestationError.invalidResponse
        }
        return EudiHTTPResponse(
            body: body,
            statusCode: response.statusCode,
            headers: response.allHeaderFields.reduce(into: [:]) {
                $0[String(describing: $1.key)] = String(describing: $1.value)
            }
        )
    }
}

struct ReferenceDemoCredentialStatusProvider: EudiCredentialStatusProviding {
    func status(for document: EudiWalletDocumentSummary) async throws -> CredentialStatusState {
        .notEvaluated
    }
}
