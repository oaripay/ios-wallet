import EudiWalletKit
import EudiWalletKitAdapter
import Foundation
import MdocSecurity18013
import Testing
@testable import OariWallet

struct EudiReferenceDemoConfigurationTests {
    @Test("Reference demo endpoints and client identity are exact")
    func exactEnvironmentIdentity() {
        #expect(EudiReferenceDemoConfiguration.clientID == "eudiw-abca")
        #expect(EudiReferenceDemoConfiguration.redirectURI.absoluteString ==
                "eu.europa.ec.euidi://authorization")
        #expect(EudiReferenceDemoConfiguration.issuerOrigins == [
            "https://issuer.eudiw.dev",
            "https://issuer-backend.eudiw.dev",
        ])
    }

    @Test("Reference demo composes exact VCI, VP, key, and trust policies")
    func exactWalletKitConfiguration() throws {
        let demo = try EudiReferenceDemoConfiguration.makeWalletConfiguration(
            attestationProvider: ConfigurationAttestationProvider()
        )
        let baseline = demo.baseline
        #expect(Set(baseline.openID4VciConfigurations.keys) == [
            "issuer.eudiw.dev", "issuer-backend.eudiw.dev",
        ])
        #expect(baseline.trustConfiguration.defaultPolicy == .warning)
        #expect(baseline.trustConfiguration.requireSignedMetadata)
        #expect(baseline.trustConfiguration.statusTrustPolicy == .warning)
        #expect(baseline.trustConfiguration.wrprcVpTrustPolicy == .warning)
        #expect(baseline.trustConfiguration.wrprcVciTrustPolicy == .warning)

        for (host, issuer) in baseline.openID4VciConfigurations {
            #expect(issuer.credentialIssuerURL == "https://\(host)")
            #expect(issuer.clientId == "eudiw-abca")
            #expect(issuer.authFlowRedirectionURI == EudiReferenceDemoConfiguration.redirectURI)
            #expect(issuer.requireDpop)
            #expect(!issuer.validateRegistrationCertificate)
            #expect(!issuer.userAuthenticationRequired)
            #expect(issuer.dpopKeyOptions == nil)
            #expect(issuer.keyAttestationsConfig.popKeyOptions?.curve == .P256)
            #expect(issuer.keyAttestationsConfig.popKeyOptions?.secureAreaName ==
                    SecureEnclaveSecureArea.name)
            switch issuer.parUsage {
            case .required(let authorizationCodeDPoPBinding):
                #expect(authorizationCodeDPoPBinding)
            default:
                Issue.record("Reference demo must require PAR")
            }
        }

        let schemes = baseline.openID4VpConfiguration.clientIdSchemes
        #expect(schemes.count == 2)
        guard schemes.count == 2 else { return }
        if case .x509SanDns = schemes[0] {} else {
            Issue.record("First VP client-id scheme must be x509_san_dns")
        }
        if case .x509Hash = schemes[1] {} else {
            Issue.record("Second VP client-id scheme must be x509_hash")
        }
    }

    @Test("Reference demo attestation uses the wallet-instance route and exact payload")
    func walletAttestationRequest() async throws {
        let transport = AttestationTransport(responseKey: "walletInstanceAttestation")
        let provider = ReferenceDemoWalletAttestationsProvider(transport: transport)

        #expect(try await provider.walletAttestation(publicJWK: Self.publicJWK) == Self.compactJWS)
        let request = try #require(await transport.lastRequest)
        #expect(request.url?.absoluteString ==
                "https://wallet-provider.eudiw.dev/wallet-instance-attestation/jwk")
        #expect(request.httpMethod == "POST")
        #expect(request.value(forHTTPHeaderField: "Content-Type") == "application/json")
        let body = try #require(request.httpBody)
        let object = try #require(
            try JSONSerialization.jsonObject(with: body) as? [String: Any]
        )
        #expect(object.count == 1)
        let jwk = try #require(object["jwk"] as? [String: Any])
        #expect(jwk["kty"] as? String == "EC")
        #expect(jwk["d"] == nil)
    }

    @Test("Reference demo key attestation uses the JWK-set route and preserves nonce")
    func keyAttestationRequest() async throws {
        let transport = AttestationTransport(responseKey: "keyAttestation")
        let provider = ReferenceDemoWalletAttestationsProvider(transport: transport)

        #expect(try await provider.keyAttestation(
            publicJWKs: [Self.publicJWK], nonce: "issuer-nonce"
        ) == Self.compactJWS)
        let request = try #require(await transport.lastRequest)
        #expect(request.url?.absoluteString ==
                "https://wallet-provider.eudiw.dev/key-attestation/jwk-set")
        let body = try #require(request.httpBody)
        let object = try #require(
            try JSONSerialization.jsonObject(with: body) as? [String: Any]
        )
        #expect(object["nonce"] as? String == "issuer-nonce")
        let jwkSet = try #require(object["jwkSet"] as? [String: Any])
        let keys = try #require(jwkSet["keys"] as? [[String: Any]])
        #expect(keys.count == 1)
        #expect(keys[0]["kty"] as? String == "EC")
    }

    @Test("Reference demo attestation rejects private JWK material and non-JSON responses")
    func strictAttestationBoundary() async {
        let provider = ReferenceDemoWalletAttestationsProvider(
            transport: AttestationTransport(responseKey: "walletInstanceAttestation")
        )
        await #expect(throws: ReferenceDemoAttestationError.invalidJWK) {
            _ = try await provider.walletAttestation(
                publicJWK: #"{"kty":"EC","crv":"P-256","x":"x","y":"y","d":"private"}"#
            )
        }

        let wrongContentType = ReferenceDemoWalletAttestationsProvider(
            transport: AttestationTransport(
                responseKey: "walletInstanceAttestation",
                contentType: "text/plain"
            )
        )
        await #expect(throws: ReferenceDemoAttestationError.invalidResponse) {
            _ = try await wrongContentType.walletAttestation(publicJWK: Self.publicJWK)
        }
    }

    private static let publicJWK = #"{"kty":"EC","crv":"P-256","x":"eA","y":"eQ"}"#
    private static let compactJWS = "aGVhZGVy.cGF5bG9hZA.c2lnbmF0dXJl"
}

private struct ConfigurationAttestationProvider: EudiWalletAttestationProviding {
    func walletAttestation(publicJWK: String) async throws -> String {
        "aGVhZGVy.cGF5bG9hZA.c2lnbmF0dXJl"
    }

    func keyAttestation(publicJWKs: [String], nonce: String?) async throws -> String {
        "aGVhZGVy.cGF5bG9hZA.c2lnbmF0dXJl"
    }
}

private actor AttestationTransport: EudiNetworkTransport {
    private(set) var lastRequest: URLRequest?
    private let responseKey: String
    private let contentType: String

    init(responseKey: String, contentType: String = "application/json; charset=utf-8") {
        self.responseKey = responseKey
        self.contentType = contentType
    }

    func data(for request: URLRequest) async throws -> EudiHTTPResponse {
        lastRequest = request
        let body = try JSONSerialization.data(withJSONObject: [
            responseKey: "aGVhZGVy.cGF5bG9hZA.c2lnbmF0dXJl",
        ])
        return EudiHTTPResponse(
            body: body,
            statusCode: 200,
            headers: ["Content-Type": contentType]
        )
    }
}
