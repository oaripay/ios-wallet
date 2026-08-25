import EbsiW3CBackend
import Foundation
import IdentityDomain

/// The app-level release composition. Production recognizes explicit HTTPS
/// revision paths while local HTTP compatibility stays Debug-only.
struct W3CBackendComposition: Sendable {
    static let backendID = "openid4vc-w3c"
    static let authorizationClientID = "io.oari.wallet"
    static let authorizationRedirectURI = URL(string: "https://oari.io/oauth/callback")!
    static let credentialModels = "VCDM 1.1, VCDM 2.0, SD-JWT VC"
    static let issuanceProfiles = "Final, Draft 13/17/18"
    static let presentationProfile = "DID, DCQL, direct_post"

    let endpoint: EBSIChainEndpoint
    let environmentPolicy: EBSIEnvironmentPolicy
    let approvedProductionEndpoints: [String: EBSIChainEndpoint]
    let transportProfileRegistry: OID4VCITransportProfileRegistry

    static func make() throws -> W3CBackendComposition {
        let endpoint = try EBSIChainEndpoint.productionEBSIRegistries()
        return W3CBackendComposition(
            endpoint: endpoint,
            environmentPolicy: .production,
            approvedProductionEndpoints: [endpoint.id: endpoint],
            transportProfileRegistry: .productionInteroperability
        )
    }

    static func additionalProfiles() throws -> [EbsiCredentialProfile] {
        // Do not collapse these: their data model and wire representations differ.
        [try .vcdm2JWTVCJSON(), try .vcdm11Jwt(), try .dcSdJWTVC(), try .vcdm2SdJWT()]
    }

    static func ownsCredential(backendID: String?) -> Bool {
        backendID == self.backendID
    }
}
