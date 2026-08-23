import CryptoKit
import Foundation
import IdentityDomain
import TrustDomain
import WalletDomain

public struct OpenID4VCHTTPResponse: Equatable, Sendable {
    public let statusCode: Int
    public let body: Data
    public let headers: [String: String]

    public init(statusCode: Int, body: Data, headers: [String: String] = [:]) {
        self.statusCode = statusCode
        self.body = body
        self.headers = headers
    }
}

public protocol OpenID4VCHTTPTransport: Sendable {
    func send(
        url: URL,
        method: String,
        headers: [String: String],
        body: Data?
    ) async throws -> OpenID4VCHTTPResponse
}

public protocol CredentialIssuerServiceTrustEvaluating: Sendable {
    func evaluate(issuer: String, at date: Date) async -> TrustVerdict
}

/// Trust in an OpenID4VCI HTTPS service and trust in the entity that signed a
/// returned credential are deliberately separate. Implementations of this
/// protocol are only called with the signed issuer extracted after successful
/// credential validation.
public protocol CredentialSignerTrustEvaluating: Sendable {
    func evaluate(issuer: String, at date: Date) async -> TrustVerdict
}

extension EBSITIRCredentialSignerTrustEvaluator: CredentialSignerTrustEvaluating {}

private struct LegacySignerTrustEvaluator: CredentialSignerTrustEvaluating {
    let base: any CredentialIssuerServiceTrustEvaluating
    func evaluate(issuer: String, at date: Date) async -> TrustVerdict {
        await base.evaluate(issuer: issuer, at: date)
    }
}

public protocol W3CCredentialValidating: Sendable {
    func validate(
        rawCredential: Data,
        profile: EbsiCredentialProfile,
        expectedIssuer: String,
        expectedHolderDID: String,
        at date: Date
    ) async throws -> String
}

/// Atomic replay protection for externally supplied OpenID4VP Request Objects.
/// Applications that need replay protection across launches can inject a persistent implementation.
public protocol OpenID4VPReplayProtecting: Sendable {
    func consume(requestDigest: String, nonce: String, expiresAt: Date, at date: Date) async throws
}

public actor InMemoryOpenID4VPReplayStore: OpenID4VPReplayProtecting {
    private var requestDigests: [String: Date] = [:]
    private var nonces: [String: Date] = [:]
    private let maximumEntries: Int
    private let maximumRetention: TimeInterval

    public init(maximumEntries: Int = 1_024, maximumRetention: TimeInterval = 600) {
        self.maximumEntries = max(1, maximumEntries)
        self.maximumRetention = max(1, maximumRetention)
    }

    public func consume(requestDigest: String, nonce: String, expiresAt: Date, at date: Date) throws {
        guard !requestDigest.isEmpty, !nonce.isEmpty, expiresAt > date,
              expiresAt.timeIntervalSince(date) <= maximumRetention else {
            throw OpenID4VCBackendError.invalidPresentationChallenge(reason: "signed request replay lifetime was invalid")
        }
        requestDigests = requestDigests.filter { $0.value > date }
        nonces = nonces.filter { $0.value > date }
        guard requestDigests[requestDigest] == nil, nonces[nonce] == nil else {
            throw OpenID4VCBackendError.invalidPresentationChallenge(reason: "signed request was replayed")
        }
        guard requestDigests.count < maximumEntries, nonces.count < maximumEntries else {
            throw OpenID4VCBackendError.invalidPresentationChallenge(reason: "signed request replay store is at capacity")
        }
        requestDigests[requestDigest] = expiresAt
        nonces[nonce] = expiresAt
    }
}

public struct ResolvedOpenID4VCCredentialOffer: Equatable, Identifiable, Sendable {
    public let id: UUID
    public let issuer: String
    public let displayName: String?
    public let configurationIDs: [String]
    public let transactionCodeRequired: Bool
    public let transactionCodeLength: Int?
    public let transactionCodeDescription: String?
    public let trustOutcome: EbsiTrustGateOutcome
    public let authorizationRequired: Bool
    public let issuerState: String?
    public let representations: [String]
    public let credentialDisplay: [String: CredentialConfigurationDisplay]
}

public struct CredentialConfigurationDisplay: Codable, Equatable, Sendable {
    public let name: String
    public let locale: String?
    public let description: String?
    public let backgroundColor: String?
    public let textColor: String?
    public let logoURL: URL?
    public let logoAlternativeText: String?
    public let backgroundImageURL: URL?
    public let claims: [CredentialConfigurationClaim]
}

public struct CredentialConfigurationClaim: Codable, Equatable, Sendable, Identifiable {
    public let id: String
    public let path: [String]
    public let name: String?
    public let description: String?

    public init(id: String, path: [String], name: String?, description: String?) {
        self.id = id
        self.path = path
        self.name = name
        self.description = description
    }

    public init(from decoder: any Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        if values.contains(.path), !(try values.decodeNil(forKey: .path)) {
            var components = try values.nestedUnkeyedContainer(forKey: .path)
            var decodedPath: [String] = []
            while !components.isAtEnd {
                let componentDecoder = try components.superDecoder()
                let component = try componentDecoder.singleValueContainer()
                if component.decodeNil() {
                    decodedPath.append("*")
                } else if let value = try? component.decode(String.self) {
                    decodedPath.append(value)
                } else if let value = try? component.decode(Int.self) {
                    decodedPath.append("[\(value)]")
                } else {
                    throw DecodingError.dataCorruptedError(
                        in: component,
                        debugDescription: "Credential claim paths support string, integer, and null components."
                    )
                }
            }
            path = decodedPath
        } else {
            path = []
        }
        name = try values.decodeIfPresent(String.self, forKey: .name)
        description = try values.decodeIfPresent(String.self, forKey: .description)
        id = path.joined(separator: ".")
    }

    private enum CodingKeys: String, CodingKey { case path, name, description }
}

public struct WebAuthorizationChallenge: Equatable, Identifiable, Sendable {
    public let id: UUID
    public let authSession: String
    public let authorizationURL: URL
    public let authorizationChallengeEndpoint: URL
    public init(id: UUID, authSession: String, authorizationURL: URL, authorizationChallengeEndpoint: URL) {
        self.id = id
        self.authSession = authSession
        self.authorizationURL = authorizationURL
        self.authorizationChallengeEndpoint = authorizationChallengeEndpoint
    }
}

public enum InteractiveAuthorizationChallenge: Equatable, Sendable {
    case presentation(OpenID4VPPresentationRequest)
    case web(WebAuthorizationChallenge)

    public var authorizationChallengeEndpoint: URL {
        switch self {
        case let .presentation(request): request.authorizationChallengeEndpoint
        case let .web(challenge): challenge.authorizationChallengeEndpoint
        }
    }

}

public enum InteractiveAuthorizationResult: Equatable, Sendable {
    case interaction(InteractiveAuthorizationChallenge)
    case authorizationCode(String)
}

public struct OpenID4VPPresentationRequest: Equatable, Identifiable, Sendable {
    public let id: UUID
    public let authorizationChallengeEndpoint: URL
    public let authSession: String?
    public let interactionType: String
    public let responseMode: String
    public let responseURI: URL?
    public let nonce: String
    public let state: String?
    public let dcqlQuery: [String: AnySendableJSON]
    public let signedRequest: String?
    public let clientID: String?
    /// Decoded `transaction_data` objects supplied by the verifier.
    public let transactionData: [[String: AnySendableJSON]]

    public init(
        id: UUID,
        authorizationChallengeEndpoint: URL,
        authSession: String?,
        interactionType: String,
        responseMode: String,
        responseURI: URL?,
        nonce: String,
        state: String?,
        dcqlQuery: [String: AnySendableJSON],
        signedRequest: String?,
        clientID: String? = nil,
        transactionData: [[String: AnySendableJSON]] = []
    ) {
        self.id = id
        self.authorizationChallengeEndpoint = authorizationChallengeEndpoint
        self.authSession = authSession
        self.interactionType = interactionType
        self.responseMode = responseMode
        self.responseURI = responseURI
        self.nonce = nonce
        self.state = state
        self.dcqlQuery = dcqlQuery
        self.signedRequest = signedRequest
        self.clientID = clientID
        self.transactionData = transactionData
    }
}

public enum WebAuthorizationPollResult: Equatable, Sendable {
    case pending
    case authorizationCode(String)
    case failed(String)
}

public struct DCQLRequestedClaim: Equatable, Identifiable, Sendable {
    public let id: String
    public let path: [String]
    public let value: String
    public let required: Bool
}

public struct DCQLCredentialPresentationRequest: Equatable, Identifiable, Sendable {
    public let id: UUID
    public let verifierName: String?
    public let claims: [DCQLRequestedClaim]
    /// Decoded `transaction_data` objects supplied by the verifier, to be
    /// displayed to the user alongside the requested claims.
    public let transactionData: [[String: AnySendableJSON]]

    public init(
        id: UUID,
        verifierName: String?,
        claims: [DCQLRequestedClaim],
        transactionData: [[String: AnySendableJSON]] = []
    ) {
        self.id = id
        self.verifierName = verifierName
        self.claims = claims
        self.transactionData = transactionData
    }
}

public struct IssuedW3CCredential: Codable, Equatable, Sendable {
    public let id: UUID
    public let configurationID: String
    public let displayName: String
    public let issuerIdentifier: String
    public let profileID: String
    public let representation: EbsiCredentialRepresentation
    public let hasStatusReference: Bool
    public let displayClaims: [CredentialDisplayClaim]
    public let display: CredentialDisplayMetadata?
}

public struct DeferredCredentialExpectation: Codable, Equatable, Sendable {
    public let format: String
    public let profileIDs: [String]
    public let displayName: String
    public let display: CredentialDisplayMetadata?

    public init(format: String, profileIDs: [String], displayName: String, display: CredentialDisplayMetadata?) {
        self.format = format
        self.profileIDs = profileIDs
        self.displayName = displayName
        self.display = display
    }
}

public struct DeferredStagedCredential: Codable, Equatable, Sendable {
    public let stored: StoredEbsiCredential
    public let issued: IssuedW3CCredential
}

public struct DeferredCredentialNotification: Codable, Equatable, Sendable {
    public let endpoint: URL
    public let notificationID: String
}

/// A sensitive, persistence-ready continuation for deferred issuance.
/// Persist this value only in encrypted, access-controlled storage. Endpoints
/// are restored only when they remain HTTPS and same-origin with `issuer`.
public struct DeferredW3CCredential: Codable, Equatable, Sendable {
    public let transactionID: UUID
    public let issuer: URL
    public let endpoint: URL
    public let remoteTransactionIDs: [String: String]
    public let accessToken: String
    public let accessTokenExpiresAt: Date?
    public let usesDPoP: Bool
    public let securityState: OID4VCIClientSecurityState?
    public let holderIdentity: W3CHolderIdentity
    public let expectations: [String: DeferredCredentialExpectation]
    public let stagedCredentials: [DeferredStagedCredential]
    public let notifications: [DeferredCredentialNotification]
    public let notificationEndpoint: URL?
    public let serviceTrustAccepted: Bool
    public let transportProfile: OID4VCITransportProfile
    public let pollInterval: TimeInterval
    public let nextPollAt: Date

    public var configurationIDs: [String] { remoteTransactionIDs.keys.sorted() }

    public init(
        transactionID: UUID,
        issuer: URL,
        endpoint: URL,
        remoteTransactionIDs: [String: String],
        accessToken: String,
        accessTokenExpiresAt: Date?,
        usesDPoP: Bool,
        securityState: OID4VCIClientSecurityState?,
        holderIdentity: W3CHolderIdentity,
        expectations: [String: DeferredCredentialExpectation],
        stagedCredentials: [DeferredStagedCredential],
        notifications: [DeferredCredentialNotification],
        notificationEndpoint: URL?,
        serviceTrustAccepted: Bool,
        transportProfile: OID4VCITransportProfile,
        pollInterval: TimeInterval,
        nextPollAt: Date
    ) {
        self.transactionID = transactionID
        self.issuer = issuer
        self.endpoint = endpoint
        self.remoteTransactionIDs = remoteTransactionIDs
        self.accessToken = accessToken
        self.accessTokenExpiresAt = accessTokenExpiresAt
        self.usesDPoP = usesDPoP
        self.securityState = securityState
        self.holderIdentity = holderIdentity
        self.expectations = expectations
        self.stagedCredentials = stagedCredentials
        self.notifications = notifications
        self.notificationEndpoint = notificationEndpoint
        self.serviceTrustAccepted = serviceTrustAccepted
        self.transportProfile = transportProfile
        self.pollInterval = pollInterval
        self.nextPollAt = nextPollAt
    }

    fileprivate func updated(
        remoteTransactionIDs: [String: String],
        stagedCredentials: [DeferredStagedCredential],
        notifications: [DeferredCredentialNotification],
        pollInterval: TimeInterval,
        nextPollAt: Date
    ) -> Self {
        Self(
            transactionID: transactionID, issuer: issuer, endpoint: endpoint,
            remoteTransactionIDs: remoteTransactionIDs, accessToken: accessToken,
            accessTokenExpiresAt: accessTokenExpiresAt, usesDPoP: usesDPoP,
            securityState: securityState, holderIdentity: holderIdentity,
            expectations: expectations, stagedCredentials: stagedCredentials,
            notifications: notifications, notificationEndpoint: notificationEndpoint,
            serviceTrustAccepted: serviceTrustAccepted, transportProfile: transportProfile,
            pollInterval: pollInterval, nextPollAt: nextPollAt
        )
    }
}

public enum W3CCredentialIssuanceOutcome: Equatable, Sendable {
    case issued([IssuedW3CCredential])
    case deferred(DeferredW3CCredential)
}

public enum OpenID4VCBackendError: Error, Equatable, Sendable {
    case malformedOffer
    case unsafeEndpoint
    case unsupportedGrant
    case invalidTransactionCode
    case untrustedConsentRequired
    case rejectedTrust
    case invalidResponse
    case missingCredentialNonce
    case missingCredentialAuthorization
    case credentialAuthorizationMismatch(offered: String, authorized: [String])
    case unknownTransaction
    case presentationRequired
    case invalidPresentationResponse
    case presentationCredentialUnavailable
    case invalidPresentationChallenge(reason: String)
    case presentationSubmissionHTTPError(method: String, path: String, status: Int, detail: String?)
    case authorizationFailed
    case decodingFailed(stage: String, path: String, reason: String)
    case remoteOAuthError(code: String, detail: String?)
    case remoteHTTPError(status: Int, detail: String?)
    case clientSecurityUnavailable
    case holderIdentityRecoveryRequired
    case invalidTokenType(expected: String, actual: String?)
    case credentialSignerTrustWarning(EbsiTrustWarning)
    case deferredCredentialPending(DeferredW3CCredential)
    case deferredCredentialNotReady(nextPollAt: Date)
    case deferredCredentialSignerTrustWarning(EbsiTrustWarning, DeferredW3CCredential)
}

public actor OpenID4VCW3CBackend {
    private struct Transaction: Sendable {
        let issuer: URL
        let issuerMetadata: IssuerMetadata
        let configurationIDs: [String]
        let grant: Grant
        let trustOutcome: EbsiTrustGateOutcome
    }

    private struct StagedCredential: Sendable {
        let stored: StoredEbsiCredential
        let result: IssuedW3CCredential
    }

    private struct StagedNotification: Sendable {
        let endpoint: URL
        let notificationID: String
        let accessToken: String
    }

    private struct StagedIssuance: Sendable {
        let credentials: [StagedCredential]
        let notifications: [StagedNotification]
    }


    enum Grant: Sendable {
        case preAuthorized(code: String, txCode: TxCode?)
        case authorizationCode(issuerState: String)
    }

    struct TxCode: Sendable {
        let length: Int?
        let numeric: Bool
        let description: String?
    }

    private let transport: any OpenID4VCHTTPTransport
    private let trustEvaluator: any CredentialIssuerServiceTrustEvaluating
    private let credentialSignerTrustEvaluator: any CredentialSignerTrustEvaluating
    private let keyProvider: any KeyProvider
    private let credentialStore: any EbsiCredentialStore
    private let credentialValidator: any W3CCredentialValidating
    private let profiles: [EbsiCredentialProfile]
    private let clientSecurity: (any OID4VCIClientSecurity)?
    private let transportProfileRegistry: OID4VCITransportProfileRegistry
    private let holderIdentityProvider: any W3CHolderIdentityProviding
    private let presentationRequestValidator: (any OpenID4VPRequestObjectValidating)?
    private let presentationReplayProtection: any OpenID4VPReplayProtecting
    private let trustEnvironment: EbsiTrustEnvironment
    private let authorizationClientID: String
    private let authorizationRedirectURI: URL
    private let now: @Sendable () -> Date
    private var transactions: [UUID: Transaction] = [:]
    private var authorizationCodes: [UUID: String] = [:]
    private var authorizationCodeVerifiers: [UUID: String] = [:]
    private var authorizationStates: [UUID: String] = [:]
    private var trustConsents: Set<UUID> = []
    private var presentationChallenges: [UUID: OpenID4VPPresentationRequest] = [:]
    private var presentationChallengeTasks: [UUID: Task<InteractiveAuthorizationChallenge, Error>] = [:]
    private var interactiveAuthorizationContexts: [UUID: InteractiveAuthorizationContext] = [:]
    private var preparedPIDPresentations: [UUID: PreparedW3CPresentation] = [:]
    private var transactionHolderIdentities: [UUID: W3CHolderIdentity] = [:]
    private var stagedCredentials: [UUID: StagedIssuance] = [:]

    public init(
        transport: any OpenID4VCHTTPTransport,
        trustEvaluator: any CredentialIssuerServiceTrustEvaluating,
        credentialSignerTrustEvaluator: (any CredentialSignerTrustEvaluating)? = nil,
        keyProvider: any KeyProvider,
        credentialStore: any EbsiCredentialStore,
        credentialValidator: any W3CCredentialValidating,
        profile: EbsiCredentialProfile,
        additionalProfiles: [EbsiCredentialProfile] = [],
        clientSecurity: (any OID4VCIClientSecurity)? = nil,
        transportProfileRegistry: OID4VCITransportProfileRegistry = .finalOnly,
        holderIdentityProvider: (any W3CHolderIdentityProviding)? = nil,
        presentationRequestValidator: (any OpenID4VPRequestObjectValidating)? = nil,
        presentationReplayProtection: any OpenID4VPReplayProtecting = InMemoryOpenID4VPReplayStore(),
        trustEnvironment: EbsiTrustEnvironment = .development,
        authorizationClientID: String = "oari-development-wallet",
        authorizationRedirectURI: URL = URL(string: "https://oari.io/oauth/callback")!,
        now: @escaping @Sendable () -> Date = Date.init
    ) {
        self.transport = transport
        self.trustEvaluator = trustEvaluator
        self.credentialSignerTrustEvaluator = credentialSignerTrustEvaluator
            ?? LegacySignerTrustEvaluator(base: trustEvaluator)
        self.keyProvider = keyProvider
        self.credentialStore = credentialStore
        self.credentialValidator = credentialValidator
        self.profiles = [profile] + additionalProfiles
        self.clientSecurity = clientSecurity
        self.transportProfileRegistry = transportProfileRegistry
        self.holderIdentityProvider = holderIdentityProvider ?? PersistentW3CHolderIdentityProvider(
            keyProvider: keyProvider,
            referenceStore: InMemoryW3CHolderKeyReferenceStore()
        )
        self.presentationRequestValidator = presentationRequestValidator
        self.presentationReplayProtection = presentationReplayProtection
        self.trustEnvironment = trustEnvironment
        self.authorizationClientID = authorizationClientID
        self.authorizationRedirectURI = authorizationRedirectURI
        self.now = now
    }

    public func resolveOffer(_ value: String) async throws -> ResolvedOpenID4VCCredentialOffer {
        guard let url = URL(string: value), let components = URLComponents(url: url, resolvingAgainstBaseURL: false) else {
            throw OpenID4VCBackendError.malformedOffer
        }
        let items = components.queryItems ?? []
        let data: Data
        if let embedded = items.first(where: { $0.name == "credential_offer" })?.value {
            data = Data(embedded.utf8)
        } else if let reference = items.first(where: { $0.name == "credential_offer_uri" })?.value,
                  let referenceURL = URL(string: reference) {
            try Self.validateHTTPS(referenceURL)
            data = try await successfulGET(
                referenceURL,
                allowedOrigins: [try Self.origin(of: referenceURL)]
            )
        } else if components.scheme?.lowercased() == "https" ||
                    (components.scheme?.lowercased() == "http" && components.host == "127.0.0.1") {
            try Self.validateHTTPS(url)
            data = try await successfulGET(
                url,
                allowedOrigins: [try Self.origin(of: url)]
            )
        } else {
            throw OpenID4VCBackendError.malformedOffer
        }
        let offer = try Self.decode(CredentialOffer.self, from: data, stage: "credential offer")
        guard let issuer = URL(string: offer.credentialIssuer) else { throw OpenID4VCBackendError.malformedOffer }
        try Self.validateHTTPS(issuer)
        let grant: Grant
        if let preauthorized = offer.grants?.preauthorized {
            grant = .preAuthorized(
                code: preauthorized.code,
                txCode: preauthorized.txCode.map {
                    TxCode(length: $0.length, numeric: $0.inputMode == "numeric", description: $0.description)
                }
            )
        } else if let authorization = offer.grants?.authorizationCode,
                  let issuerState = authorization.issuerState {
            grant = .authorizationCode(issuerState: issuerState)
        } else {
            throw OpenID4VCBackendError.unsupportedGrant
        }
        let issuerMetadataURL = try Self.wellKnownURL(
            name: "openid-credential-issuer",
            issuer: issuer
        )
        let issuerMetadata = try await discoverMetadata(
            IssuerMetadata.self,
            name: "openid-credential-issuer",
            issuer: issuer,
            standardURL: issuerMetadataURL,
            stage: "credential issuer metadata"
        )
        let selectedConfigurations = try offer.credentialConfigurationIds.map { configurationID in
            guard let configuration = issuerMetadata.credentialConfigurations[configurationID] else {
                throw OpenID4VCBackendError.unsupportedGrant
            }
            return configuration
        }
        let representations = selectedConfigurations.map(\.format)
        guard representations.allSatisfy(Self.supportedRepresentation) else {
            throw OpenID4VCBackendError.unsupportedGrant
        }
        // `credential_issuer` identifies the HTTPS protocol service, not the
        // credential signer. Its identity is established by the HTTPS and
        // metadata/endpoint same-origin checks above and below; never submit it
        // to a DID Trusted Issuers Registry.
        let outcome: EbsiTrustGateOutcome = .allow
        let id = UUID()
        transactions[id] = Transaction(
            issuer: issuer,
            issuerMetadata: issuerMetadata,
            configurationIDs: offer.credentialConfigurationIds,
            grant: grant,
            trustOutcome: outcome
        )
        return ResolvedOpenID4VCCredentialOffer(
            id: id,
            issuer: offer.credentialIssuer,
            displayName: issuerMetadata.display?.first?.name,
            configurationIDs: offer.credentialConfigurationIds,
            transactionCodeRequired: ifCasePreAuthorizedTxCode(grant),
            transactionCodeLength: transactionCodeLength(grant),
            transactionCodeDescription: transactionCodeDescription(grant),
            trustOutcome: outcome,
            authorizationRequired: ifCaseAuthorization(grant),
            issuerState: ifCaseIssuerState(grant),
            representations: representations
            , credentialDisplay: issuerMetadata.credentialConfigurations.mapValues(\.display)
        )
    }

    public func beginPresentationRequired(
        id: UUID,
        allowUntrusted: Bool,
        interactionTypes: [String] = [
            "urn:openid:dcp:ia:openid4vp_presentation",
            "urn:openid:dcp:ia:auth_via_web",
        ]
    ) async throws -> InteractiveAuthorizationChallenge {
        if let context = interactiveAuthorizationContexts[id] {
            guard context.expiresAt > now() else {
                interactiveAuthorizationContexts[id] = nil
                presentationChallenges[id] = nil
                preparedPIDPresentations[id] = nil
                authorizationCodeVerifiers[id] = nil
                authorizationStates[id] = nil
                throw OpenID4VCBackendError.invalidPresentationChallenge(reason: "authorization session expired")
            }
            return context.activeInteraction
        }
        if let task = presentationChallengeTasks[id] {
            return try await task.value
        }
        let task = Task { [self] in
            try await createPresentationChallenge(
                id: id,
                allowUntrusted: allowUntrusted,
                interactionTypes: interactionTypes
            )
        }
        presentationChallengeTasks[id] = task
        do {
            let challenge = try await task.value
            let context = InteractiveAuthorizationContext(
                generationID: UUID(),
                authorizationChallengeEndpoint: challenge.authorizationChallengeEndpoint,
                activeInteraction: challenge,
                expiresAt: now().addingTimeInterval(300)
            )
            interactiveAuthorizationContexts[id] = context
            if case let .presentation(request) = challenge { presentationChallenges[id] = request }
            presentationChallengeTasks[id] = nil
            return challenge
        } catch {
            presentationChallengeTasks[id] = nil
            authorizationCodeVerifiers[id] = nil
            throw error
        }
    }

    private func createPresentationChallenge(
        id: UUID,
        allowUntrusted: Bool,
        interactionTypes: [String] = [
            "urn:openid:dcp:ia:openid4vp_presentation",
            "urn:openid:dcp:ia:auth_via_web",
        ]
    ) async throws -> InteractiveAuthorizationChallenge {
        guard let transaction = transactions[id],
              case let .authorizationCode(issuerState) = transaction.grant else {
            throw OpenID4VCBackendError.presentationRequired
        }
        try authorizeTrust(transaction: transaction, id: id, allowUntrusted: allowUntrusted)
        let usesDraftInteraction = interactionTypes == ["openid4vp_presentation"]
        let endpoint: URL
        let requestMethod: String
        let requestURL: URL
        let requestBody: Data?
        let authorizationServer = URL(
            string: transaction.issuerMetadata.authorizationServers?.first ?? transaction.issuer.absoluteString
        ) ?? transaction.issuer
        let authorizationServerOrigin = try Self.origin(of: authorizationServer)
        let metadataURL = try Self.wellKnownURL(
            name: "oauth-authorization-server",
            issuer: authorizationServer
        )
        let metadata = try await discoverMetadata(
            AuthorizationMetadata.self,
            name: "oauth-authorization-server",
            issuer: authorizationServer,
            standardURL: metadataURL,
            stage: "authorization server metadata"
        )
        if let metadataIssuer = metadata.issuer,
           URL(string: metadataIssuer) != authorizationServer {
            throw OpenID4VCBackendError.invalidPresentationChallenge(
                reason: "authorization server metadata issuer did not match the selected server"
            )
        }
        if !usesDraftInteraction,
           let publishedEndpoint = metadata.authorizationChallengeEndpoint,
           let url = URL(string: publishedEndpoint),
           try Self.origin(of: url) == authorizationServerOrigin {
            endpoint = url
            requestMethod = "POST"
            requestURL = endpoint
            requestBody = try interactiveAuthorizationRequestBody(
                id: id,
                issuerState: issuerState,
                interactionTypes: interactionTypes,
                endpoint: endpoint,
                configurationIDs: transaction.configurationIDs,
                includeState: usesDraftInteraction
            )
        } else if let publishedEndpoint = transaction.issuerMetadata.interactiveAuthorizationEndpoint,
                  let url = URL(string: publishedEndpoint),
                  try Self.origin(of: url) == Self.origin(of: transaction.issuer) {
            endpoint = url
            requestMethod = "POST"
            requestURL = endpoint
            requestBody = try interactiveAuthorizationRequestBody(
                id: id,
                issuerState: issuerState,
                interactionTypes: interactionTypes,
                endpoint: endpoint,
                configurationIDs: transaction.configurationIDs,
                includeState: usesDraftInteraction
            )
        } else {
            if let value = metadata.authorizationEndpoint,
               let url = URL(string: value),
               try Self.origin(of: url) == authorizationServerOrigin {
                endpoint = url
                requestMethod = "GET"
                let fields = try interactiveAuthorizationRequestFields(
                    id: id,
                    issuerState: issuerState,
                    interactionTypes: interactionTypes,
                    endpoint: endpoint,
                    configurationIDs: transaction.configurationIDs,
                    includeState: usesDraftInteraction
                )
                var components = URLComponents(url: endpoint, resolvingAgainstBaseURL: false)
                components?.queryItems = fields.compactMap { key, value in
                    value.map { URLQueryItem(name: key, value: $0) }
                }
                guard let url = components?.url else { throw OpenID4VCBackendError.unsafeEndpoint }
                requestURL = url
                requestBody = nil
            } else {
                endpoint = transaction.issuer.appendingPathComponent(
                    usesDraftInteraction ? "authorize" : "authorize-challenge"
                )
                requestMethod = "POST"
                requestURL = endpoint
                requestBody = form([
                    "issuer_state": issuerState,
                    "interaction_types_supported": interactionTypes.joined(separator: ","),
                ])
            }
        }
        let endpointOrigin = try Self.origin(of: endpoint)
        let issuerOrigin = try Self.origin(of: transaction.issuer)
        guard endpointOrigin == authorizationServerOrigin || endpointOrigin == issuerOrigin else {
            throw OpenID4VCBackendError.unsafeEndpoint
        }
        let raw = try await transport.send(
            url: requestURL,
            method: requestMethod,
            headers: requestMethod == "POST"
                ? ["Content-Type": "application/x-www-form-urlencoded"]
                : ["Accept": "application/json"],
            body: requestBody
        )
        guard raw.body.count <= 1_048_576 else {
            throw OpenID4VCBackendError.invalidPresentationChallenge(reason: "response exceeded the 1 MB limit")
        }
        guard raw.statusCode == 200 || raw.statusCode == 403 else {
            let detail = Self.safeHTTPErrorDetail(raw.body)
            throw OpenID4VCBackendError.invalidPresentationChallenge(
                reason: "\(requestMethod) \(endpoint.path) returned HTTP \(raw.statusCode)\(detail.map { ": \($0)" } ?? "")"
            )
        }
        let data = raw.body
        let response = try Self.decode(
            PresentationChallengeResponse.self,
            from: data,
            stage: "presentation challenge"
        )
        if raw.statusCode == 403, response.error != "insufficient_authorization" {
            throw OpenID4VCBackendError.invalidPresentationChallenge(reason: "response was not insufficient_authorization")
        }
        if raw.statusCode == 200, response.error != nil {
            throw OpenID4VCBackendError.invalidPresentationChallenge(reason: "successful response contained an error")
        }
        if (response.interactionTypeRequired ?? response.type) == "urn:openid:dcp:ia:auth_via_web" {
            guard interactionTypes.contains("urn:openid:dcp:ia:auth_via_web"),
                  let session = response.authSession, !session.isEmpty,
                  let value = response.authorizationURL,
                  let authorizationURL = URL(string: value),
                  authorizationURL.scheme?.lowercased() == "https", authorizationURL.host != nil else {
                throw OpenID4VCBackendError.invalidPresentationChallenge(reason: "web interaction was malformed")
            }
            return .web(WebAuthorizationChallenge(
                id: id, authSession: session, authorizationURL: authorizationURL,
                authorizationChallengeEndpoint: endpoint
            ))
        }
        let expectedInteractionType = usesDraftInteraction
            ? "openid4vp_presentation"
            : "urn:openid:dcp:ia:openid4vp_presentation"
        guard (response.interactionTypeRequired ?? response.type) == expectedInteractionType,
              interactionTypes.contains(expectedInteractionType),
              usesDraftInteraction || !(response.authSession?.isEmpty ?? true) else {
            throw OpenID4VCBackendError.invalidPresentationChallenge(
                reason: "response did not contain the requested interaction type and auth_session"
            )
        }
        guard let request = response.openid4vpRequest else {
            throw OpenID4VCBackendError.invalidPresentationChallenge(
                reason: "response did not contain openid4vp_request"
            )
        }
        let signedClaims: VerifiedOpenID4VPRequestObject?
        if let requestJWT = request.requestJWT {
            guard let presentationRequestValidator else {
                throw OpenID4VCBackendError.invalidPresentationChallenge(
                    reason: "signed request verification is not configured"
                )
            }
            signedClaims = try await presentationRequestValidator.validate(
                compactJWT: requestJWT,
                at: now()
            )
            guard usesDraftInteraction || signedClaims?.audience == "https://self-issued.me/v2" else {
                throw OpenID4VCBackendError.invalidPresentationChallenge(
                    reason: "signed interactive request audience was invalid"
                )
            }
            guard usesDraftInteraction || signedClaims?.responseType == "vp_token" else {
                throw OpenID4VCBackendError.invalidPresentationChallenge(
                    reason: "signed interactive request response_type was invalid"
                )
            }
        } else {
            signedClaims = nil
        }
        if let signedClaims {
            try Self.requireUnsignedMatchesSigned(request: request, signed: signedClaims)
        }
        let responseMode = signedClaims?.responseMode ?? request.responseMode ?? request.requestObject?.responseMode
        let nonce = signedClaims?.nonce ?? request.nonce ?? request.requestObject?.nonce
        let dcqlQuery = signedClaims?.dcqlQuery ?? request.dcqlQuery ?? request.requestObject?.dcqlQuery
        guard let responseMode,
              let nonce,
              !nonce.isEmpty,
              let dcqlQuery else {
            throw OpenID4VCBackendError.invalidPresentationChallenge(
                reason: "request did not contain response_mode, nonce, and dcql_query"
            )
        }
        let supportedResponseModes = usesDraftInteraction
            ? ["direct_post", "iar-post"]
            : ["ia_post"]
        guard supportedResponseModes.contains(responseMode) else {
            throw OpenID4VCBackendError.invalidPresentationChallenge(
                reason: responseMode == "ia_post.jwt"
                    ? "encrypted ia_post.jwt is not implemented"
                    : "unsupported response_mode \(responseMode)"
            )
        }
        let requestedResponseURI = signedClaims?.responseURI ?? request.responseURI ?? request.requestObject?.responseURI
        if responseMode == "ia_post",
           let requestedResponseURI,
           let url = URL(string: requestedResponseURI),
           url != endpoint {
            throw OpenID4VCBackendError.invalidPresentationChallenge(
                reason: "ia_post response_uri did not match authorization_challenge_endpoint"
            )
        }
        _ = try Self.presentationQuery(from: dcqlQuery)
        if let requestJWT = request.requestJWT, let signedClaims {
            let expiry = min(signedClaims.expiresAt ?? now().addingTimeInterval(300), now().addingTimeInterval(300))
            try await presentationReplayProtection.consume(
                requestDigest: Data(SHA256.hash(data: Data(requestJWT.utf8))).base64URLEncodedString(),
                nonce: signedClaims.nonce,
                expiresAt: expiry,
                at: now()
            )
        }
        let challenge = OpenID4VPPresentationRequest(
            id: id,
            authorizationChallengeEndpoint: endpoint,
            authSession: response.authSession,
            interactionType: expectedInteractionType,
            responseMode: responseMode,
            responseURI: endpoint,
            nonce: nonce,
            state: signedClaims?.state ?? request.state ?? request.requestObject?.state,
            dcqlQuery: dcqlQuery,
            signedRequest: request.request,
            clientID: signedClaims?.clientID ?? request.clientID ?? request.requestObject?.clientID,
            transactionData: signedClaims?.transactionData ?? []
        )
        return .presentation(challenge)
    }

    public func prepareStoredPIDPresentation(id: UUID) async throws -> DCQLCredentialPresentationRequest {
        guard let context = interactiveAuthorizationContexts[id], context.expiresAt > now() else {
            throw OpenID4VCBackendError.unknownTransaction
        }
        guard case let .presentation(challenge) = context.activeInteraction else {
            throw OpenID4VCBackendError.unknownTransaction
        }
        let holderIdentity = try await holderIdentity(for: id)
        let query = try Self.presentationQuery(from: challenge.dcqlQuery)
        let credentials = try await credentialStore.credentials()
        for credential in credentials where credential.holderKeyReference == holderIdentity.keyID.rawValue.uuidString {
            var claims: [DCQLRequestedClaim] = []
            let kind: PreparedW3CPresentation.Kind
            switch (query.format, credential.representation) {
            case ("dc+sd-jwt", .dcSdJwt):
                let parsed = try Self.parseStoredSDJWT(credential.rawCredential)
                guard query.vctValues.contains(parsed.vct) else { continue }
                var disclosures: [String: String] = [:]
                var satisfies = true
                for requestedClaim in query.claims {
                    let path = requestedClaim.path
                    guard path.count == 1, let name = path.first else {
                        satisfies = false
                        break
                    }
                    if let disclosure = parsed.disclosures[name] {
                        claims.append(Self.presentationClaim(
                            id: requestedClaim.id, path: path, value: disclosure.displayValue
                        ))
                        disclosures[requestedClaim.id] = disclosure.encoded
                    } else if let value = parsed.payload[name]?.displayString {
                        claims.append(Self.presentationClaim(
                            id: requestedClaim.id, path: path, value: value
                        ))
                    } else {
                        satisfies = false
                        break
                    }
                }
                guard satisfies else { continue }
                kind = .sdJWT(issuerJWT: parsed.issuerJWT, disclosures: disclosures)
            case ("jwt_vc_json", .jwtVcJson), ("jwt_vc_json", .vcdm2Jwt):
                guard let profile = profiles.first(where: { $0.id == credential.profileID }) else { continue }
                let compact = String(decoding: credential.rawCredential, as: UTF8.self)
                let document = try EbsiCredentialInspector().inspectCompactJWT(compact, profile: profile)
                guard Self.matchesTypeValues(query.typeValues, document: document) else { continue }
                var satisfies = true
                for requestedClaim in query.claims {
                    let path = requestedClaim.path
                    guard let value = Self.value(at: path, in: document)?.displayString else {
                        satisfies = false
                        break
                    }
                    claims.append(Self.presentationClaim(
                        id: requestedClaim.id, path: path, value: value
                    ))
                }
                guard satisfies else { continue }
                kind = credential.representation == .vcdm2Jwt ? .jwtVC20(compact) : .jwtVC11(compact)
            default:
                continue
            }
            preparedPIDPresentations[id] = PreparedW3CPresentation(
                credential: credential,
                authorizationGenerationID: context.generationID,
                kind: kind,
                requiredClaimIDs: Set(claims.map(\.id)),
                queryID: query.id
            )
            return DCQLCredentialPresentationRequest(
                id: id,
                verifierName: challenge.clientID,
                claims: claims,
                transactionData: challenge.transactionData
            )
        }
        throw OpenID4VCBackendError.presentationCredentialUnavailable
    }

    public func pollWebAuthorization(id: UUID) async throws -> WebAuthorizationPollResult {
        guard let context = interactiveAuthorizationContexts[id], context.expiresAt > now(),
              case let .web(challenge) = context.activeInteraction else {
            throw OpenID4VCBackendError.unknownTransaction
        }
        let response = try await transport.send(
            url: context.authorizationChallengeEndpoint,
            method: "POST",
            headers: ["Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"],
            body: form(["auth_session": challenge.authSession])
        )
        guard response.statusCode == 200 || response.statusCode == 400 else {
            throw OpenID4VCBackendError.authorizationFailed
        }
        let result = try Self.decode(
            InteractiveAuthorizationResponse.self,
            from: response.body,
            stage: "web authorization response"
        )
        if result.error == "authorization_pending" {
            if let session = result.authSession, !session.isEmpty, session != challenge.authSession {
                interactiveAuthorizationContexts[id] = InteractiveAuthorizationContext(
                    generationID: context.generationID,
                    authorizationChallengeEndpoint: context.authorizationChallengeEndpoint,
                    activeInteraction: .web(WebAuthorizationChallenge(
                        id: id, authSession: session, authorizationURL: challenge.authorizationURL,
                        authorizationChallengeEndpoint: context.authorizationChallengeEndpoint
                    )),
                    expiresAt: context.expiresAt
                )
            }
            return .pending
        }
        if let error = result.error { return .failed(error) }
        guard let code = result.authorizationCode ?? result.code, !code.isEmpty else {
            throw OpenID4VCBackendError.invalidResponse
        }
        return .authorizationCode(code)
    }

    private func webAuthorizationChallenge(
        id: UUID,
        response: InteractiveAuthorizationResponse,
        authorizationChallengeEndpoint: URL
    ) throws -> WebAuthorizationChallenge {
        guard response.interactionTypeRequired == "urn:openid:dcp:ia:auth_via_web",
              let authSession = response.authSession, !authSession.isEmpty,
              let value = response.authorizationURL,
              let authorizationURL = URL(string: value),
              authorizationURL.scheme?.lowercased() == "https", authorizationURL.host != nil else {
            throw OpenID4VCBackendError.invalidPresentationResponse
        }
        return WebAuthorizationChallenge(
            id: id, authSession: authSession, authorizationURL: authorizationURL,
            authorizationChallengeEndpoint: authorizationChallengeEndpoint
        )
    }

    public func beginStoredOpenID4VPPresentation(uri: String) async throws -> DCQLCredentialPresentationRequest {
        guard let components = URLComponents(string: uri),
              components.scheme?.lowercased() == "openid4vp",
              let queryItems = components.queryItems,
              let presentationRequestValidator else {
            throw OpenID4VCBackendError.invalidPresentationChallenge(reason: "OpenID4VP request envelope was malformed")
        }
        let singletonNames = [
            "client_id", "request", "request_uri", "request_uri_method", "response_type",
            "response_mode", "response_uri", "nonce", "state", "dcql_query",
        ]
        for name in singletonNames { _ = try Self.singleQueryValue(named: name, in: queryItems) }
        guard let outerClientID = try Self.singleQueryValue(named: "client_id", in: queryItems),
              !outerClientID.isEmpty else {
            throw OpenID4VCBackendError.invalidPresentationChallenge(reason: "OpenID4VP client_id was missing")
        }
        let inlineRequest = try Self.singleQueryValue(named: "request", in: queryItems)
        let requestURIValue = try Self.singleQueryValue(named: "request_uri", in: queryItems)
        guard (inlineRequest == nil) != (requestURIValue == nil) else {
            throw OpenID4VCBackendError.invalidPresentationChallenge(
                reason: "OpenID4VP envelope must contain exactly one of request or request_uri"
            )
        }
        let hasRequestURIMethod = queryItems.contains { $0.name == "request_uri_method" }
        let requestURIMethod = try Self.singleQueryValue(named: "request_uri_method", in: queryItems)
        if hasRequestURIMethod, requestURIMethod?.isEmpty != false {
            throw OpenID4VCBackendError.invalidPresentationChallenge(reason: "request_uri_method was empty")
        }
        if requestURIValue == nil, requestURIMethod != nil {
            throw OpenID4VCBackendError.invalidPresentationChallenge(reason: "request_uri_method requires request_uri")
        }
        if let requestURIMethod {
            if requestURIMethod == "post" {
                throw OpenID4VCBackendError.invalidPresentationChallenge(reason: "request_uri_method post is not supported")
            }
            guard requestURIMethod == "get" else {
                throw OpenID4VCBackendError.invalidPresentationChallenge(
                    reason: "unsupported request_uri_method \(requestURIMethod)"
                )
            }
        }
        let compactRequest: String
        var fetchedRequestURI: URL?
        if let inlineRequest {
            guard !inlineRequest.isEmpty else {
                throw OpenID4VCBackendError.invalidPresentationChallenge(reason: "inline request was empty")
            }
            compactRequest = inlineRequest
        } else {
            guard let requestURIValue, let requestURI = URL(string: requestURIValue),
                  requestURI.scheme?.lowercased() == "https" else {
                throw OpenID4VCBackendError.invalidPresentationChallenge(reason: "request_uri was malformed")
            }
            fetchedRequestURI = requestURI
            let response = try await successfulHTTPResponse(
                requestURI,
                method: "GET",
                headers: ["Accept": "application/oauth-authz-req+jwt"],
                body: nil,
                allowedOrigins: [try Self.origin(of: requestURI)]
            )
            guard Self.baseMediaType(of: response) == "application/oauth-authz-req+jwt" else {
                throw OpenID4VCBackendError.invalidPresentationChallenge(
                    reason: "request_uri response Content-Type was not application/oauth-authz-req+jwt"
                )
            }
            guard let value = String(data: response.body, encoding: .utf8), !value.isEmpty else {
                throw OpenID4VCBackendError.invalidPresentationChallenge(reason: "request_uri returned an empty Request Object")
            }
            compactRequest = value
        }
        let verified = try await presentationRequestValidator.validate(compactJWT: compactRequest, at: now())
        try Self.requireOuterValuesMatchSigned(queryItems, signed: verified)
        guard verified.clientID == outerClientID else {
            throw OpenID4VCBackendError.invalidPresentationChallenge(reason: "outer and signed client_id values did not match")
        }
        try Self.validateStandaloneLifetime(verified, at: now())
        if verified.clientID.hasPrefix("decentralized_identifier:") {
            guard let signingDID = verified.signingDID,
                  verified.clientID == "decentralized_identifier:\(signingDID)" else {
                throw OpenID4VCBackendError.invalidPresentationChallenge(
                    reason: "decentralized_identifier client_id was not bound to the signing DID"
                )
            }
        } else if let redirectClient = NativeOpenID4VPRequestObjectValidator.redirectURIClient(from: verified.clientID) {
            // OpenID4VP Section 5.9.3: with the redirect_uri Client Identifier
            // Prefix the request signature cannot be verified by the wallet, so
            // trust is anchored in the envelope: the response_uri must be the
            // exact URI embedded in the client_id, and a request_uri, when
            // used, must share its origin so the Request Object provably comes
            // from the party that will receive the presentation.
            guard verified.responseURI == redirectClient.absoluteString else {
                throw OpenID4VCBackendError.invalidPresentationChallenge(
                    reason: "redirect_uri client_id did not match the response_uri"
                )
            }
            if let fetchedRequestURI {
                guard try Self.origin(of: fetchedRequestURI) == Self.origin(of: redirectClient) else {
                    throw OpenID4VCBackendError.invalidPresentationChallenge(
                        reason: "request_uri origin did not match the redirect_uri client_id"
                    )
                }
            }
        } else {
            throw OpenID4VCBackendError.invalidPresentationChallenge(reason: "unsupported client_id prefix")
        }
        // Section 5.8: aud is the static-discovery symbolic value, or equal to
        // iss when the verifier performed dynamic discovery of this wallet.
        let validAudience = verified.audience == "https://self-issued.me/v2"
            || (verified.issuer != nil && verified.audience == verified.issuer)
        guard validAudience,
              verified.responseType == "vp_token",
              verified.responseMode == "direct_post",
              let responseURIValue = verified.responseURI,
               let responseURI = URL(string: responseURIValue),
               responseURI.scheme?.lowercased() == "https",
               responseURI.host != nil,
               responseURI.user == nil, responseURI.password == nil,
               responseURI.fragment == nil else {
            throw OpenID4VCBackendError.invalidPresentationChallenge(reason: "unsupported standalone response mode or response URI")
        }
        let query = try Self.presentationQuery(from: verified.dcqlQuery)
        guard let formats = verified.vpFormatsSupported,
              formats[query.format]?.contains("ES256") == true else {
            throw OpenID4VCBackendError.invalidPresentationChallenge(
                reason: "verifier metadata did not support ES256 for the requested presentation format"
            )
        }
        let digest = Data(SHA256.hash(data: Data(compactRequest.utf8))).base64URLEncodedString()
        try await presentationReplayProtection.consume(
            requestDigest: digest,
            nonce: verified.nonce,
            expiresAt: try Self.requiredStandaloneExpiry(verified),
            at: now()
        )
        let id = UUID()
        let challenge = OpenID4VPPresentationRequest(
            id: id,
            authorizationChallengeEndpoint: responseURI,
            authSession: nil,
            interactionType: "openid4vp_presentation",
            responseMode: verified.responseMode,
            responseURI: responseURI,
            nonce: verified.nonce,
            state: verified.state,
            dcqlQuery: verified.dcqlQuery,
            signedRequest: compactRequest,
            clientID: verified.clientID,
            transactionData: verified.transactionData
        )
        interactiveAuthorizationContexts[id] = InteractiveAuthorizationContext(
            generationID: UUID(),
            authorizationChallengeEndpoint: responseURI,
            activeInteraction: .presentation(challenge),
            expiresAt: now().addingTimeInterval(300)
        )
        do {
            return try await prepareStoredPIDPresentation(id: id)
        } catch {
            interactiveAuthorizationContexts[id] = nil
            transactionHolderIdentities[id] = nil
            throw error
        }
    }

    private func holderIdentity(for transactionID: UUID) async throws -> W3CHolderIdentity {
        if let identity = transactionHolderIdentities[transactionID] { return identity }
        let identity = try await holderIdentityProvider.loadOrCreateIdentity()
        transactionHolderIdentities[transactionID] = identity
        return identity
    }

    public func storedPIDPresentationToken(
        id: UUID,
        selectedClaimIDs: Set<String>
    ) async throws -> String {
        guard let context = interactiveAuthorizationContexts[id],
              context.expiresAt > now(),
              let prepared = preparedPIDPresentations.removeValue(forKey: id),
              prepared.authorizationGenerationID == context.generationID,
              prepared.requiredClaimIDs.isSubset(of: selectedClaimIDs),
              let keyUUID = UUID(uuidString: prepared.credential.holderKeyReference) else {
            throw OpenID4VCBackendError.invalidPresentationResponse
        }
        guard case let .presentation(challenge) = context.activeInteraction else {
            throw OpenID4VCBackendError.unknownTransaction
        }
        let keyID = KeyID(rawValue: keyUUID)
        let presentation: String
        let audience: String
        if challenge.responseMode == "ia_post" {
            audience = "ia:\(try Self.origin(of: challenge.authorizationChallengeEndpoint))"
        } else if let clientID = challenge.clientID, !clientID.isEmpty {
            audience = clientID
        } else {
            throw OpenID4VCBackendError.invalidPresentationChallenge(reason: "presentation client_id was missing")
        }
        switch prepared.kind {
        case let .sdJWT(issuerJWT, disclosures):
            let selectedDisclosures = disclosures.keys.sorted().compactMap {
                selectedClaimIDs.contains($0) ? disclosures[$0] : nil
            }
            let withoutKeyBinding = ([issuerJWT] + selectedDisclosures).joined(separator: "~") + "~"
            presentation = withoutKeyBinding + (try await signedPresentationJWT(
                keyID: keyID,
                type: "kb+jwt",
                payload: [
                    "aud": audience,
                    "nonce": challenge.nonce,
                    "iat": Int(now().timeIntervalSince1970),
                    "sd_hash": Data(SHA256.hash(data: Data(withoutKeyBinding.utf8))).base64URLEncodedString(),
                ]
            ))
        case let .jwtVC11(compactCredential):
            let publicKey = try await keyProvider.publicKey(id: keyID)
            let holder = try KeyDIDResolver().derive(publicKeyX963: publicKey.x963Representation)
            let issuedAt = Int(now().timeIntervalSince1970)
            presentation = try await signedPresentationJWT(
                keyID: keyID,
                type: "JWT",
                payload: [
                    "iss": holder,
                    "jti": "urn:uuid:\(UUID().uuidString.lowercased())",
                    "aud": audience,
                    "nonce": challenge.nonce,
                    "nbf": issuedAt,
                    "iat": issuedAt,
                    "exp": issuedAt + 300,
                    "vp": [
                        "@context": ["https://www.w3.org/2018/credentials/v1"],
                        "type": ["VerifiablePresentation"],
                        "holder": holder,
                        "verifiableCredential": [compactCredential],
                    ],
                ]
            )
        case let .jwtVC20(compactCredential):
            let publicKey = try await keyProvider.publicKey(id: keyID)
            let holder = try KeyDIDResolver().derive(publicKeyX963: publicKey.x963Representation)
            let issuedAt = Int(now().timeIntervalSince1970)
            presentation = try await signedPresentationJWT(
                keyID: keyID,
                type: "vp+jwt",
                contentType: "vp",
                payload: [
                    "@context": ["https://www.w3.org/ns/credentials/v2"],
                    "type": ["VerifiablePresentation"],
                    "holder": holder,
                    "verifiableCredential": [[
                        "@context": ["https://www.w3.org/ns/credentials/v2"],
                        "type": ["EnvelopedVerifiableCredential"],
                        "id": "data:application/vc+jwt,\(compactCredential)",
                    ]],
                    "iss": holder,
                    "aud": audience,
                    "nonce": challenge.nonce,
                    "iat": issuedAt,
                    "exp": issuedAt + 300,
                ]
            )
        }
        let object = try JSONSerialization.data(withJSONObject: [prepared.queryID: [presentation]])
        return String(decoding: object, as: UTF8.self)
    }

    public func completeStoredOpenID4VPPresentation(
        id: UUID,
        selectedClaimIDs: Set<String>,
        userAccepted: Bool
    ) async throws -> URL? {
        guard userAccepted else {
            guard let context = interactiveAuthorizationContexts[id],
                  context.expiresAt > now(),
                   case let .presentation(challenge) = context.activeInteraction,
                   challenge.responseMode == "direct_post",
                   let responseURI = challenge.responseURI else {
                throw OpenID4VCBackendError.unknownTransaction
            }
            let redirectURI = try await submitStandaloneDirectPost(
                responseURI: responseURI,
                fields: ["error": "access_denied", "state": challenge.state]
            )
            preparedPIDPresentations[id] = nil
            interactiveAuthorizationContexts[id] = nil
            transactionHolderIdentities[id] = nil
            return redirectURI
        }
        guard let context = interactiveAuthorizationContexts[id],
              context.expiresAt > now(),
              case let .presentation(challenge) = context.activeInteraction,
              challenge.responseMode == "direct_post",
              let responseURI = challenge.responseURI else {
            throw OpenID4VCBackendError.unknownTransaction
        }
        let token = try await storedPIDPresentationToken(id: id, selectedClaimIDs: selectedClaimIDs)
        let redirectURI = try await submitStandaloneDirectPost(
            responseURI: responseURI,
            fields: ["vp_token": token, "state": challenge.state]
        )
        interactiveAuthorizationContexts[id] = nil
        transactionHolderIdentities[id] = nil
        return redirectURI
    }

    private func submitStandaloneDirectPost(
        responseURI: URL,
        fields: [String: String?]
    ) async throws -> URL? {
        try Self.validateHTTPS(responseURI)
        let response = try await transport.send(
            url: responseURI,
            method: "POST",
            headers: ["Content-Type": "application/x-www-form-urlencoded"],
            body: form(fields)
        )
        guard response.body.count <= 1_048_576 else { throw OpenID4VCBackendError.invalidResponse }
        guard response.statusCode == 200 else {
            let detail = (try? JSONDecoder().decode(RemoteHTTPError.self, from: response.body))?.detail
                ?? String(data: response.body, encoding: .utf8)
            throw OpenID4VCBackendError.presentationSubmissionHTTPError(
                method: "POST", path: responseURI.path, status: response.statusCode, detail: detail
            )
        }
        guard Self.baseMediaType(of: response) == "application/json",
              let object = try? JSONSerialization.jsonObject(with: response.body),
              let dictionary = object as? [String: Any] else {
            throw OpenID4VCBackendError.invalidPresentationResponse
        }
        guard let value = dictionary["redirect_uri"] else { return nil }
        guard let string = value as? String, let url = URL(string: string),
              url.scheme?.lowercased() == "https", url.host != nil,
              url.user == nil, url.password == nil, url.fragment == nil else {
            throw OpenID4VCBackendError.invalidPresentationResponse
        }
        return url
    }

    public func submitPresentation(
        id: UUID,
        vpToken: String
    ) async throws -> InteractiveAuthorizationResult {
        guard let transaction = transactions[id],
              let context = interactiveAuthorizationContexts[id],
              context.expiresAt > now(),
              trustConsents.contains(id) else {
            throw OpenID4VCBackendError.unknownTransaction
        }
        guard case let .presentation(challenge) = context.activeInteraction else {
            throw OpenID4VCBackendError.unknownTransaction
        }
        var fields: [String: String?] = [:]
        if challenge.responseMode == "direct_post" {
            fields["state"] = challenge.state
            fields["vp_token"] = vpToken
        } else if challenge.responseMode == "iar-post" {
            fields["state"] = challenge.state
            fields["auth_session"] = challenge.authSession
            if case let .authorizationCode(issuerState) = transaction.grant {
                fields["issuer_state"] = issuerState
            }
            fields["response_type"] = "code"
            fields["client_id"] = challenge.clientID
            fields["code_challenge"] = authorizationCodeVerifiers[id].map {
                Data(SHA256.hash(data: Data($0.utf8))).base64URLEncodedString()
            }
            fields["code_challenge_method"] = "S256"
            fields["interaction_types_supported"] = "openid4vp_presentation"
            let authorizationDetails = try JSONSerialization.data(
                withJSONObject: transaction.configurationIDs.map { configurationID in
                    ["type": "openid_credential", "credential_configuration_id": configurationID]
                }
            )
            fields["authorization_details"] = String(decoding: authorizationDetails, as: UTF8.self)
            fields["openid4vp_presentation"] = vpToken
        } else if challenge.responseMode == "ia_post" {
            fields["auth_session"] = challenge.authSession
            guard let tokenObject = try JSONSerialization.jsonObject(with: Data(vpToken.utf8)) as? [String: Any] else {
                throw OpenID4VCBackendError.invalidPresentationResponse
            }
            var responseObject: [String: Any] = ["vp_token": tokenObject]
            if let state = challenge.state { responseObject["state"] = state }
            let wrapped = try JSONSerialization.data(withJSONObject: responseObject)
            fields["openid4vp_response"] = String(decoding: wrapped, as: UTF8.self)
        } else if challenge.responseMode == "ia_post.jwt" {
            throw OpenID4VCBackendError.invalidPresentationChallenge(
                reason: "encrypted ia_post.jwt response generation is not implemented"
            )
        } else {
            throw OpenID4VCBackendError.invalidPresentationChallenge(
                reason: "unsupported response_mode \(challenge.responseMode)"
            )
        }
        let responseEndpoint = challenge.responseMode == "ia_post" || challenge.responseMode == "ia_post.jwt"
            ? challenge.authorizationChallengeEndpoint
            : (challenge.responseURI ?? challenge.authorizationChallengeEndpoint)
        let rawResponse = try await transport.send(
            url: responseEndpoint,
            method: "POST",
            headers: ["Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"],
            body: form(fields)
        )
        guard rawResponse.statusCode == 200 || rawResponse.statusCode == 403 else {
            throw OpenID4VCBackendError.presentationSubmissionHTTPError(
                method: "POST", path: responseEndpoint.path, status: rawResponse.statusCode,
                detail: Self.safeHTTPErrorDetail(rawResponse.body)
            )
        }
        let result = try Self.decode(
            InteractiveAuthorizationResponse.self,
            from: rawResponse.body,
            stage: "presentation authorization response"
        )
        guard (rawResponse.statusCode == 403 && result.error == "insufficient_authorization")
                || (rawResponse.statusCode == 200 && result.error == nil) else {
            throw OpenID4VCBackendError.invalidPresentationResponse
        }
        if let responseState = result.state {
            let matchesAuthorizationState = authorizationStates[id] == responseState
            let matchesSignedPresentationState = challenge.state == responseState
            guard matchesAuthorizationState || matchesSignedPresentationState else {
                throw OpenID4VCBackendError.authorizationFailed
            }
        } else if challenge.responseMode != "ia_post" &&
                    challenge.responseMode != "direct_post" &&
                    challenge.responseMode != "iar-post" {
            throw OpenID4VCBackendError.authorizationFailed
        }
        if result.error == "insufficient_authorization" {
            let next = try webAuthorizationChallenge(
                id: id, response: result,
                authorizationChallengeEndpoint: context.authorizationChallengeEndpoint
            )
            interactiveAuthorizationContexts[id] = InteractiveAuthorizationContext(
                generationID: context.generationID,
                authorizationChallengeEndpoint: context.authorizationChallengeEndpoint,
                activeInteraction: .web(next),
                expiresAt: context.expiresAt
            )
            presentationChallenges[id] = nil
            return .interaction(.web(next))
        }
        guard result.error == nil,
              let value = result.authorizationCode ?? result.code, !value.isEmpty else {
            throw OpenID4VCBackendError.invalidPresentationResponse
        }
        authorizationCodes[id] = value
        presentationChallenges[id] = nil
        interactiveAuthorizationContexts[id] = nil
        return .authorizationCode(value)
    }

    public func acceptAuthorizationCode(id: UUID, code: String) throws {
        guard transactions[id] != nil, !code.isEmpty else {
            throw OpenID4VCBackendError.unknownTransaction
        }
        authorizationCodes[id] = code
        presentationChallenges[id] = nil
        interactiveAuthorizationContexts[id] = nil
        preparedPIDPresentations[id] = nil
    }

    public func issue(
        id: UUID,
        allowUntrusted: Bool,
        transactionCode: String?
    ) async throws -> [IssuedW3CCredential] {
        switch try await issueOutcome(id: id, allowUntrusted: allowUntrusted, transactionCode: transactionCode) {
        case let .issued(credentials): return credentials
        case let .deferred(deferred): throw OpenID4VCBackendError.deferredCredentialPending(deferred)
        }
    }

    public func issueOutcome(
        id: UUID,
        allowUntrusted: Bool,
        transactionCode: String?
    ) async throws -> W3CCredentialIssuanceOutcome {
        guard let transaction = transactions[id] else {
            throw OpenID4VCBackendError.unknownTransaction
        }
        if let staged = stagedCredentials[id] {
            guard allowUntrusted else {
                throw OpenID4VCBackendError.untrustedConsentRequired
            }
            return .issued(try await commitStagedCredentials(staged, transactionID: id))
        }
        try authorizeTrust(transaction: transaction, id: id, allowUntrusted: allowUntrusted)
        let tokenValues: [String: String?]
        switch transaction.grant {
        case let .preAuthorized(code, txCode):
            try Self.validate(transactionCode, requirement: txCode)
            tokenValues = [
                "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
                "pre-authorized_code": code,
                "tx_code": transactionCode,
            ]
        case .authorizationCode:
            guard let code = authorizationCodes[id] else {
                throw OpenID4VCBackendError.presentationRequired
            }
            tokenValues = [
                "grant_type": "authorization_code",
                "code": code,
                "code_verifier": authorizationCodeVerifiers[id],
                "client_id": authorizationClientID,
                "redirect_uri": authorizationRedirectURI.absoluteString,
            ]
        }
        let issuerMetadata = transaction.issuerMetadata
        guard let authorizationServer = URL(
            string: issuerMetadata.authorizationServers?.first ?? transaction.issuer.absoluteString
        ) else { throw OpenID4VCBackendError.unsafeEndpoint }
        let authMetadataURL = try Self.wellKnownURL(
            name: "oauth-authorization-server",
            issuer: authorizationServer
        )
        let authMetadata = try await discoverMetadata(
            AuthorizationMetadata.self,
            name: "oauth-authorization-server",
            issuer: authorizationServer,
            standardURL: authMetadataURL,
            stage: "authorization server metadata"
        )
        let transportContract = OID4VCITransportContract.resolve(
            selectedProfile: transportProfileRegistry.profile(for: transaction.issuer),
            authorizationMetadata: OID4VCIAuthorizationMetadata(
                dpopSigningAlgorithms: authMetadata.dpopSigningAlgorithms,
                clientAttestationAlgorithms: authMetadata.clientAttestationAlgorithms,
                tokenEndpointAuthenticationMethods: authMetadata.tokenEndpointAuthenticationMethods
            )
        )
        guard transportContract.tokenEndpointAuthentication != .unsupported else {
            throw OpenID4VCBackendError.clientSecurityUnavailable
        }
        let securityState: OID4VCIClientSecurityState?
        if transportContract.requiresDPoP || transportContract.requiresClientAttestation ||
            transportContract.requiresCredentialResponseEncryption {
            guard let clientSecurity else { throw OpenID4VCBackendError.clientSecurityUnavailable }
            securityState = try await clientSecurity.state(for: transportContract.profile)
        } else {
            securityState = nil
        }
        let tokenBody = form(tokenValues)
        guard let tokenEndpoint = URL(string: authMetadata.tokenEndpoint) else {
            throw OpenID4VCBackendError.unsafeEndpoint
        }
        var tokenHeaders = ["Content-Type": "application/x-www-form-urlencoded"]
        if let securityState, let clientSecurity {
            if transportContract.requiresDPoP {
                tokenHeaders["DPoP"] = try await clientSecurity.dpopHeader(
                    state: securityState,
                    method: "POST",
                    targetURI: tokenEndpoint,
                    accessToken: nil
                )
            }
            if transportContract.requiresClientAttestation {
                let attestationHeaders = try await clientSecurity.clientAttestationHeaders(
                    state: securityState,
                    audience: tokenEndpoint
                )
                guard !attestationHeaders.isEmpty else {
                    throw OpenID4VCBackendError.clientSecurityUnavailable
                }
                tokenHeaders.merge(attestationHeaders, uniquingKeysWith: { _, new in new })
            }
        }
        let tokenResponse = try await successfulRequest(
            tokenEndpoint,
            method: "POST",
            headers: tokenHeaders,
            body: tokenBody,
            allowedOrigins: [try Self.origin(of: authorizationServer)]
        )
        let token = try Self.decode(TokenResponse.self, from: tokenResponse, stage: "token response")
        let expectedTokenType = transportContract.requiresDPoP ? "DPoP" : "Bearer"
        guard token.tokenType?.caseInsensitiveCompare(expectedTokenType) == .orderedSame else {
            throw OpenID4VCBackendError.invalidTokenType(expected: expectedTokenType, actual: token.tokenType)
        }
        let holderIdentity = try await holderIdentity(for: id)
        let holderDID = holderIdentity.did
        let method = holderIdentity.assertionMethod
        var staged: [StagedCredential] = []
        var pendingNotifications: [StagedNotification] = []
        var deferredTransactions: [String: String] = [:]
        var deferredNextPollAt = now()
        var deferredPollInterval: TimeInterval = 0
        let configurationIDs: [String]
        var draftAuthorizationDetails: [String: TokenResponse.AuthorizationDetail] = [:]
        var draftCredentialIdentifiers: [String: [String]] = [:]
        if transportContract.profile != .final {
            if let authorizationDetails = token.authorizationDetails {
                guard !authorizationDetails.isEmpty else {
                    throw OpenID4VCBackendError.missingCredentialAuthorization
                }
                var matchedIndexes: Set<Int> = []
                for offeredID in transaction.configurationIDs {
                    var ranked = authorizationDetails.indices.compactMap { index -> (Int, Int, String)? in
                        guard let match = Self.draftAuthorizationMatch(
                            offeredID: offeredID,
                            detail: authorizationDetails[index],
                            configurations: transaction.issuerMetadata.credentialConfigurations
                        ) else { return nil }
                        return (index, match.score, match.credentialIdentifier)
                    }
                    if ranked.isEmpty,
                       transaction.configurationIDs.count == 1,
                       authorizationDetails.count == 1 {
                        ranked = authorizationDetails.indices.compactMap { index in
                            guard let identifier = authorizationDetails[index].credentialIdentifiers?
                                .first(where: { !$0.isEmpty }) else { return nil }
                            return (index, 0, identifier)
                        }
                    }
                    let highestScore = ranked.map(\.1).max()
                    let candidates = ranked.filter { $0.1 == highestScore }
                    let candidate = candidates.count == 1 ? candidates.first : nil
                    guard highestScore != nil, let candidate,
                          matchedIndexes.insert(candidate.0).inserted else {
                        throw OpenID4VCBackendError.credentialAuthorizationMismatch(
                            offered: offeredID,
                            authorized: Self.authorizationIdentifiers(authorizationDetails)
                        )
                    }
                    let index = candidate.0
                    draftAuthorizationDetails[offeredID] = authorizationDetails[index]
                    var identifiers = [candidate.2]
                    identifiers.append(contentsOf: authorizationDetails[index].credentialIdentifiers ?? [])
                    identifiers.append(contentsOf: authorizationDetails.flatMap { $0.credentialIdentifiers ?? [] })
                    draftCredentialIdentifiers[offeredID] = Self.uniqueNonEmpty(identifiers)
                }
            }
            configurationIDs = transaction.configurationIDs
        } else {
            let advertisedConfigurationIDs = Set(transaction.issuerMetadata.credentialConfigurations.keys)
            let authorizedConfigurationIDs = token.authorizationDetails?.compactMap(\.credentialConfigurationID)
                .filter { !$0.isEmpty && advertisedConfigurationIDs.contains($0) } ?? []
            configurationIDs = authorizedConfigurationIDs.isEmpty
                ? transaction.configurationIDs
                : authorizedConfigurationIDs
        }
        for configurationID in configurationIDs {
            let display = await offlineDisplayMetadata(
                transaction.issuerMetadata.credentialConfigurations[configurationID]?.display
            )
            let authorizationDetail = transportContract.profile == .final
                ? token.authorizationDetails?.first { $0.credentialConfigurationID == configurationID }
                : draftAuthorizationDetails[configurationID]
            let credentialIdentifier = draftCredentialIdentifiers[configurationID]?.first
                ?? authorizationDetail?.credentialIdentifiers?.first(where: { !$0.isEmpty })
                ?? configurationID
            let responseEncryption: CredentialResponseEncryptionRequest?
            if transportContract.requiresCredentialResponseEncryption,
               let securityState, let clientSecurity {
                let parameters = try await clientSecurity.responseEncryption(state: securityState)
                guard let jwk = try JSONSerialization.jsonObject(
                    with: Data(parameters.publicJWK.utf8)
                ) as? [String: String] else {
                    throw OpenID4VCBackendError.clientSecurityUnavailable
                }
                responseEncryption = CredentialResponseEncryptionRequest(
                    jwk: jwk,
                    alg: parameters.algorithm,
                    enc: parameters.encryption
                )
            } else {
                responseEncryption = nil
            }
            guard let credentialEndpoint = URL(string: issuerMetadata.credentialEndpoint) else {
                throw OpenID4VCBackendError.unsafeEndpoint
            }
            let identifierCandidates: [String?]
            if transportContract.credentialIdentifierField == .credentialIdentifier {
                var values = draftCredentialIdentifiers[configurationID] ?? [credentialIdentifier]
                values.append(configurationID)
                values = Self.uniqueNonEmpty(values)
                identifierCandidates = values.map(Optional.some)
            } else {
                identifierCandidates = [nil]
            }
            var successfulResponse: OpenID4VCHTTPResponse?
            for (index, candidate) in identifierCandidates.enumerated() {
                // A proof is a single-use assertion. In particular, identifier fallback
                // must not replay the proof accepted or rejected for a prior identifier.
                let proofNonce: String?
                if let nonceEndpointValue = issuerMetadata.nonceEndpoint {
                    guard let nonceEndpoint = URL(string: nonceEndpointValue) else {
                        throw OpenID4VCBackendError.unsafeEndpoint
                    }
                    let nonceData = try await successfulRequest(
                        nonceEndpoint,
                        method: "POST",
                        headers: ["Accept": "application/json"],
                        body: nil,
                        allowedOrigins: [try Self.origin(of: transaction.issuer)]
                    )
                    let response = try Self.decode(
                        CredentialNonceResponse.self,
                        from: nonceData,
                        stage: "credential nonce response"
                    )
                    guard !response.nonce.isEmpty else {
                        throw OpenID4VCBackendError.invalidResponse
                    }
                    proofNonce = response.nonce
                } else {
                    proofNonce = token.nonce
                }
                let proof = try await proofJWT(
                    keyID: holderIdentity.keyID,
                    kid: method,
                    issuer: holderDID,
                    audience: transaction.issuer.absoluteString,
                    nonce: proofNonce
                )
                let request = CredentialRequest(
                    credentialConfigurationId: transportContract.credentialIdentifierField == .credentialConfigurationID ? configurationID : nil,
                    credentialIdentifier: candidate,
                    format: nil,
                    proof: transportContract.proofShape == .draftProof
                        ? ProofValue(proofType: "jwt", jwt: proof)
                        : nil,
                    proofs: transportContract.proofShape == .finalProofsJWT
                        ? ["jwt": [proof]]
                        : nil,
                    credentialResponseEncryption: responseEncryption
                )
                let data = try JSONEncoder().encode(request)
                var credentialHeaders = [
                    "Content-Type": "application/json",
                    "Authorization": "Bearer \(token.accessToken)",
                ]
                if transportContract.requiresDPoP,
                   let securityState, let clientSecurity {
                    credentialHeaders["DPoP"] = try await clientSecurity.dpopHeader(
                        state: securityState,
                        method: "POST",
                        targetURI: credentialEndpoint,
                        accessToken: token.accessToken
                    )
                    credentialHeaders["Authorization"] = "DPoP \(token.accessToken)"
                }
                do {
                    successfulResponse = try await successfulHTTPResponse(
                        credentialEndpoint,
                        method: "POST",
                        headers: credentialHeaders,
                        body: data,
                        allowedOrigins: [try Self.origin(of: transaction.issuer)]
                    )
                    break
                } catch let error as OpenID4VCBackendError {
                    let canRetry = index + 1 < identifierCandidates.count &&
                        Self.isRetryableCredentialIdentifierError(error)
                    guard canRetry else { throw error }
                }
            }
            guard let httpResponse = successfulResponse else { throw OpenID4VCBackendError.invalidResponse }
            var response = httpResponse.body
            if transportContract.requiresCredentialResponseEncryption {
                guard Self.looksLikeCompactJWE(response),
                      let securityState, let clientSecurity else {
                    throw OpenID4VCBackendError.invalidResponse
                }
                response = try await clientSecurity.decryptCredentialResponse(
                    state: securityState,
                    compactJWE: response
                )
            }
            let credentials = try Self.decode(
                CredentialResponse.self,
                from: response,
                stage: "credential response"
            )
            if let deferredTransactionID = credentials.transactionID {
                guard transportContract.supportsDeferredIssuance,
                      httpResponse.statusCode == 202,
                      credentials.credentials.isEmpty,
                      (credentials.interval ?? 0) > 0,
                      let endpointValue = issuerMetadata.deferredCredentialEndpoint,
                      let endpoint = URL(string: endpointValue),
                      try Self.origin(of: endpoint) == Self.origin(of: transaction.issuer),
                      !deferredTransactionID.isEmpty else {
                    throw OpenID4VCBackendError.invalidResponse
                }
                deferredTransactions[configurationID] = deferredTransactionID
                deferredPollInterval = max(
                    deferredPollInterval, TimeInterval(credentials.interval ?? 0)
                )
                deferredNextPollAt = max(
                    deferredNextPollAt,
                    now().addingTimeInterval(deferredPollInterval)
                )
                continue
            }
            guard httpResponse.statusCode == 200, !credentials.credentials.isEmpty,
                  credentials.interval == nil else {
                throw OpenID4VCBackendError.invalidResponse
            }
            staged.append(contentsOf: try await stageCredentials(
                credentials, configurationID: configurationID, transaction: transaction,
                holderIdentity: holderIdentity, display: display
            ))
            if let notificationID = credentials.notificationID,
               let endpoint = issuerMetadata.notificationEndpoint.flatMap(URL.init(string:)) {
                pendingNotifications.append(StagedNotification(
                    endpoint: endpoint,
                    notificationID: notificationID,
                    accessToken: token.accessToken
                ))
            }
        }
        let stagedIssuance = StagedIssuance(
            credentials: staged,
            notifications: pendingNotifications
        )
        if !deferredTransactions.isEmpty {
            guard let endpointValue = issuerMetadata.deferredCredentialEndpoint,
                  let endpoint = URL(string: endpointValue) else {
                throw OpenID4VCBackendError.invalidResponse
            }
            var expectations: [String: DeferredCredentialExpectation] = [:]
            for configurationID in configurationIDs {
                guard let configuration = transaction.issuerMetadata.credentialConfigurations[configurationID] else {
                    throw OpenID4VCBackendError.invalidResponse
                }
                expectations[configurationID] = DeferredCredentialExpectation(
                    format: configuration.format,
                    profileIDs: compatibleProfileIDs(format: configuration.format),
                    displayName: configuration.display.name,
                    display: await offlineDisplayMetadata(configuration.display)
                )
            }
            guard expectations.values.allSatisfy({ !$0.profileIDs.isEmpty }) else {
                throw OpenID4VCBackendError.invalidResponse
            }
            let continuation = DeferredW3CCredential(
                transactionID: id,
                issuer: transaction.issuer,
                endpoint: endpoint,
                remoteTransactionIDs: deferredTransactions,
                accessToken: token.accessToken,
                accessTokenExpiresAt: token.expiresIn.map { now().addingTimeInterval(TimeInterval($0)) },
                usesDPoP: transportContract.requiresDPoP,
                securityState: securityState,
                holderIdentity: holderIdentity,
                expectations: expectations,
                stagedCredentials: staged.map { DeferredStagedCredential(stored: $0.stored, issued: $0.result) },
                notifications: pendingNotifications.map {
                    DeferredCredentialNotification(endpoint: $0.endpoint, notificationID: $0.notificationID)
                },
                notificationEndpoint: issuerMetadata.notificationEndpoint.flatMap(URL.init(string:)),
                serviceTrustAccepted: true,
                transportProfile: transportContract.profile,
                pollInterval: deferredPollInterval,
                nextPollAt: deferredNextPollAt
            )
            // Everything needed to continue now lives in the exported state.
            // Drop token-flow and holder caches so restart and in-process paths
            // have identical ownership and no stale authorization can be reused.
            cancel(id: id)
            return .deferred(continuation)
        }
        let signerWarning = await credentialSignerWarning(for: staged.map(\.result.issuerIdentifier))
        if let signerWarning {
            // Raw credentials are already cryptographically validated. Retain
            // them only in this actor's transaction memory so Continue can
            // commit without replaying token or credential requests.
            stagedCredentials[id] = stagedIssuance
            throw OpenID4VCBackendError.credentialSignerTrustWarning(signerWarning)
        }
        return .issued(try await commitStagedCredentials(stagedIssuance, transactionID: id))
    }

    public func retrieveDeferredCredential(
        _ deferred: DeferredW3CCredential
    ) async throws -> W3CCredentialIssuanceOutcome {
        try validateDeferredState(deferred)
        if deferred.remoteTransactionIDs.isEmpty {
            try await validateRestoredStagedCredentials(deferred.stagedCredentials, state: deferred)
            if let warning = await credentialSignerWarning(
                for: deferred.stagedCredentials.map(\.issued.issuerIdentifier)
            ) {
                throw OpenID4VCBackendError.deferredCredentialSignerTrustWarning(warning, deferred)
            }
            return try await commitDeferredCredential(deferred, allowUntrusted: true)
        }
        guard now() >= deferred.nextPollAt else {
            throw OpenID4VCBackendError.deferredCredentialNotReady(nextPollAt: deferred.nextPollAt)
        }
        if let expiry = deferred.accessTokenExpiresAt, now() >= expiry {
            throw OpenID4VCBackendError.authorizationFailed
        }
        var pending = deferred.remoteTransactionIDs
        var staged = deferred.stagedCredentials
        var notifications = deferred.notifications
        try await validateRestoredStagedCredentials(staged, state: deferred)
        guard let configurationID = pending.keys.sorted().first,
              let remoteID = pending[configurationID] else {
            throw OpenID4VCBackendError.invalidResponse
        }
        let body = try JSONEncoder().encode(DeferredCredentialRequest(transactionID: remoteID))
        var headers = [
                "Content-Type": "application/json",
                "Authorization": "Bearer \(deferred.accessToken)",
        ]
        if deferred.usesDPoP, let securityState = deferred.securityState, let clientSecurity {
            headers["DPoP"] = try await clientSecurity.dpopHeader(
                state: securityState, method: "POST", targetURI: deferred.endpoint,
                accessToken: deferred.accessToken
            )
            headers["Authorization"] = "DPoP \(deferred.accessToken)"
        }
        let httpResponse = try await successfulHTTPResponse(
            deferred.endpoint, method: "POST", headers: headers, body: body,
            allowedOrigins: [try Self.origin(of: deferred.issuer)]
        )
        let response = try Self.decode(
            CredentialResponse.self, from: httpResponse.body, stage: "deferred credential response"
        )
        if let replacementTransactionID = response.transactionID {
            guard httpResponse.statusCode == 202,
                  response.credentials.isEmpty,
                  replacementTransactionID == remoteID,
                  (response.interval ?? 0) > 0 else {
                throw OpenID4VCBackendError.invalidResponse
            }
            let interval = TimeInterval(response.interval!)
            return .deferred(deferred.updated(
                remoteTransactionIDs: pending,
                stagedCredentials: staged,
                notifications: notifications,
                pollInterval: interval,
                nextPollAt: now().addingTimeInterval(interval)
            ))
        }
        guard httpResponse.statusCode == 200, !response.credentials.isEmpty,
              response.interval == nil,
              let expectation = deferred.expectations[configurationID] else {
            throw OpenID4VCBackendError.invalidResponse
        }
        let additions = try await stageDeferredCredentials(
            response, configurationID: configurationID, issuer: deferred.issuer,
            holderIdentity: deferred.holderIdentity, expectation: expectation
        )
        staged.append(contentsOf: additions)
        if let notificationID = response.notificationID,
           let endpoint = deferred.notificationEndpoint {
            notifications.append(DeferredCredentialNotification(
                endpoint: endpoint, notificationID: notificationID
            ))
        }
        pending[configurationID] = nil
        return .deferred(deferred.updated(
            remoteTransactionIDs: pending, stagedCredentials: staged,
            notifications: notifications, pollInterval: deferred.pollInterval,
            nextPollAt: pending.isEmpty ? now() : deferred.nextPollAt
        ))
    }

    public func commitDeferredCredential(
        _ state: DeferredW3CCredential,
        allowUntrusted: Bool
    ) async throws -> W3CCredentialIssuanceOutcome {
        guard allowUntrusted, state.remoteTransactionIDs.isEmpty,
              state.serviceTrustAccepted,
              Set(state.expectations.keys) == Set(state.stagedCredentials.map(\.issued.configurationID)),
              state.expectations.values.allSatisfy({ expectation in
                  !expectation.profileIDs.isEmpty
                      && expectation.profileIDs.allSatisfy { expected in profiles.contains { $0.id == expected } }
              }) else {
            throw OpenID4VCBackendError.untrustedConsentRequired
        }
        try Self.validateHTTPS(state.issuer)
        guard try Self.origin(of: state.endpoint) == Self.origin(of: state.issuer) else {
            throw OpenID4VCBackendError.unsafeEndpoint
        }
        try await validateRestoredStagedCredentials(state.stagedCredentials, state: state)
        for item in state.stagedCredentials { try await credentialStore.save(item.stored) }
        for item in state.notifications { await sendDeferredNotification(item, state: state) }
        return .issued(state.stagedCredentials.map(\.issued))
    }

    private func validateRestoredStagedCredentials(
        _ staged: [DeferredStagedCredential],
        state: DeferredW3CCredential
    ) async throws {
        for item in staged {
            guard let expectation = state.expectations[item.issued.configurationID],
                  expectation.profileIDs.contains(item.issued.profileID),
                  item.issued.displayName == expectation.displayName,
                  item.issued.display == expectation.display,
                  item.stored.id == item.issued.id,
                  item.stored.profileID == item.issued.profileID,
                  item.stored.representation == item.issued.representation,
                  item.stored.holderKeyReference == state.holderIdentity.keyID.rawValue.uuidString,
                  let profile = profiles.first(where: { $0.id == item.stored.profileID }) else {
                throw OpenID4VCBackendError.invalidResponse
            }
            let signedIssuer = try await credentialValidator.validate(
                rawCredential: item.stored.rawCredential,
                profile: profile,
                expectedIssuer: state.issuer.absoluteString,
                expectedHolderDID: state.holderIdentity.did,
                at: now()
            )
            guard signedIssuer == item.issued.issuerIdentifier else {
                throw OpenID4VCBackendError.invalidResponse
            }
        }
    }

    private func validateDeferredState(_ state: DeferredW3CCredential) throws {
        try Self.validateHTTPS(state.issuer)
        try Self.validateHTTPS(state.endpoint)
        let representedConfigurationIDs = Set(state.remoteTransactionIDs.keys)
            .union(state.stagedCredentials.map(\.issued.configurationID))
        guard state.transportProfile == .final,
              state.serviceTrustAccepted,
              !state.accessToken.isEmpty,
              state.pollInterval > 0,
              try Self.origin(of: state.endpoint) == Self.origin(of: state.issuer),
              !representedConfigurationIDs.isEmpty,
              state.remoteTransactionIDs.allSatisfy({ !$0.key.isEmpty && !$0.value.isEmpty }),
              Set(state.remoteTransactionIDs.values).count == state.remoteTransactionIDs.count,
              Set(state.expectations.keys) == representedConfigurationIDs,
              state.expectations.values.allSatisfy({ expectation in
                  !expectation.profileIDs.isEmpty
                      && expectation.profileIDs.allSatisfy { expected in profiles.contains { $0.id == expected } }
              }),
              !state.usesDPoP || state.securityState != nil else {
            throw OpenID4VCBackendError.invalidResponse
        }
        if let endpoint = state.notificationEndpoint {
            guard try Self.origin(of: endpoint) == Self.origin(of: state.issuer) else {
                throw OpenID4VCBackendError.unsafeEndpoint
            }
        }
        guard state.notifications.allSatisfy({
            (try? Self.origin(of: $0.endpoint)) == (try? Self.origin(of: state.issuer))
                && !$0.notificationID.isEmpty
        }) else { throw OpenID4VCBackendError.unsafeEndpoint }
    }

    private func compatibleProfileIDs(format: String) -> [String] {
        profiles.filter { profile in
            switch format {
            case "dc+sd-jwt": profile.representation == .dcSdJwt
            case "vcdm2_sd_jwt": profile.representation == .vcdm2SdJwt
            case "jwt_vc_json", "jwt_vc_json-ld": profile.dataModel == .v1_1
            case "application/vc+jwt": profile.representation == .vcdm2Jwt
            default: false
            }
        }.map(\.id)
    }

    private func stageDeferredCredentials(
        _ response: CredentialResponse,
        configurationID: String,
        issuer: URL,
        holderIdentity: W3CHolderIdentity,
        expectation: DeferredCredentialExpectation
    ) async throws -> [DeferredStagedCredential] {
        let staged = try await stageCredentialPayload(
            response, configurationID: configurationID, issuer: issuer,
            holderIdentity: holderIdentity, expectedFormat: expectation.format,
            displayName: expectation.displayName, display: expectation.display
        )
        guard staged.allSatisfy({ expectation.profileIDs.contains($0.result.profileID) }) else {
            throw OpenID4VCBackendError.invalidResponse
        }
        return staged.map { DeferredStagedCredential(stored: $0.stored, issued: $0.result) }
    }

    private func sendDeferredNotification(
        _ notification: DeferredCredentialNotification,
        state: DeferredW3CCredential
    ) async {
        let body = try? JSONSerialization.data(withJSONObject: [
            "event": "credential_accepted",
            "notification_id": notification.notificationID,
        ])
        var headers = [
            "Content-Type": "application/json",
            "Authorization": "Bearer \(state.accessToken)",
        ]
        if state.usesDPoP, let securityState = state.securityState, let clientSecurity {
            headers["DPoP"] = try? await clientSecurity.dpopHeader(
                state: securityState, method: "POST", targetURI: notification.endpoint,
                accessToken: state.accessToken
            )
            headers["Authorization"] = "DPoP \(state.accessToken)"
        }
        _ = try? await successfulRequest(
            notification.endpoint, method: "POST", headers: headers, body: body,
            allowedOrigins: [try Self.origin(of: state.issuer)]
        )
    }

    private func stageCredentials(
        _ response: CredentialResponse,
        configurationID: String,
        transaction: Transaction,
        holderIdentity: W3CHolderIdentity,
        display: CredentialDisplayMetadata?
    ) async throws -> [StagedCredential] {
        let configuration = transaction.issuerMetadata.credentialConfigurations[configurationID]
        return try await stageCredentialPayload(
            response, configurationID: configurationID, issuer: transaction.issuer,
            holderIdentity: holderIdentity, expectedFormat: configuration?.format,
            displayName: configuration?.display.name ?? "Credential", display: display
        )
    }

    private func stageCredentialPayload(
        _ response: CredentialResponse,
        configurationID: String,
        issuer: URL,
        holderIdentity: W3CHolderIdentity,
        expectedFormat: String?,
        displayName: String,
        display: CredentialDisplayMetadata?
    ) async throws -> [StagedCredential] {
        var staged: [StagedCredential] = []
        for item in response.credentials {
            let raw = Data(item.credential.utf8)
            let selectedProfile = try selectProfile(
                format: response.format ?? item.format ?? expectedFormat,
                rawCredential: raw
            )
            let signedIssuer = try await credentialValidator.validate(
                rawCredential: raw,
                profile: selectedProfile,
                expectedIssuer: issuer.absoluteString,
                expectedHolderDID: holderIdentity.did,
                at: now()
            )
            let stored = StoredEbsiCredential(
                profileID: selectedProfile.id,
                representation: selectedProfile.representation,
                rawCredential: raw,
                holderKeyReference: holderIdentity.keyID.rawValue.uuidString,
                receivedAt: now()
            )
            let result = IssuedW3CCredential(
                id: stored.id,
                configurationID: configurationID,
                displayName: displayName,
                issuerIdentifier: signedIssuer,
                profileID: stored.profileID,
                representation: stored.representation,
                hasStatusReference: Self.hasCredentialStatus(raw: raw, profile: selectedProfile),
                displayClaims: Self.displayClaims(
                    raw: String(decoding: raw, as: UTF8.self), profile: selectedProfile
                ),
                display: display
            )
            staged.append(StagedCredential(stored: stored, result: result))
        }
        return staged
    }

    private func credentialSignerWarning(for issuers: [String]) async -> EbsiTrustWarning? {
        for issuer in Set(issuers).sorted() {
            let verdict: TrustVerdict
            if issuer.hasPrefix("did:ebsi:") {
                verdict = await credentialSignerTrustEvaluator.evaluate(issuer: issuer, at: now())
            } else if issuer.hasPrefix("did:key:") {
                verdict = .untrusted(reasons: [.issuerNotAccredited], evidence: [])
            } else {
                // HTTPS JWT issuers are bound to their metadata and keys by the
                // credential validator. TIR is a DID accreditation registry.
                continue
            }
            guard case .trusted = verdict else {
                let reasons: [TrustReason]
                let evidence: [TrustEvidence]
                switch verdict {
                case .trusted: continue
                case let .untrusted(value, items), let .invalid(value, items), let .indeterminate(value, items):
                    reasons = value.isEmpty ? [.issuerNotAccredited] : value
                    evidence = items
                }
                return EbsiTrustWarning(
                    counterpartyIdentifier: issuer,
                    role: .issuer,
                    reasons: reasons,
                    evidenceSources: evidence.map(\.sourceIdentifier).sorted(),
                    nextAction: "Continue to store the validated credential, or Cancel. No credential has been stored and no credential request will be repeated."
                )
            }
        }
        return nil
    }

    private func commitStagedCredentials(
        _ staged: StagedIssuance, transactionID id: UUID
    ) async throws -> [IssuedW3CCredential] {
        guard let transaction = transactions[id] else { throw OpenID4VCBackendError.unknownTransaction }
        for item in staged.credentials { try await credentialStore.save(item.stored) }
        for item in staged.notifications {
            let notification = try JSONSerialization.data(withJSONObject: [
                "event": "credential_accepted",
                "notification_id": item.notificationID,
            ])
            // Notification delivery is secondary to an already completed local
            // commit. A transient notification failure must not report issuance
            // as failed after the credential has been stored.
            _ = try? await successfulRequest(
                item.endpoint,
                method: "POST",
                headers: [
                    "Content-Type": "application/json",
                    "Authorization": "Bearer \(item.accessToken)",
                ],
                body: notification,
                allowedOrigins: [try Self.origin(of: transaction.issuer)]
            )
        }
        stagedCredentials[id] = nil
        transactions[id] = nil
        authorizationCodes[id] = nil
        authorizationCodeVerifiers[id] = nil
        authorizationStates[id] = nil
        interactiveAuthorizationContexts[id] = nil
        presentationChallengeTasks.removeValue(forKey: id)?.cancel()
        transactionHolderIdentities[id] = nil
        trustConsents.remove(id)
        return staged.credentials.map(\.result)
    }

    private func selectProfile(
        format: String?,
        rawCredential: Data
    ) throws -> EbsiCredentialProfile {
        if format == "dc+sd-jwt" {
            guard let profile = profiles.first(where: { $0.representation == .dcSdJwt }) else {
                throw EbsiCredentialError.unsupportedRepresentation
            }
            return profile
        }
        if format == "vcdm2_sd_jwt" {
            guard let profile = profiles.first(where: { $0.representation == .vcdm2SdJwt }) else {
                throw EbsiCredentialError.unsupportedRepresentation
            }
            return profile
        }
        let context = Self.jwtContext(rawCredential)
        if context == "https://www.w3.org/ns/credentials/v2",
           let profile = profiles.first(where: { $0.representation == .vcdm2Jwt }) {
            return profile
        }
        if format == "jwt_vc_json" || format == "jwt_vc_json-ld" {
            guard let profile = profiles.first(where: { $0.dataModel == .v1_1 }) else {
                throw EbsiCredentialError.unsupportedRepresentation
            }
            return profile
        }
        if context == "https://www.w3.org/2018/credentials/v1",
           let profile = profiles.first(where: { $0.dataModel == .v1_1 }) {
            return profile
        }
        guard let profile = profiles.first(where: { $0.representation == .vcdm2Jwt }) else {
            throw EbsiCredentialError.unsupportedRepresentation
        }
        return profile
    }

    private static func jwtContext(_ raw: Data) -> String? {
        let parts = String(decoding: raw, as: UTF8.self).split(separator: ".")
        guard parts.count >= 2 else { return nil }
        var value = String(parts[1]).replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        value += String(repeating: "=", count: (4 - value.count % 4) % 4)
        guard let data = Data(base64Encoded: value),
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return nil
        }
        if let contexts = object["@context"] as? [String] { return contexts.first }
        return object["@context"] as? String
    }

    private static func supportedRepresentation(_ format: String) -> Bool {
        ["jwt_vc_json", "jwt_vc_json-ld", "dc+sd-jwt", "vcdm2_sd_jwt", "application/vc+jwt"]
            .contains(format)
    }

    private static func base64URL(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    private static func safeHTTPErrorDetail(_ data: Data) -> String? {
        guard data.count <= 1_048_576,
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return nil
        }
        if let detail = object["detail"] as? String {
            if let nestedData = detail.data(using: .utf8),
               let failures = try? JSONSerialization.jsonObject(with: nestedData) as? [[String: Any]] {
                let values = failures.compactMap { failure -> String? in
                    let path = (failure["loc"] as? [Any])?.compactMap { $0 as? String }.joined(separator: ".")
                    let message = failure["msg"] as? String
                    guard let message else { return nil }
                    return path.map { "\($0): \(message)" } ?? message
                }
                return values.isEmpty ? nil : values.joined(separator: ", ")
            }
            return detail.count <= 200 && !detail.contains("eyJ") ? detail : nil
        }
        if let description = object["error_description"] as? String, description.count <= 200 {
            return description
        }
        if let error = object["error"] as? String, error.count <= 100 { return error }
        return nil
    }

    private static func decode<Value: Decodable>(
        _ type: Value.Type,
        from data: Data,
        stage: String
    ) throws -> Value {
        do {
            return try JSONDecoder().decode(type, from: data)
        } catch let error as DecodingError {
            let context: DecodingError.Context
            let reason: String
            switch error {
            case let .dataCorrupted(value):
                context = value
                reason = "invalid value"
            case let .keyNotFound(key, value):
                context = value
                reason = "missing key \(key.stringValue)"
            case let .typeMismatch(expected, value):
                context = value
                reason = "expected \(String(describing: expected))"
            case let .valueNotFound(expected, value):
                context = value
                reason = "missing \(String(describing: expected))"
            @unknown default:
                throw OpenID4VCBackendError.decodingFailed(
                    stage: stage,
                    path: "$",
                    reason: "unknown decoding failure"
                )
            }
            let path = context.codingPath.reduce("$") { partial, key in
                if let index = key.intValue { return "\(partial)[\(index)]" }
                return "\(partial).\(key.stringValue)"
            }
            throw OpenID4VCBackendError.decodingFailed(stage: stage, path: path, reason: reason)
        }
    }

    private static func looksLikeCompactJWE(_ data: Data) -> Bool {
        let compact = String(decoding: data, as: UTF8.self)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        return compact.split(separator: ".", omittingEmptySubsequences: false).count == 5
    }

    private static func wellKnownURL(name: String, issuer: URL) throws -> URL {
        guard let scheme = issuer.scheme, let host = issuer.host else {
            throw OpenID4VCBackendError.unsafeEndpoint
        }
        var components = URLComponents()
        components.scheme = scheme
        components.host = host
        components.port = issuer.port
        let issuerPath = issuer.path == "/" ? "" : issuer.path
        components.path = "/.well-known/\(name)\(issuerPath)"
        guard let url = components.url else { throw OpenID4VCBackendError.unsafeEndpoint }
        return url
    }

    private static func presentationQuery(
        from dcqlQuery: [String: AnySendableJSON]
    ) throws -> (
        id: String,
        format: String,
        vctValues: Set<String>,
        typeValues: [[String]],
        claims: [(id: String, path: [String])]
    ) {
        let parsed = try OpenID4VPDCQLQuery.parse(dcqlQuery)
        try parsed.requireCurrentlySupportedEvaluation()
        let query = parsed.credentials[0]
        let format = query.format
        let id = query.id
        guard format == "dc+sd-jwt" || format == "jwt_vc_json" else {
            throw OpenID4VCBackendError.invalidPresentationChallenge(reason: "DCQL credential format was unsupported")
        }
        let meta = query.meta
            let vcts: Set<String>
            if case let .array(values)? = meta["vct_values"] {
                let decoded = values.compactMap(\.string)
                guard decoded.count == values.count, !decoded.contains(where: \.isEmpty) else {
                    throw OpenID4VCBackendError.invalidPresentationChallenge(reason: "DCQL vct_values were malformed")
                }
                vcts = Set(decoded)
            } else {
                vcts = []
            }
            let typeValues: [[String]]
            if case let .array(values)? = meta["type_values"] {
                typeValues = values.compactMap { value in
                    guard case let .array(types) = value else { return nil }
                    let decoded = types.compactMap(\.string)
                    return decoded.count == types.count && !decoded.isEmpty ? decoded : nil
                }
                guard typeValues.count == values.count else {
                    throw OpenID4VCBackendError.invalidPresentationChallenge(reason: "DCQL type_values were malformed")
                }
            } else {
                typeValues = []
            }
            if query.claims.contains(where: { $0.values != nil }) {
                throw OpenID4VPDCQLError.unsupportedClaimValueEvaluation
            }
            let claims = try query.claims.map { claim -> (id: String, path: [String]) in
                let path = try claim.path.map { component -> String in
                    guard case let .string(value) = component else {
                        throw OpenID4VPDCQLError.unsupportedPathStructure(claimIdentity: claim.id)
                    }
                    return value
                }
                if format == "dc+sd-jwt", path.count != 1 {
                    throw OpenID4VPDCQLError.unsupportedPathStructure(claimIdentity: claim.id)
                }
                return (claim.id, path)
            }
            guard format != "dc+sd-jwt" || !vcts.isEmpty,
                  format != "jwt_vc_json" || !typeValues.isEmpty else {
                throw OpenID4VCBackendError.invalidPresentationChallenge(reason: "DCQL claim constraints were unsupported")
            }
            return (id, format, vcts, typeValues, claims)
    }

    private static func requireUnsignedMatchesSigned(
        request: PresentationRequest,
        signed: VerifiedOpenID4VPRequestObject
    ) throws {
        try requireMatches([request.clientID, request.requestObject?.clientID], signed: signed.clientID, name: "client_id")
        try requireMatches([request.responseType, request.requestObject?.responseType], signed: signed.responseType, name: "response_type")
        try requireMatches([request.responseMode, request.requestObject?.responseMode], signed: signed.responseMode, name: "response_mode")
        try requireMatches([request.responseURI, request.requestObject?.responseURI], signed: signed.responseURI, name: "response_uri")
        try requireMatches([request.nonce, request.requestObject?.nonce], signed: signed.nonce, name: "nonce")
        try requireMatches([request.state, request.requestObject?.state], signed: signed.state, name: "state")
        try requireMatches([request.dcqlQuery, request.requestObject?.dcqlQuery], signed: signed.dcqlQuery, name: "dcql_query")
    }

    private static func requireMatches<Value: Equatable>(
        _ unsignedValues: [Value?], signed: Value?, name: String
    ) throws {
        for value in unsignedValues.compactMap({ $0 }) where value != signed {
            throw OpenID4VCBackendError.invalidPresentationChallenge(
                reason: "unsigned \(name) did not exactly match the signed Request Object"
            )
        }
    }

    private static func singleQueryValue(named name: String, in items: [URLQueryItem]) throws -> String? {
        let values = items.filter { $0.name == name }
        guard values.count <= 1 else {
            throw OpenID4VCBackendError.invalidPresentationChallenge(reason: "duplicate \(name) parameter")
        }
        return values.first?.value
    }

    private static func requireOuterValuesMatchSigned(
        _ items: [URLQueryItem], signed: VerifiedOpenID4VPRequestObject
    ) throws {
        let scalarValues: [(String, String?)] = [
            ("client_id", signed.clientID), ("response_type", signed.responseType),
            ("response_mode", signed.responseMode), ("response_uri", signed.responseURI),
            ("nonce", signed.nonce), ("state", signed.state),
        ]
        for (name, signedValue) in scalarValues {
            if let unsigned = try singleQueryValue(named: name, in: items), unsigned != signedValue {
                throw OpenID4VCBackendError.invalidPresentationChallenge(
                    reason: "unsigned \(name) did not exactly match the signed Request Object"
                )
            }
        }
        if let value = try singleQueryValue(named: "dcql_query", in: items) {
            guard let data = value.data(using: .utf8),
                  let decoded = try? JSONDecoder().decode([String: AnySendableJSON].self, from: data),
                  decoded == signed.dcqlQuery else {
                throw OpenID4VCBackendError.invalidPresentationChallenge(
                    reason: "unsigned dcql_query did not exactly match the signed Request Object"
                )
            }
        }
    }

    private static func requiredStandaloneExpiry(_ request: VerifiedOpenID4VPRequestObject) throws -> Date {
        guard let expiresAt = request.expiresAt else {
            throw OpenID4VCBackendError.invalidPresentationChallenge(reason: "standalone signed request exp was missing")
        }
        return expiresAt
    }

    private static func validateStandaloneLifetime(
        _ request: VerifiedOpenID4VPRequestObject, at date: Date
    ) throws {
        guard let issuedAt = request.issuedAt, let expiresAt = request.expiresAt,
              issuedAt <= date.addingTimeInterval(60),
              issuedAt >= date.addingTimeInterval(-300),
              expiresAt > date,
              expiresAt > issuedAt,
              expiresAt.timeIntervalSince(issuedAt) <= 300 else {
            throw OpenID4VCBackendError.invalidPresentationChallenge(
                reason: "standalone signed request required a current iat and an exp within five minutes"
            )
        }
    }

    private static func presentationClaim(
        id: String,
        path: [String],
        value: String
    ) -> DCQLRequestedClaim {
        DCQLRequestedClaim(
            id: id,
            path: path,
            value: value,
            required: true
        )
    }

    private static func value(
        at path: [String],
        in document: [String: AnySendableJSON]
    ) -> AnySendableJSON? {
        guard let first = path.first, var value = document[first] else { return nil }
        for component in path.dropFirst() {
            guard let next = value.object?[component] else { return nil }
            value = next
        }
        return value
    }

    private static func matchesTypeValues(
        _ typeValues: [[String]],
        document: [String: AnySendableJSON]
    ) -> Bool {
        guard !typeValues.isEmpty else { return true }
        let types: Set<String>
        if let type = document["type"]?.string {
            types = [type]
        } else if case let .array(values)? = document["type"] {
            types = Set(values.compactMap(\.string))
        } else {
            types = []
        }
        return typeValues.contains { Set($0).isSubset(of: types) }
    }

    private static func parseStoredSDJWT(_ rawCredential: Data) throws -> (
        issuerJWT: String,
        vct: String,
        payload: [String: AnySendableJSON],
        disclosures: [String: (encoded: String, displayValue: String)]
    ) {
        let raw = String(decoding: rawCredential, as: UTF8.self)
        guard let issuerJWT = raw.split(separator: "~", omittingEmptySubsequences: false).first else {
            throw EbsiCredentialError.malformedCredential
        }
        let payload = try EbsiCredentialInspector().inspectSDJWT(raw)
        guard let vct = payload["vct"]?.string else { throw EbsiCredentialError.profileMismatch }
        let validDigests: Set<String>
        if case let .array(values)? = payload["_sd"] {
            validDigests = Set(values.compactMap(\.string))
        } else {
            validDigests = []
        }
        var disclosures: [String: (encoded: String, displayValue: String)] = [:]
        for encoded in raw.split(separator: "~").dropFirst() where !encoded.isEmpty {
            let digest = Data(SHA256.hash(data: Data(encoded.utf8))).base64URLEncodedString()
            guard validDigests.contains(digest) else { continue }
            var base64 = String(encoded).replacingOccurrences(of: "-", with: "+")
                .replacingOccurrences(of: "_", with: "/")
            base64 += String(repeating: "=", count: (4 - base64.count % 4) % 4)
            guard let data = Data(base64Encoded: base64),
                  let value = try? JSONSerialization.jsonObject(with: data) as? [Any],
                  value.count == 3, let name = value[1] as? String else { continue }
            let displayValue: String
            if let string = value[2] as? String { displayValue = string }
            else if let number = value[2] as? NSNumber { displayValue = number.stringValue }
            else { displayValue = "Available" }
            disclosures[name] = (String(encoded), displayValue)
        }
        return (String(issuerJWT), vct, payload, disclosures)
    }

    private static func equivalentDraftConfiguration(
        offeredID: String,
        authorizedID: String,
        configurations: [String: SupportedConfiguration]
    ) -> Bool {
        if offeredID == authorizedID { return true }
        guard let offered = configurations[offeredID],
              let authorized = configurations[authorizedID],
              let offeredVCT = offered.vct, !offeredVCT.isEmpty,
              offeredVCT == authorized.vct else {
            return false
        }
        return offered.format == authorized.format
    }

    private static func draftAuthorizationMatch(
        offeredID: String,
        detail: TokenResponse.AuthorizationDetail,
        configurations: [String: SupportedConfiguration]
    ) -> (score: Int, credentialIdentifier: String)? {
        let identifiers = detail.credentialIdentifiers?.filter { !$0.isEmpty } ?? []
        guard !identifiers.isEmpty else { return nil }
        let equivalentIdentifiers = identifiers.filter {
            equivalentDraftConfiguration(
                offeredID: offeredID,
                authorizedID: $0,
                configurations: configurations
            )
        }
        let equivalentIdentifier = equivalentIdentifiers.count == 1 ? equivalentIdentifiers[0] : nil
        if detail.credentialConfigurationID == offeredID {
            return (400, identifiers.first(where: { $0 == offeredID }) ?? equivalentIdentifier ?? identifiers[0])
        }
        if identifiers.contains(offeredID) {
            return (300, offeredID)
        }
        if let authorizedID = detail.credentialConfigurationID,
           equivalentDraftConfiguration(
               offeredID: offeredID,
               authorizedID: authorizedID,
               configurations: configurations
           ) {
            return (200, equivalentIdentifier ?? identifiers[0])
        }
        if let equivalentIdentifier {
            return (100, equivalentIdentifier)
        }
        return nil
    }

    private static func authorizationIdentifiers(
        _ details: [TokenResponse.AuthorizationDetail]
    ) -> [String] {
        var seen: Set<String> = []
        return details.flatMap { detail in
            [detail.credentialConfigurationID].compactMap { $0 } + (detail.credentialIdentifiers ?? [])
        }.filter { !$0.isEmpty && seen.insert($0).inserted }
    }

    private static func uniqueNonEmpty(_ values: [String]) -> [String] {
        var seen: Set<String> = []
        return values.filter { !$0.isEmpty && seen.insert($0).inserted }
    }

    private static func isRetryableCredentialIdentifierError(_ error: OpenID4VCBackendError) -> Bool {
        switch error {
        case .remoteOAuthError(code: "invalid_credential_request", detail: _),
             .remoteOAuthError(code: "unsupported_credential_type", detail: _):
            return true
        case let .remoteHTTPError(status: 400, detail):
            let value = detail?.lowercased() ?? ""
            return value.contains("invalid credential request") ||
                value.contains("unsupported credential type")
        default:
            return false
        }
    }

    private static func displayClaims(from credential: [String: AnySendableJSON]?) -> [CredentialDisplayClaim] {
        guard let credential else { return [] }
        let subject = credential["credentialSubject"]?.object ?? credential
        return subject.compactMap { key, value in
            guard let string = value.displayString else { return nil }
            return CredentialDisplayClaim(
                id: key,
                label: key.replacingOccurrences(of: "_", with: " ").capitalized,
                value: string,
                isSensitive: key.lowercased().contains("id") || key.lowercased().contains("name")
            )
        }.sorted { $0.label < $1.label }
    }

    private static func displayClaims(
        raw: String,
        profile: EbsiCredentialProfile
    ) -> [CredentialDisplayClaim] {
        if profile.representation == .dcSdJwt || profile.representation == .vcdm2SdJwt {
            var claims = (try? EbsiCredentialInspector().inspectSDJWT(raw)) ?? [:]
            for disclosure in raw.split(separator: "~").dropFirst() where !disclosure.isEmpty {
                var value = String(disclosure).replacingOccurrences(of: "-", with: "+")
                    .replacingOccurrences(of: "_", with: "/")
                value += String(repeating: "=", count: (4 - value.count % 4) % 4)
                guard let data = Data(base64Encoded: value),
                      let array = try? JSONDecoder().decode([AnySendableJSON].self, from: data),
                      array.count >= 3, let name = array[1].string else { continue }
                claims[name] = array[2]
            }
            let hidden = Set(["_sd", "_sd_alg", "cnf", "iss", "iat", "exp", "vct", "status"])
            return displayClaims(from: claims.filter { !hidden.contains($0.key) })
        }
        return displayClaims(from: try? EbsiCredentialInspector().inspectCompactJWT(raw, profile: profile))
    }

    private static func hasCredentialStatus(raw: Data, profile: EbsiCredentialProfile) -> Bool {
        let compact = String(decoding: raw, as: UTF8.self)
        if profile.representation == .dcSdJwt || profile.representation == .vcdm2SdJwt {
            guard let payload = try? EbsiCredentialInspector().inspectSDJWT(
                compact,
                requiresHolderBinding: profile.requiresSDJWTHolderBinding
            ) else { return false }
            return payload["status"] != nil || payload["status_list"] != nil
        }
        guard let credential = try? EbsiCredentialInspector().inspectCompactJWT(
            compact,
            profile: profile
        ) else { return false }
        return credential["credentialStatus"] != nil || credential["status"] != nil
    }

    public func cancel(id: UUID) {
        stagedCredentials[id] = nil
        transactions[id] = nil
        authorizationCodes[id] = nil
        authorizationCodeVerifiers[id] = nil
        authorizationStates[id] = nil
        presentationChallenges[id] = nil
        presentationChallengeTasks.removeValue(forKey: id)?.cancel()
        interactiveAuthorizationContexts[id] = nil
        preparedPIDPresentations[id] = nil
        transactionHolderIdentities[id] = nil
        trustConsents.remove(id)
    }

    public func deleteStoredCredential(id: UUID) async throws {
        try await credentialStore.delete(id: id)
    }

    private func authorizeTrust(
        transaction: Transaction,
        id: UUID,
        allowUntrusted: Bool
    ) throws {
        switch transaction.trustOutcome {
        case .allow: trustConsents.insert(id)
        case .requireExplicitWarning:
            guard allowUntrusted || trustConsents.contains(id) else {
                throw OpenID4VCBackendError.untrustedConsentRequired
            }
            trustConsents.insert(id)
        case .reject: throw OpenID4VCBackendError.rejectedTrust
        }
    }

    private func interactiveAuthorizationRequestBody(
        id: UUID,
        issuerState: String,
        interactionTypes: [String],
        endpoint: URL,
        configurationIDs: [String],
        includeState: Bool
    ) throws -> Data {
        form(try interactiveAuthorizationRequestFields(
            id: id,
            issuerState: issuerState,
            interactionTypes: interactionTypes,
            endpoint: endpoint,
            configurationIDs: configurationIDs,
            includeState: includeState
        ))
    }

    private func interactiveAuthorizationRequestFields(
        id: UUID,
        issuerState: String,
        interactionTypes: [String],
        endpoint: URL,
        configurationIDs: [String],
        includeState: Bool
    ) throws -> [String: String?] {
        let verifier = Self.base64URL(Data((UUID().uuidString + UUID().uuidString).utf8))
        authorizationCodeVerifiers[id] = verifier
        let state: String?
        if includeState {
            state = authorizationStates[id] ?? UUID().uuidString.lowercased()
            authorizationStates[id] = state
        } else {
            state = nil
            authorizationStates[id] = nil
        }
        let challenge = Data(SHA256.hash(data: Data(verifier.utf8))).base64URLEncodedString()
        let authorizationDetails = try JSONSerialization.data(
            withJSONObject: configurationIDs.map { configurationID in
                ["type": "openid_credential", "credential_configuration_id": configurationID]
            }
        )
        return [
            "issuer_state": issuerState,
            "interaction_types_supported": interactionTypes.joined(separator: ","),
            "response_type": "code",
            "client_id": authorizationClientID,
            "redirect_uri": authorizationRedirectURI.absoluteString,
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "authorization_details": String(decoding: authorizationDetails, as: UTF8.self),
        ]
    }

    private func proofJWT(
        keyID: KeyID,
        kid: String,
        issuer: String,
        audience: String,
        nonce: String?
    ) async throws -> String {
        let issuedAt = Int(now().timeIntervalSince1970)
        let header = try Self.base64JSON(["alg": "ES256", "kid": kid, "typ": "openid4vci-proof+jwt"])
        var payload: [String: Any] = [
            "iss": issuer,
            "aud": audience,
            "iat": issuedAt,
            "exp": issuedAt + 300,
            "jti": "urn:uuid:\(UUID().uuidString.lowercased())",
        ]
        if let nonce { payload["nonce"] = nonce }
        let encodedPayload = try Self.base64JSON(payload)
        let input = Data("\(header).\(encodedPayload)".utf8)
        let signature = try await keyProvider.sign(SigningRequest(
            keyID: keyID,
            payload: input,
            userAuthenticationReason: "Sign EBSI credential proof",
            signatureFormat: .joseRaw
        ))
        return "\(header).\(encodedPayload).\(signature.base64URLEncodedString())"
    }

    private func signedPresentationJWT(
        keyID: KeyID,
        type: String,
        contentType: String? = nil,
        payload: [String: Any]
    ) async throws -> String {
        var headerObject = ["alg": "ES256", "typ": type]
        if let contentType { headerObject["cty"] = contentType }
        if let publicKey = try? await keyProvider.publicKey(id: keyID),
           let did = try? KeyDIDResolver().derive(publicKeyX963: publicKey.x963Representation),
           let document = try? await KeyDIDResolver().resolve(did),
           let method = document.assertionMethod.first {
            headerObject["kid"] = method
        }
        let header = try Self.base64JSON(headerObject)
        let encodedPayload = try Self.base64JSON(payload)
        let signingInput = Data("\(header).\(encodedPayload)".utf8)
        let signature = try await keyProvider.sign(SigningRequest(
            keyID: keyID,
            payload: signingInput,
            userAuthenticationReason: "Present approved identity claims",
            signatureFormat: .joseRaw
        ))
        return "\(header).\(encodedPayload).\(signature.base64URLEncodedString())"
    }

    private func successfulGET(_ url: URL, allowedOrigins: Set<String>) async throws -> Data {
        try await successfulRequest(
            url,
            method: "GET",
            headers: [:],
            body: nil,
            allowedOrigins: allowedOrigins
        )
    }

    private func discoverMetadata<Value: Decodable>(
        _ type: Value.Type,
        name: String,
        issuer: URL,
        standardURL: URL,
        stage: String
    ) async throws -> Value {
        let allowedOrigins = Set([try Self.origin(of: issuer)])
        do {
            let data = try await successfulGET(standardURL, allowedOrigins: allowedOrigins)
            return try Self.decode(type, from: data, stage: stage)
        } catch let error as OpenID4VCBackendError {
            let shouldTryLegacy = switch error {
            case .remoteHTTPError(status: 404, detail: _): true
            case .remoteOAuthError(code: "not_found", detail: _): true
            case .decodingFailed: true
            default: false
            }
            guard shouldTryLegacy else { throw error }
            let legacyURL = issuer
                .appendingPathComponent(".well-known")
                .appendingPathComponent(name)
            guard legacyURL != standardURL else { throw error }
            let data = try await successfulGET(legacyURL, allowedOrigins: allowedOrigins)
            return try Self.decode(type, from: data, stage: stage)
        }
    }

    private func offlineDisplayMetadata(
        _ display: CredentialConfigurationDisplay?
    ) async -> CredentialDisplayMetadata? {
        guard let display else { return nil }
        async let logo = downloadDisplayImage(
            display.logoURL,
            alternativeText: display.logoAlternativeText
        )
        async let background = downloadDisplayImage(display.backgroundImageURL)
        let images = await (logo, background)
        return CredentialDisplayMetadata(
            locale: display.locale,
            description: display.description,
            backgroundColor: display.backgroundColor,
            textColor: display.textColor,
            logo: images.0,
            backgroundImage: images.1
        )
    }

    private func downloadDisplayImage(
        _ url: URL?,
        alternativeText: String? = nil
    ) async -> CredentialDisplayImage? {
        guard let url else { return nil }
        do {
            try Self.validateHTTPS(url)
            let response = try await transport.send(url: url, method: "GET", headers: [:], body: nil)
            guard (200..<300).contains(response.statusCode),
                  !response.body.isEmpty,
                  response.body.count <= 1_048_576,
                  let mediaType = Self.validatedImageMediaType(
                      response.headers.first { $0.key.caseInsensitiveCompare("Content-Type") == .orderedSame }?.value,
                      data: response.body
                  ) else { return nil }
            return CredentialDisplayImage(
                mediaType: mediaType,
                data: response.body,
                alternativeText: alternativeText
            )
        } catch {
            return nil
        }
    }

    private static func validatedImageMediaType(_ contentType: String?, data: Data) -> String? {
        let declared = contentType?.split(separator: ";", maxSplits: 1).first?
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()
        let detected: String?
        if data.starts(with: [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]) {
            detected = "image/png"
        } else if data.starts(with: [0xff, 0xd8, 0xff]) {
            detected = "image/jpeg"
        } else if data.count >= 12,
                  String(decoding: data.prefix(4), as: UTF8.self) == "RIFF",
                  String(decoding: data.dropFirst(8).prefix(4), as: UTF8.self) == "WEBP" {
            detected = "image/webp"
        } else {
            detected = nil
        }
        guard let detected, declared == nil || declared == detected else { return nil }
        return detected
    }

    private func successfulRequest(
        _ url: URL,
        method: String,
        headers: [String: String],
        body: Data?,
        allowedOrigins: Set<String>
    ) async throws -> Data {
        try await successfulHTTPResponse(
            url, method: method, headers: headers, body: body, allowedOrigins: allowedOrigins
        ).body
    }

    private func successfulHTTPResponse(
        _ url: URL,
        method: String,
        headers: [String: String],
        body: Data?,
        allowedOrigins: Set<String>
    ) async throws -> OpenID4VCHTTPResponse {
        try Self.validateHTTPS(url)
        guard allowedOrigins.contains(try Self.origin(of: url)) else {
            throw OpenID4VCBackendError.unsafeEndpoint
        }
        let response = try await transport.send(url: url, method: method, headers: headers, body: body)
        guard response.body.count <= 1_048_576 else {
            throw OpenID4VCBackendError.invalidResponse
        }
        guard (200..<300).contains(response.statusCode) else {
            if let error = try? JSONDecoder().decode(RemoteOAuthError.self, from: response.body) {
                throw OpenID4VCBackendError.remoteOAuthError(code: error.error,
                detail: error.errorDescription)
            }
            let detail = (try? JSONDecoder().decode(RemoteHTTPError.self, from: response.body))?.detail
                ?? String(data: response.body, encoding: .utf8)
            throw OpenID4VCBackendError.remoteHTTPError(status: response.statusCode, detail: detail)
        }
        return response
    }

    private static func baseMediaType(of response: OpenID4VCHTTPResponse) -> String? {
        response.headers.first {
            $0.key.caseInsensitiveCompare("Content-Type") == .orderedSame
        }?.value.split(separator: ";", maxSplits: 1).first?
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()
    }

    private static func validateHTTPS(_ url: URL) throws {
        guard let scheme = url.scheme?.lowercased(),
              scheme == "https" || (scheme == "http" && (url.host == "127.0.0.1" || url.host == "localhost")),
              url.host != nil,
              url.user == nil, url.password == nil, url.fragment == nil else {
            throw OpenID4VCBackendError.unsafeEndpoint
        }
    }

    private static func origin(of url: URL) throws -> String {
        try validateHTTPS(url)
        guard let scheme = url.scheme?.lowercased(), let host = url.host?.lowercased() else {
            throw OpenID4VCBackendError.unsafeEndpoint
        }
        return "\(scheme)://\(host)\(url.port.map { ":\($0)" } ?? "")"
    }

    private static func validate(_ value: String?, requirement: TxCode?) throws {
        guard let requirement else { return }
        guard let value, requirement.length.map({ value.count == $0 }) ?? true else {
            throw OpenID4VCBackendError.invalidTransactionCode
        }
        guard !value.isEmpty,
              value.unicodeScalars.allSatisfy({ $0.isASCII && $0.value >= 0x21 && $0.value <= 0x7e }),
              value.utf8.count == value.count else {
            throw OpenID4VCBackendError.invalidTransactionCode
        }
        if requirement.numeric,
           !value.unicodeScalars.allSatisfy({ (48...57).contains(Int($0.value)) }) {
            throw OpenID4VCBackendError.invalidTransactionCode
        }
    }

    private func form(_ values: [String: String?]) -> Data {
        var components = URLComponents()
        components.queryItems = values.compactMap { key, value in value.map { URLQueryItem(name: key, value: $0) } }
        return Data((components.percentEncodedQuery ?? "").utf8)
    }

    private static func base64JSON(_ value: Any) throws -> String {
        try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]).base64URLEncodedString()
    }

}

private struct CredentialOffer: Decodable {
    let credentialIssuer: String
    let credentialConfigurationIds: [String]
    let grants: Grants?
    enum CodingKeys: String, CodingKey {
        case credentialIssuer = "credential_issuer"
        case credentialConfigurationIds = "credential_configuration_ids"
        case grants
    }
}

private struct Grants: Decodable {
    let preauthorized: PreauthorizedGrant?
    let authorizationCode: AuthorizationCodeGrant?
    enum CodingKeys: String, CodingKey {
        case preauthorized = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
        case authorizationCode = "authorization_code"
    }
}

private struct AuthorizationCodeGrant: Decodable {
    let issuerState: String?
    enum CodingKeys: String, CodingKey { case issuerState = "issuer_state" }
}

private struct PresentationChallengeResponse: Decodable {
    let error: String?
    let authSession: String?
    let authorizationURL: String?
    let interactionTypeRequired: String?
    let type: String?
    let openid4vpRequest: PresentationRequest?
    enum CodingKeys: String, CodingKey {
        case error
        case authSession = "auth_session"
        case authorizationURL = "authorization_url"
        case interactionTypeRequired = "interaction_type_required"
        case type
        case openid4vpRequest = "openid4vp_request"
    }
}

private struct PresentationRequest: Decodable {
    let responseType: String?
    let responseMode: String?
    let responseURI: String?
    let clientID: String?
    let nonce: String?
    let state: String?
    let dcqlQuery: [String: AnySendableJSON]?
    let request: String?
    let requestJWT: String?
    let requestObject: PresentationRequestObject?
    enum CodingKeys: String, CodingKey {
        case responseType = "response_type"
        case responseMode = "response_mode"
        case responseURI = "response_uri"
        case clientID = "client_id"
        case nonce, state
        case dcqlQuery = "dcql_query"
        case request
    }

    init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        responseType = try values.decodeIfPresent(String.self, forKey: .responseType)
        responseMode = try values.decodeIfPresent(String.self, forKey: .responseMode)
        responseURI = try values.decodeIfPresent(String.self, forKey: .responseURI)
        clientID = try values.decodeIfPresent(String.self, forKey: .clientID)
        nonce = try values.decodeIfPresent(String.self, forKey: .nonce)
        state = try values.decodeIfPresent(String.self, forKey: .state)
        dcqlQuery = try values.decodeIfPresent([String: AnySendableJSON].self, forKey: .dcqlQuery)
        if let jwt = try? values.decode(String.self, forKey: .request) {
            request = jwt
            requestJWT = jwt
            requestObject = nil
        } else {
            request = nil
            requestJWT = nil
            requestObject = try values.decodeIfPresent(PresentationRequestObject.self, forKey: .request)
        }
    }
}

private struct PresentationRequestObject: Decodable {
    let clientID: String?
    let responseType: String?
    let responseMode: String?
    let responseURI: String?
    let nonce: String?
    let state: String?
    let dcqlQuery: [String: AnySendableJSON]?

    enum CodingKeys: String, CodingKey {
        case clientID = "client_id"
        case responseType = "response_type"
        case responseMode = "response_mode"
        case responseURI = "response_uri"
        case nonce, state
        case dcqlQuery = "dcql_query"
    }
}

private struct SignedPresentationRequest: Decodable {
    let clientID: String
    let responseMode: String
    let responseURI: String?
    let nonce: String
    let state: String?
    let dcqlQuery: [String: AnySendableJSON]
    enum CodingKeys: String, CodingKey {
        case responseMode = "response_mode"
        case responseURI = "response_uri"
        case clientID = "client_id"
        case nonce, state
        case dcqlQuery = "dcql_query"
    }
}

private struct PreparedW3CPresentation: Sendable {
    enum Kind: Sendable {
        case sdJWT(issuerJWT: String, disclosures: [String: String])
        case jwtVC11(String)
        case jwtVC20(String)
    }

    let credential: StoredEbsiCredential
    let authorizationGenerationID: UUID
    let kind: Kind
    let requiredClaimIDs: Set<String>
    let queryID: String
}

private struct InteractiveAuthorizationContext: Sendable {
    let generationID: UUID
    let authorizationChallengeEndpoint: URL
    let activeInteraction: InteractiveAuthorizationChallenge
    let expiresAt: Date
}

private struct InteractiveAuthorizationResponse: Decodable {
    let authorizationCode: String?
    let code: String?
    let state: String?
    let error: String?
    let interactionTypeRequired: String?
    let authSession: String?
    let authorizationURL: String?
    enum CodingKeys: String, CodingKey {
        case authorizationCode = "authorization_code"
        case code
        case state
        case error
        case interactionTypeRequired = "interaction_type_required"
        case authSession = "auth_session"
        case authorizationURL = "authorization_url"
    }
}

private func ifCasePreAuthorizedTxCode(_ grant: OpenID4VCW3CBackend.Grant) -> Bool {
    if case let .preAuthorized(_, txCode) = grant { return txCode != nil }
    return false
}

private func transactionCodeLength(_ grant: OpenID4VCW3CBackend.Grant) -> Int? {
    if case let .preAuthorized(_, requirement) = grant { return requirement?.length }
    return nil
}

private func transactionCodeDescription(_ grant: OpenID4VCW3CBackend.Grant) -> String? {
    if case let .preAuthorized(_, requirement) = grant { return requirement?.description }
    return nil
}

private func ifCaseAuthorization(_ grant: OpenID4VCW3CBackend.Grant) -> Bool {
    if case .authorizationCode = grant { return true }
    return false
}

private func ifCaseIssuerState(_ grant: OpenID4VCW3CBackend.Grant) -> String? {
    if case let .authorizationCode(issuerState) = grant { return issuerState }
    return nil
}

private struct PreauthorizedGrant: Decodable {
    let code: String
    let txCode: TxCodeDefinition?
    enum CodingKeys: String, CodingKey {
        case code = "pre-authorized_code"
        case txCode = "tx_code"
    }
}

private struct TxCodeDefinition: Decodable {
    let inputMode: String?
    let length: Int?
    let description: String?
    enum CodingKeys: String, CodingKey { case inputMode = "input_mode", length, description }
}

private struct IssuerMetadata: Decodable {
    struct Display: Decodable { let name: String? }
    let credentialEndpoint: String
    let authorizationServers: [String]?
    let display: [Display]?
    let credentialConfigurations: [String: SupportedConfiguration]
    let nonceEndpoint: String?
    let notificationEndpoint: String?
    let deferredCredentialEndpoint: String?
    let interactiveAuthorizationEndpoint: String?
    enum CodingKeys: String, CodingKey {
        case credentialEndpoint = "credential_endpoint"
        case authorizationServers = "authorization_servers"
        case display
        case credentialConfigurations = "credential_configurations_supported"
        case nonceEndpoint = "nonce_endpoint"
        case notificationEndpoint = "notification_endpoint"
        case deferredCredentialEndpoint = "deferred_credential_endpoint"
        case interactiveAuthorizationEndpoint = "interactive_authorization_endpoint"
    }

    init(from decoder: any Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        credentialEndpoint = try values.decode(String.self, forKey: .credentialEndpoint)
        authorizationServers = try values.decodeIfPresent([String].self, forKey: .authorizationServers)
        display = try values.decodeIfPresent([Display].self, forKey: .display)
        credentialConfigurations = try values.decodeIfPresent(
            [String: SupportedConfiguration].self,
            forKey: .credentialConfigurations
        ) ?? [:]
        nonceEndpoint = try values.decodeIfPresent(String.self, forKey: .nonceEndpoint)
        notificationEndpoint = try values.decodeIfPresent(String.self, forKey: .notificationEndpoint)
        deferredCredentialEndpoint = try values.decodeIfPresent(String.self, forKey: .deferredCredentialEndpoint)
        interactiveAuthorizationEndpoint = try values.decodeIfPresent(String.self, forKey: .interactiveAuthorizationEndpoint)
    }
}

private struct SupportedConfiguration: Decodable {
    let format: String
    let vct: String?
    let credentialMetadata: CredentialMetadata?
    let directDisplay: [CredentialDisplay]?
    let directClaims: [String: ClaimDefinition]?

    var display: CredentialConfigurationDisplay {
        let display = (directDisplay ?? credentialMetadata?.display)?.first
        return CredentialConfigurationDisplay(
            name: display?.name ?? "Credential",
            locale: display?.locale,
            description: display?.description,
            backgroundColor: display?.backgroundColor,
            textColor: display?.textColor,
            logoURL: display?.logo.flatMap { URL(string: $0.url) },
            logoAlternativeText: display?.logo?.alternativeText,
            backgroundImageURL: display?.backgroundImage.flatMap { URL(string: $0.url) },
            claims: directClaims?.map { key, value in
                CredentialConfigurationClaim(
                    id: key,
                    path: [key],
                    name: value.display?.first?.name ?? key,
                    description: value.description
                )
            }.sorted { $0.id < $1.id } ?? credentialMetadata?.claims ?? []
        )
    }

    enum CodingKeys: String, CodingKey {
        case format, vct
        case credentialMetadata = "credential_metadata"
        case directDisplay = "display"
        case directClaims = "claims"
    }

    init(from decoder: any Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        format = try values.decode(String.self, forKey: .format)
        vct = try values.decodeIfPresent(String.self, forKey: .vct)
        credentialMetadata = try values.decodeIfPresent(CredentialMetadata.self, forKey: .credentialMetadata)
        directDisplay = try values.decodeIfPresent([CredentialDisplay].self, forKey: .directDisplay)
        directClaims = try values.decodeIfPresent([String: ClaimDefinition].self, forKey: .directClaims)
    }
}

private struct CredentialMetadata: Decodable {
    let display: [CredentialDisplay]?
    let claims: [CredentialConfigurationClaim]?
}

private struct CredentialDisplay: Decodable {
    let name: String?
    let locale: String?
    let description: String?
    let backgroundColor: String?
    let textColor: String?
    let logo: Logo?
    let backgroundImage: DisplayImage?

    enum CodingKeys: String, CodingKey {
        case name, locale, description
        case backgroundColor = "background_color"
        case textColor = "text_color"
        case logo
        case backgroundImage = "background_image"
    }
}

private struct ClaimDefinition: Decodable {
    let display: [CredentialDisplay]?
    let description: String?
}

private struct Logo: Decodable {
    let url: String
    let alternativeText: String?
    enum CodingKeys: String, CodingKey { case url, uri, alternativeText = "alt_text" }
    init(from decoder: any Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        url = try values.decodeIfPresent(String.self, forKey: .url)
            ?? values.decode(String.self, forKey: .uri)
        alternativeText = try values.decodeIfPresent(String.self, forKey: .alternativeText)
    }
}

private struct DisplayImage: Decodable {
    let url: String
    enum CodingKeys: String, CodingKey { case url, uri }
    init(from decoder: any Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        url = try values.decodeIfPresent(String.self, forKey: .url)
            ?? values.decode(String.self, forKey: .uri)
    }
}

private struct AuthorizationMetadata: Decodable {
    let issuer: String?
    let tokenEndpoint: String
    let authorizationEndpoint: String?
    let authorizationChallengeEndpoint: String?
    let dpopSigningAlgorithms: [String]?
    let clientAttestationAlgorithms: [String]?
    let tokenEndpointAuthenticationMethods: [String]?
    enum CodingKeys: String, CodingKey {
        case issuer
        case tokenEndpoint = "token_endpoint"
        case authorizationEndpoint = "authorization_endpoint"
        case authorizationChallengeEndpoint = "authorization_challenge_endpoint"
        case dpopSigningAlgorithms = "dpop_signing_alg_values_supported"
        case clientAttestationAlgorithms = "client_attestation_signing_alg_values_supported"
        case tokenEndpointAuthenticationMethods = "token_endpoint_auth_methods_supported"
    }
}

private struct RemoteOAuthError: Decodable {
    let error: String
    let errorDescription: String?
    enum CodingKeys: String, CodingKey {
        case error
        case errorDescription = "error_description"
    }
}

private struct RemoteHTTPError: Decodable { let detail: String? }

private struct CredentialNonceResponse: Decodable {
    let nonce: String
    enum CodingKeys: String, CodingKey { case nonce = "c_nonce" }
}

private struct TokenResponse: Decodable {
    struct AuthorizationDetail: Decodable {
        let credentialConfigurationID: String?
        let credentialIdentifiers: [String]?
        enum CodingKeys: String, CodingKey {
            case credentialConfigurationID = "credential_configuration_id"
            case credentialIdentifiers = "credential_identifiers"
        }
    }
    let accessToken: String
    let tokenType: String?
    let expiresIn: Int?
    let nonce: String?
    let authorizationDetails: [AuthorizationDetail]?
    enum CodingKeys: String, CodingKey {
        case accessToken = "access_token"
        case tokenType = "token_type"
        case expiresIn = "expires_in"
        case nonce = "c_nonce"
        case authorizationDetails = "authorization_details"
    }
}

private struct CredentialRequest: Encodable {
    let credentialConfigurationId: String?
    let credentialIdentifier: String?
    let format: String?
    let proof: ProofValue?
    let proofs: [String: [String]]?
    let credentialResponseEncryption: CredentialResponseEncryptionRequest?
    enum CodingKeys: String, CodingKey {
        case credentialConfigurationId = "credential_configuration_id"
        case credentialIdentifier = "credential_identifier"
        case format
        case proof, proofs
        case credentialResponseEncryption = "credential_response_encryption"
    }
}

private struct CredentialResponseEncryptionRequest: Encodable {
    let jwk: [String: String]
    let alg: String
    let enc: String
}

private struct ProofValue: Encodable {
    let proofType: String
    let jwt: String
    enum CodingKeys: String, CodingKey { case proofType = "proof_type", jwt }
}

private struct CredentialResponse: Decodable {
    struct Item: Decodable {
        let credential: String
        let format: String?
    }
    let format: String?
    let credential: String?
    let credentials: [Item]
    let notificationID: String?
    let transactionID: String?
    let interval: Int?

    private enum CodingKeys: String, CodingKey {
        case format, credential, credentials
        case notificationID = "notification_id"
        case transactionID = "transaction_id"
        case interval
    }

    init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        format = try container.decodeIfPresent(String.self, forKey: .format)
        credential = try container.decodeIfPresent(String.self, forKey: .credential)
        let plural = try container.decodeIfPresent([Item].self, forKey: .credentials) ?? []
        notificationID = try container.decodeIfPresent(String.self, forKey: .notificationID)
        transactionID = try container.decodeIfPresent(String.self, forKey: .transactionID)
        interval = try container.decodeIfPresent(Int.self, forKey: .interval)
        if plural.isEmpty, let credential {
            credentials = [Item(credential: credential, format: format)]
        } else {
            credentials = plural
        }
    }
}

private struct DeferredCredentialRequest: Encodable {
    let transactionID: String
    enum CodingKeys: String, CodingKey { case transactionID = "transaction_id" }
}

private extension Data {
    func base64URLEncodedString() -> String {
        base64EncodedString().replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }
}
