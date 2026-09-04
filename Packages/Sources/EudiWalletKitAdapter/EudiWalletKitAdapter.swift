import EudiWalletKit
import CryptoKit
import Foundation
import JOSESwift
import MdocDataTransfer18013
import OpenID4VCI
import Security
import WalletDomain
import X509
#if canImport(EudiEtsi1196x2)
import MdocSecurity18013
#endif

public struct EudiWalletKitBaseline: Sendable {
    public static let selectedVersion = "0.39.1"
    public static let selectedCommit = "79005ab4bf0399238c1c9ebff9ee7d8a42c521f9"

    public let serviceName: String
    public let trustConfiguration: TrustConfiguration
    public let openID4VciConfigurations: [String: OpenId4VciConfiguration]
    public let openID4VpConfiguration: OpenId4VpConfiguration
    private let derivesTrustConfigurationFromSource: Bool

    public init(
        serviceName: String,
        trustConfiguration: TrustConfiguration,
        openID4VciConfigurations: [String: OpenId4VciConfiguration],
        openID4VpConfiguration: OpenId4VpConfiguration
    ) throws {
        let serviceName = serviceName.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !serviceName.isEmpty, !serviceName.contains(":") else {
            throw EudiWalletKitAdapterError.invalidServiceName
        }
        self.serviceName = serviceName
        self.trustConfiguration = trustConfiguration
        self.openID4VciConfigurations = openID4VciConfigurations
        self.openID4VpConfiguration = openID4VpConfiguration
        self.derivesTrustConfigurationFromSource = false
    }

    /// Test-support compatibility. Production callers should provide the full
    /// native Wallet Kit trust and protocol configuration.
    public init(serviceName: String) throws {
        let serviceName = serviceName.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !serviceName.isEmpty, !serviceName.contains(":") else {
            throw EudiWalletKitAdapterError.invalidServiceName
        }
        self.serviceName = serviceName
        self.trustConfiguration = Self.compatibilityTrustConfiguration(anchors: [])
        self.openID4VciConfigurations = [:]
        self.openID4VpConfiguration = OpenId4VpConfiguration(
            clientIdSchemes: [.redirectUri],
            supportedTransactionDataTypes: [.default()]
        )
        self.derivesTrustConfigurationFromSource = true
    }

    public func walletConfiguration() -> EudiWalletConfiguration {
        EudiWalletConfiguration(
            serviceName: serviceName,
            userAuthenticationRequired: true,
            logFileName: nil,
            bleTransferMode: .server
        )
    }

    public func presentationConfiguration() -> OpenId4VpConfiguration {
        openID4VpConfiguration
    }

    public func makeWallet(
        trustSource: EudiTrustAnchorSource,
        operationalConfiguration: EudiOperationalConfiguration? = nil,
        validationDate: Date = Date()
    ) throws -> EudiWalletKitAdapter {
        // Keep the profile-bound validation boundary, while allowing the caller to supply
        // Wallet Kit's complete native trust model (including ETSI LoTE and fallback sources).
        let anchors = try trustSource.validatedAnchors(at: validationDate)
        let effectiveTrustConfiguration = derivesTrustConfigurationFromSource
            ? Self.compatibilityTrustConfiguration(anchors: anchors)
            : trustConfiguration
        return try makeWallet(
            trustConfiguration: effectiveTrustConfiguration,
            trustProfileID: trustSource.profileID,
            operationalConfiguration: operationalConfiguration
        )
    }

    public func makeWallet(
        trustProfileID: String,
        operationalConfiguration: EudiOperationalConfiguration? = nil
    ) throws -> EudiWalletKitAdapter {
        guard !derivesTrustConfigurationFromSource,
              !trustProfileID.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw EudiWalletKitAdapterError.invalidTrustSource
        }
        return try makeWallet(
            trustConfiguration: trustConfiguration,
            trustProfileID: trustProfileID,
            operationalConfiguration: operationalConfiguration
        )
    }

    private func makeWallet(
        trustConfiguration: TrustConfiguration,
        trustProfileID: String,
        operationalConfiguration: EudiOperationalConfiguration?
    ) throws -> EudiWalletKitAdapter {
        do {
            let wallet = try EudiWallet(
                eudiWalletConfig: walletConfiguration(),
                trustConfig: trustConfiguration,
                openID4VpConfig: presentationConfiguration(),
                openID4VciConfigurations: openID4VciConfigurations,
                networking: operationalConfiguration.map(EudiNetworkingBridge.init)
            )
            return EudiWalletKitAdapter(
                wallet: wallet,
                operationalConfiguration: operationalConfiguration,
                trustProfileID: trustProfileID
            )
        } catch {
            throw EudiWalletKitAdapterError.initializationFailed
        }
    }

    private static func compatibilityTrustConfiguration(anchors: [Data]) -> TrustConfiguration {
        #if canImport(EudiEtsi1196x2)
        TrustConfiguration(
            trustSource: .staticList(StaticListTrustSource(rootCertificates: anchors)),
            defaultPolicy: .warning,
            requireSignedMetadata: false,
            statusTrustPolicy: .warning
        )
        #else
        TrustConfiguration(
            rootIaca: [anchors],
            defaultPolicy: .warning,
            requireSignedMetadata: false,
            statusTrustPolicy: .warning
        )
        #endif
    }
}

public protocol EudiWalletAttestationProviding: Sendable {
    func walletAttestation(publicJWK: String) async throws -> String
    func keyAttestation(publicJWKs: [String], nonce: String?) async throws -> String
}

public struct EudiHTTPResponse: Equatable, Sendable {
    public let body: Data
    public let statusCode: Int
    public let headers: [String: String]

    public init(body: Data, statusCode: Int, headers: [String: String] = [:]) {
        self.body = body
        self.statusCode = statusCode
        self.headers = headers
    }
}

public protocol EudiNetworkTransport: Sendable {
    func data(for request: URLRequest) async throws -> EudiHTTPResponse
}

public protocol EudiCredentialStatusProviding: Sendable {
    func status(for document: EudiWalletDocumentSummary) async throws -> CredentialStatusState
}

public struct EudiOperationalConfiguration: Sendable {
    public let clientID: String
    public let authorizationRedirectURI: URL
    public let attestationProvider: any EudiWalletAttestationProviding
    public let auditRepository: any AuditRepository
    public let auditPolicy: AuditPolicy
    public let auditPolicyVersion: AuditPolicyVersion
    public let metadataRepository: any CredentialMetadataRepository
    public let recoveryStore: any WalletOperationRecoveryStore
    public let statusProvider: any EudiCredentialStatusProviding
    public let allowedIssuerOrigins: Set<String>
    public let allowedVerifierOrigins: Set<String>
    public let networkTransport: (any EudiNetworkTransport)?
    public let allowUnregisteredDevelopmentCounterparties: Bool

    public init(
        clientID: String,
        authorizationRedirectURI: URL,
        attestationProvider: any EudiWalletAttestationProviding,
        auditRepository: any AuditRepository,
        auditPolicy: AuditPolicy,
        auditPolicyVersion: AuditPolicyVersion,
        metadataRepository: any CredentialMetadataRepository,
        recoveryStore: any WalletOperationRecoveryStore,
        statusProvider: any EudiCredentialStatusProviding,
        allowedIssuerOrigins: Set<String>,
        allowedVerifierOrigins: Set<String>,
        allowedApplicationRedirectOrigins: Set<String>,
        networkTransport: (any EudiNetworkTransport)? = nil,
        allowUnregisteredDevelopmentCounterparties: Bool = true // keep this for development
    ) throws {
        let clientID = clientID.trimmingCharacters(in: .whitespacesAndNewlines)
        let allowedIssuerOrigins = try Self.validatedOrigins(allowedIssuerOrigins)
        let allowedVerifierOrigins = try Self.validatedOrigins(allowedVerifierOrigins)
        let allowedApplicationRedirectOrigins = try Self.validatedOrigins(allowedApplicationRedirectOrigins)
        let isReferenceDemoRedirect = authorizationRedirectURI.absoluteString ==
            "eu.europa.ec.euidi://authorization"
        let redirectOrigin = try? EudiWalletKitAdapter.canonicalHTTPSOrigin(
            authorizationRedirectURI.absoluteString, requireOriginOnly: false
        )
        guard !clientID.isEmpty,
              (isReferenceDemoRedirect || (
                authorizationRedirectURI.scheme?.lowercased() == "https" &&
                redirectOrigin.map(allowedApplicationRedirectOrigins.contains) == true &&
                authorizationRedirectURI.host != nil &&
                authorizationRedirectURI.path == "/oauth/callback"
              )),
              authorizationRedirectURI.user == nil,
              authorizationRedirectURI.password == nil,
              authorizationRedirectURI.port == nil,
              authorizationRedirectURI.query == nil,
              authorizationRedirectURI.fragment == nil else {
            throw EudiWalletKitAdapterError.invalidOperationalConfiguration
        }
        self.clientID = clientID
        self.authorizationRedirectURI = authorizationRedirectURI
        self.attestationProvider = attestationProvider
        self.auditRepository = auditRepository
        self.auditPolicy = auditPolicy
        self.auditPolicyVersion = auditPolicyVersion
        self.metadataRepository = metadataRepository
        self.recoveryStore = recoveryStore
        self.statusProvider = statusProvider
        self.allowedIssuerOrigins = allowedIssuerOrigins
        self.allowedVerifierOrigins = allowedVerifierOrigins
        self.networkTransport = networkTransport
        self.allowUnregisteredDevelopmentCounterparties = allowUnregisteredDevelopmentCounterparties
    }

    private static func validatedOrigins(_ origins: Set<String>) throws -> Set<String> {
        let canonical = try Set(origins.map { try EudiWalletKitAdapter.canonicalHTTPSOrigin($0) })
        guard !canonical.isEmpty, canonical.count == origins.count else {
            throw EudiWalletKitAdapterError.invalidOperationalConfiguration
        }
        return canonical
    }

    public func validateIssuanceOfferURI(_ value: String) throws -> String {
        if allowUnregisteredDevelopmentCounterparties {
            return try EudiWalletKitAdapter.validatedOfferURI(value, allowedOrigins: ["*"])
        }
        return try EudiWalletKitAdapter.validatedOfferURI(value, allowedOrigins: allowedIssuerOrigins)
    }

    public func validatePresentationRequestURI(_ value: String) throws -> String {
        if allowUnregisteredDevelopmentCounterparties {
            return try EudiWalletKitAdapter.validatedPresentationURI(value, allowedOrigins: ["*"])
        }
        return try EudiWalletKitAdapter.validatedPresentationURI(value, allowedOrigins: allowedVerifierOrigins)
    }

    public func validatePendingIssuancePresentationURI(_ value: String) throws -> String {
        guard let components = URLComponents(string: value), let scheme = components.scheme?.lowercased() else {
            throw EudiWalletKitAdapterError.invalidPresentationURI
        }
        if scheme == "https" {
            _ = try EudiWalletKitAdapter.canonicalHTTPSOrigin(value, requireOriginOnly: false)
            let origin = try EudiWalletKitAdapter.canonicalHTTPSOrigin(value, requireOriginOnly: false)
            guard allowUnregisteredDevelopmentCounterparties || allowedIssuerOrigins.contains(origin) else {
                throw EudiWalletKitAdapterError.unapprovedIssuer
            }
            return value
        }
        return try EudiWalletKitAdapter.validatedPresentationURI(
            value,
            allowedOrigins: allowUnregisteredDevelopmentCounterparties ? ["*"] : allowedVerifierOrigins
        )
    }
}

public struct EudiWalletAttestationsProviderAdapter: WalletAttestationsProvider {
    private let provider: any EudiWalletAttestationProviding

    public init(provider: any EudiWalletAttestationProviding) {
        self.provider = provider
    }

    public func getWalletAttestation(signingKey: SigningKeyProxy) async throws -> String {
        let publicKey: any JWK
        switch signingKey {
        case .custom(let signer): publicKey = signer.publicKey
        case .secKey(let key):
            guard let secPublicKey = SecKeyCopyPublicKey(key) else {
                throw EudiWalletKitAdapterError.attestationEncodingFailed
            }
            publicKey = try ECPublicKey(publicKey: secPublicKey)
        }
        guard let encoded = publicKey.jsonString() else {
            throw EudiWalletKitAdapterError.attestationEncodingFailed
        }
        return try await provider.walletAttestation(publicJWK: encoded)
    }

    public func getKeysAttestation(keys: [any JWK], nonce: String?) async throws -> String {
        let encoded = try keys.map {
            guard let value = $0.jsonString() else {
                throw EudiWalletKitAdapterError.attestationEncodingFailed
            }
            return value
        }
        return try await provider.keyAttestation(publicJWKs: encoded, nonce: nonce)
    }
}

private struct EudiNetworkingBridge: NetworkingProtocol {
    let transport: (any EudiNetworkTransport)?
    let issuerOrigins: Set<String>
    let verifierOrigins: Set<String>

    init(_ configuration: EudiOperationalConfiguration) {
        transport = configuration.networkTransport
        issuerOrigins = configuration.allowUnregisteredDevelopmentCounterparties ? ["*"] : configuration.allowedIssuerOrigins
        verifierOrigins = configuration.allowUnregisteredDevelopmentCounterparties ? ["*"] : configuration.allowedVerifierOrigins
    }

    func data(from url: URL) async throws -> (Data, URLResponse) {
        try await data(for: URLRequest(url: url))
    }

    func data(for request: URLRequest) async throws -> (Data, URLResponse) {
        guard let url = request.url else {
            throw EudiWalletKitAdapterError.invalidNetworkRequest
        }
        let origin = try EudiWalletKitAdapter.canonicalHTTPSOrigin(url.absoluteString, requireOriginOnly: false)
        let permittedOrigins: Set<String>
        switch EudiNetworkScope.current {
        case .issuance: permittedOrigins = issuerOrigins
        case .presentation: permittedOrigins = verifierOrigins
        case .presentationDuringIssuance: permittedOrigins = issuerOrigins.union(verifierOrigins)
        case nil: throw EudiWalletKitAdapterError.missingNetworkFlowContext
        }
        guard permittedOrigins.contains("*") || permittedOrigins.contains(origin) else {
            throw EudiWalletKitAdapterError.unapprovedNetworkDestination
        }
        let result: EudiHTTPResponse
        if let transport {
            result = try await transport.data(for: request)
        } else {
            let (body, response) = try await EudiRedirectRejectingSession.shared.data(for: request)
            guard let http = response as? HTTPURLResponse else {
                throw EudiWalletKitAdapterError.invalidNetworkResponse
            }
            result = EudiHTTPResponse(
                body: body,
                statusCode: http.statusCode,
                headers: http.allHeaderFields.reduce(into: [:]) { partial, entry in
                    partial[String(describing: entry.key)] = String(describing: entry.value)
                }
            )
        }
        guard (100...599).contains(result.statusCode),
              !(300...399).contains(result.statusCode),
              let response = HTTPURLResponse(
                url: url,
                statusCode: result.statusCode,
                httpVersion: "HTTP/1.1",
                headerFields: result.headers
              ) else {
            throw EudiWalletKitAdapterError.invalidNetworkResponse
        }
        return (result.body, response)
    }
}

private enum EudiNetworkFlow: Sendable {
    case issuance
    case presentation
    case presentationDuringIssuance
}

private enum EudiNetworkScope {
    @TaskLocal static var current: EudiNetworkFlow?
}

private final class EudiRedirectRejectingDelegate: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
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

private enum EudiRedirectRejectingSession {
    static let shared: URLSession = {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.urlCache = nil
        configuration.httpShouldSetCookies = false
        return URLSession(
            configuration: configuration,
            delegate: EudiRedirectRejectingDelegate(),
            delegateQueue: nil
        )
    }()
}

/// A profile-bound, digest-pinned trust input populated only from an
/// authenticated trust-list/configuration boundary.
public struct EudiTrustAnchorSource: Equatable, Sendable {
    public let profileID: String
    private let anchors: [Data]
    private let approvedSHA256Digests: Set<String>

    public init(
        profileID: String,
        anchors: [Data],
        approvedSHA256Digests: Set<String>
    ) throws {
        let profileID = profileID.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !profileID.isEmpty else {
            throw EudiWalletKitAdapterError.invalidTrustSource
        }
        guard !anchors.isEmpty else {
            throw EudiWalletKitAdapterError.missingTrustAnchors
        }
        guard approvedSHA256Digests.count == anchors.count,
              approvedSHA256Digests.allSatisfy(Self.isCanonicalDigest) else {
            throw EudiWalletKitAdapterError.invalidTrustSource
        }
        self.profileID = profileID
        self.anchors = anchors
        self.approvedSHA256Digests = approvedSHA256Digests
    }

    public static func sha256Digest(of anchor: Data) -> String {
        SHA256.hash(data: anchor).map { String(format: "%02x", $0) }.joined()
    }

    fileprivate func validatedAnchors(at date: Date) throws -> [Data] {
        for anchor in anchors {
            let digest = Self.sha256Digest(of: anchor)
            guard approvedSHA256Digests.contains(digest) else {
                throw EudiWalletKitAdapterError.unapprovedTrustAnchor
            }
            let certificate: Certificate
            do {
                certificate = try Certificate(derEncoded: Array(anchor))
            } catch {
                throw EudiWalletKitAdapterError.invalidTrustAnchor
            }
            guard case .isCertificateAuthority = try? certificate.extensions.basicConstraints else {
                throw EudiWalletKitAdapterError.invalidTrustAnchor
            }
            if let keyUsage = try? certificate.extensions.keyUsage,
               !keyUsage.keyCertSign {
                throw EudiWalletKitAdapterError.invalidTrustAnchor
            }
            guard certificate.notValidBefore <= date, date <= certificate.notValidAfter else {
                throw EudiWalletKitAdapterError.invalidTrustAnchor
            }
        }
        return anchors
    }

    private static func isCanonicalDigest(_ value: String) -> Bool {
        value.count == 64 && value.utf8.allSatisfy {
            (48...57).contains($0) || (97...102).contains($0)
        }
    }
}

public struct EudiWalletDocumentSummary: Equatable, Sendable {
    public let id: String
    public let documentType: String
    public let displayName: String?
    public let format: String
    public let status: String
    public let configurationID: String?
    public let issuerIdentifier: String?
    public let display: CredentialDisplayMetadata?
    public let validFrom: Date?
    public let validUntil: Date?

    public init(
        id: String,
        documentType: String,
        displayName: String?,
        format: String,
        status: String,
        configurationID: String? = nil,
        issuerIdentifier: String? = nil,
        display: CredentialDisplayMetadata? = nil,
        validFrom: Date? = nil,
        validUntil: Date? = nil
    ) {
        self.id = id
        self.documentType = documentType
        self.displayName = displayName
        self.format = format
        self.status = status
        self.configurationID = configurationID
        self.issuerIdentifier = issuerIdentifier
        self.display = display
        self.validFrom = validFrom
        self.validUntil = validUntil
    }
}

public struct EudiWalletStartupSnapshot: Equatable, Sendable {
    public let metadata: [CredentialRecord]
    public let documents: [EudiWalletDocumentSummary]
    public let pendingIssuances: [EudiPendingIssuance]

    public init(
        metadata: [CredentialRecord],
        documents: [EudiWalletDocumentSummary],
        pendingIssuances: [EudiPendingIssuance]
    ) {
        self.metadata = metadata
        self.documents = documents
        self.pendingIssuances = pendingIssuances
    }
}

public struct EudiIssuanceOfferDisplay: Equatable, Sendable {
    public let description: String?
    public let backgroundColor: String?
    public let textColor: String?
    public let logoURL: URL?
    public let logoAlternativeText: String?
    public let backgroundImageURL: URL?
}

public struct EudiIssuanceOfferDocument: Equatable, Sendable {
    public let configurationID: String
    public let documentType: String
    public let displayName: String
    public let supportedAlgorithms: [String]
    public let display: EudiIssuanceOfferDisplay?

    public init(
        configurationID: String,
        documentType: String,
        displayName: String,
        supportedAlgorithms: [String],
        display: EudiIssuanceOfferDisplay? = nil
    ) {
        self.configurationID = configurationID
        self.documentType = documentType
        self.displayName = displayName
        self.supportedAlgorithms = supportedAlgorithms
        self.display = display
    }
}

public struct EudiTransactionCodeRequirement: Equatable, Sendable {
    public let inputMode: String
    public let length: Int?
    public let displayDescription: String?

    public init(inputMode: String, length: Int?, displayDescription: String?) {
        self.inputMode = inputMode
        self.length = length
        self.displayDescription = displayDescription
    }

    public func accepts(_ value: String) -> Bool {
        guard !value.isEmpty,
              length.map({ value.count == $0 }) ?? true else { return false }
        switch inputMode {
        case "numeric": return value.allSatisfy { $0.isASCII && $0.isNumber }
        case "text": return value.allSatisfy { !$0.isWhitespace && !$0.isNewline }
        default: return false
        }
    }
}

public struct EudiIssuanceOffer: Equatable, Sendable {
    public let id: UUID
    public let issuerName: String
    public let issuerURL: URL?
    public let issuerLogoURL: URL?
    public let documents: [EudiIssuanceOfferDocument]
    public let transactionCode: EudiTransactionCodeRequirement?

    public init(
        id: UUID,
        issuerName: String,
        issuerURL: URL? = nil,
        issuerLogoURL: URL?,
        documents: [EudiIssuanceOfferDocument],
        transactionCode: EudiTransactionCodeRequirement?
    ) {
        self.id = id
        self.issuerName = issuerName
        self.issuerURL = issuerURL
        self.issuerLogoURL = issuerLogoURL
        self.documents = documents
        self.transactionCode = transactionCode
    }
}

public struct EudiIssuanceResult: Equatable, Sendable {
    public let documents: [EudiWalletDocumentSummary]
    public let metadata: [CredentialRecord]
    public let warningCount: Int
    public let pendingIssuances: [EudiPendingIssuance]

    public init(
        documents: [EudiWalletDocumentSummary],
        metadata: [CredentialRecord],
        warningCount: Int,
        pendingIssuances: [EudiPendingIssuance]
    ) {
        self.documents = documents
        self.metadata = metadata
        self.warningCount = warningCount
        self.pendingIssuances = pendingIssuances
    }
}

public struct EudiPendingIssuance: Equatable, Identifiable, Sendable {
    public let id: UUID
    public let document: EudiWalletDocumentSummary

    public init(id: UUID, document: EudiWalletDocumentSummary) {
        self.id = id
        self.document = document
    }
}

public struct EudiRequestedClaim: Equatable, Sendable {
    public let id: String
    public let documentID: String
    public let documentType: String
    public let displayName: String?
    public let claimPath: [String]
    public let displayValue: String?
    public let required: Bool
    public let intentToRetain: Bool

    public init(
        id: String,
        documentID: String,
        documentType: String,
        displayName: String?,
        claimPath: [String],
        displayValue: String?,
        required: Bool,
        intentToRetain: Bool
    ) {
        self.id = id
        self.documentID = documentID
        self.documentType = documentType
        self.displayName = displayName
        self.claimPath = claimPath
        self.displayValue = displayValue
        self.required = required
        self.intentToRetain = intentToRetain
    }
}

public indirect enum EudiTransactionDataValue: Equatable, Sendable {
    case string(String)
    case number(String)
    case bool(Bool)
    case object([String: EudiTransactionDataValue])
    case array([EudiTransactionDataValue])
    case null
}

/// A structured field from a verifier-supplied transaction data object.
public struct EudiTransactionDataField: Equatable, Identifiable, Sendable {
    public let id: String
    public let key: String
    public let value: EudiTransactionDataValue

    public init(id: String, key: String, value: EudiTransactionDataValue) {
        self.id = id
        self.key = key
        self.value = value
    }
}

/// A lossless presentation of verifier-supplied transaction data for consent UI.
public struct EudiTransactionDataPresentation: Equatable, Identifiable, Sendable {
    public let id: String
    public let type: String
    public let title: String
    public let purpose: String?
    public let credentialIDs: [String]
    public let reference: String?
    public let fields: [EudiTransactionDataField]

    public init(
        id: String,
        type: String,
        title: String,
        purpose: String? = nil,
        credentialIDs: [String] = [],
        reference: String? = nil,
        fields: [EudiTransactionDataField] = []
    ) {
        self.id = id
        self.type = type
        self.title = title
        self.purpose = purpose
        self.credentialIDs = credentialIDs
        self.reference = reference
        self.fields = fields
    }
}

public struct EudiPresentationCredential: Equatable, Identifiable, Sendable {
    public let id: String
    public let displayName: String
    public let issuerIdentifier: String?
    public let configurationID: String?
    public let format: CredentialFormat
    public let profileID: String
    public let representation: String
    public let receivedAt: Date
    public let display: CredentialDisplayMetadata?

    public init(
        id: String,
        displayName: String,
        issuerIdentifier: String? = nil,
        configurationID: String? = nil,
        format: CredentialFormat,
        profileID: String,
        representation: String,
        receivedAt: Date,
        display: CredentialDisplayMetadata? = nil
    ) {
        self.id = id
        self.displayName = displayName
        self.issuerIdentifier = issuerIdentifier
        self.configurationID = configurationID
        self.format = format
        self.profileID = profileID
        self.representation = representation
        self.receivedAt = receivedAt
        self.display = display
    }
}

public struct EudiPresentationOption: Equatable, Identifiable, Sendable {
    public let id: String
    public let credentialIDs: [String]
    public let claims: [EudiRequestedClaim]

    public init(id: String, credentialIDs: [String], claims: [EudiRequestedClaim]) {
        self.id = id
        self.credentialIDs = credentialIDs
        self.claims = claims
    }
}

public struct EudiPresentationRequest: Equatable, Sendable {
    public let id: UUID
    public let verifierName: String?
    public let verifierLegalName: String?
    public let verifierCertificateValid: Bool?
    public let claims: [EudiRequestedClaim]
    public let warningCount: Int
    /// Verifier-supplied transaction data prepared for native consent UI.
    public let transactionData: [EudiTransactionDataPresentation]
    public let credentials: [EudiPresentationCredential]
    public let options: [EudiPresentationOption]

    public init(
        id: UUID,
        verifierName: String?,
        verifierLegalName: String?,
        verifierCertificateValid: Bool?,
        claims: [EudiRequestedClaim],
        warningCount: Int,
        transactionData: [EudiTransactionDataPresentation] = [],
        credentials: [EudiPresentationCredential] = [],
        options: [EudiPresentationOption] = []
    ) {
        self.id = id
        self.verifierName = verifierName
        self.verifierLegalName = verifierLegalName
        self.verifierCertificateValid = verifierCertificateValid
        self.claims = claims
        self.warningCount = warningCount
        self.transactionData = transactionData
        self.credentials = credentials
        self.options = options
    }
}

public struct EudiBLEEngagement: Equatable, Sendable {
    public let id: UUID
    public let qrEngagement: String
}

public struct EudiPresentationResult: Equatable, Sendable {
    let redirectURI: URL?
    public let disclosedDocumentIDs: [String]
    public let pendingIssuanceID: UUID?
    public let userAccepted: Bool
    public let authorizationCode: String?
}

enum EudiPendingIssuancePolicy {
    static func nextPresentationURI(status: String, candidate: String?) throws -> String? {
        switch status {
        case "issued": return nil
        case "pending":
            guard let candidate, !candidate.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                throw EudiWalletKitAdapterError.invalidPendingIssuance
            }
            return candidate
        default: throw EudiWalletKitAdapterError.unexpectedPendingIssuanceStatus
        }
    }

    static func recoveryReferences(
        originalDocumentID: String,
        resumedDocumentID: String,
        resumedStatus: String
    ) -> [WalletDocumentRecoveryReference] {
        var references = [WalletDocumentRecoveryReference(
            id: originalDocumentID,
            status: "pending"
        )]
        if resumedDocumentID != originalDocumentID {
            references.append(WalletDocumentRecoveryReference(
                id: resumedDocumentID,
                status: resumedStatus
            ))
        }
        return references
    }

    static func mergeObservedRecoveryReferences(
        affected: [WalletDocumentRecoveryReference],
        newlyCreated: [WalletDocumentRecoveryReference],
        changedOriginal: WalletDocumentRecoveryReference?
    ) -> [WalletDocumentRecoveryReference] {
        let candidates = (changedOriginal.map { [$0] } ?? []) + affected + newlyCreated
        var seenDocumentIDs: Set<String> = []
        return candidates.filter { seenDocumentIDs.insert($0.id).inserted }
    }
}

actor EudiOperationalState {
    struct ResolvedOffer: Sendable {
        let uri: String
        let model: OfferedIssuanceModel
        let createdAt: Date
    }

    struct ActivePresentation: Sendable {
        let session: PresentationSession
        let requester: String?
        let pendingIssuanceID: UUID?
        let options: [EudiPresentationOption]
        let createdAt: Date
    }

    struct PendingIssuance: Sendable {
        let documentID: String
        let issuerName: String
        let profileID: String
        let metadataCredentialID: CredentialID
        let presentationRequestURI: String
        let createdAt: Date
    }

    private var offers: [UUID: ResolvedOffer] = [:]
    private var presentations: [UUID: ActivePresentation] = [:]
    private var pendingIssuances: [UUID: PendingIssuance] = [:]
    private var lifecycleOperationInProgress = false
    private let maximumEntries = 16
    private let lifetime: TimeInterval = 600

    func performLifecycleOperation<T: Sendable>(
        _ operation: @Sendable () async throws -> T
    ) async throws -> T {
        guard !lifecycleOperationInProgress else {
            throw EudiWalletKitAdapterError.lifecycleOperationInProgress
        }
        lifecycleOperationInProgress = true
        defer { lifecycleOperationInProgress = false }
        return try await operation()
    }

    func insert(uri: String, model: OfferedIssuanceModel) -> UUID {
        prune()
        if offers.count >= maximumEntries, let oldest = offers.min(by: { $0.value.createdAt < $1.value.createdAt })?.key {
            offers.removeValue(forKey: oldest)
        }
        let id = UUID()
        offers[id] = ResolvedOffer(uri: uri, model: model, createdAt: Date())
        return id
    }

    func consume(id: UUID) -> ResolvedOffer? {
        offers.removeValue(forKey: id)
    }

    func offer(id: UUID) -> ResolvedOffer? { prune(); return offers[id] }

    func insert(
        session: PresentationSession,
        requester: String?,
        pendingIssuanceID: UUID? = nil
        , options: [EudiPresentationOption] = []
    ) -> UUID {
        prune()
        if presentations.count >= maximumEntries, let oldest = presentations.min(by: { $0.value.createdAt < $1.value.createdAt })?.key {
            presentations.removeValue(forKey: oldest)
        }
        let id = UUID()
        presentations[id] = ActivePresentation(
            session: session,
            requester: requester,
            pendingIssuanceID: pendingIssuanceID,
            options: options,
            createdAt: Date()
        )
        return id
    }

    func presentation(id: UUID) -> ActivePresentation? { prune(); return presentations[id] }

    func consumePresentation(id: UUID) -> ActivePresentation? {
        presentations.removeValue(forKey: id)
    }

    func setRequester(id: UUID, requester: String?) {
        guard let entry = presentations[id] else { return }
        presentations[id] = ActivePresentation(
            session: entry.session,
            requester: requester,
            pendingIssuanceID: entry.pendingIssuanceID,
            options: entry.options,
            createdAt: entry.createdAt
        )
    }

    func setOptions(id: UUID, options: [EudiPresentationOption]) {
        guard let entry = presentations[id] else { return }
        presentations[id] = ActivePresentation(
            session: entry.session,
            requester: entry.requester,
            pendingIssuanceID: entry.pendingIssuanceID,
            options: options,
            createdAt: entry.createdAt
        )
    }

    func upsertPending(
        documentID: String,
        issuerName: String,
        profileID: String,
        metadataCredentialID: CredentialID,
        presentationRequestURI: String
    ) -> UUID {
        prune()
        if let existing = pendingIssuances.first(where: { $0.value.documentID == documentID })?.key {
            pendingIssuances[existing] = PendingIssuance(
                documentID: documentID,
                issuerName: issuerName,
                profileID: profileID,
                metadataCredentialID: metadataCredentialID,
                presentationRequestURI: presentationRequestURI,
                createdAt: Date()
            )
            return existing
        }
        if pendingIssuances.count >= maximumEntries,
           let oldest = pendingIssuances.min(by: { $0.value.createdAt < $1.value.createdAt })?.key {
            pendingIssuances.removeValue(forKey: oldest)
        }
        let id = UUID()
        pendingIssuances[id] = PendingIssuance(
            documentID: documentID,
            issuerName: issuerName,
            profileID: profileID,
            metadataCredentialID: metadataCredentialID,
            presentationRequestURI: presentationRequestURI,
            createdAt: Date()
        )
        return id
    }

    func pending(id: UUID) -> PendingIssuance? { prune(); return pendingIssuances[id] }
    func replacePending(
        id: UUID,
        documentID: String,
        issuerName: String,
        profileID: String,
        metadataCredentialID: CredentialID,
        presentationRequestURI: String
    ) {
        pendingIssuances[id] = PendingIssuance(
            documentID: documentID,
            issuerName: issuerName,
            profileID: profileID,
            metadataCredentialID: metadataCredentialID,
            presentationRequestURI: presentationRequestURI,
            createdAt: Date()
        )
    }
    func removePending(id: UUID) { pendingIssuances[id] = nil }

    private func prune() {
        let cutoff = Date().addingTimeInterval(-lifetime)
        offers = offers.filter { $0.value.createdAt >= cutoff }
        presentations = presentations.filter { $0.value.createdAt >= cutoff }
        pendingIssuances = pendingIssuances.filter { $0.value.createdAt >= cutoff }
    }
}

public final class EudiWalletKitAdapter: @unchecked Sendable {
    private let wallet: EudiWallet
    private let operationalConfiguration: EudiOperationalConfiguration?
    public let trustProfileID: String
    private let operationalState = EudiOperationalState()

    init(
        wallet: EudiWallet,
        operationalConfiguration: EudiOperationalConfiguration?,
        trustProfileID: String
    ) {
        self.wallet = wallet
        self.operationalConfiguration = operationalConfiguration
        self.trustProfileID = trustProfileID
    }

    public func loadDocumentSummaries() async throws -> [EudiWalletDocumentSummary] {
        try await operationalState.performLifecycleOperation { [self] in
            try await loadDocumentSummariesUnlocked()
        }
    }

    public func loadStartupSnapshot() async throws -> EudiWalletStartupSnapshot {
        try await operationalState.performLifecycleOperation { [self] in
            let configuration = try requireOperationalConfiguration()
            try await reconcilePendingOperationsUnlocked()
            async let metadataTask = configuration.metadataRepository.credentials()
            async let documentsTask = wallet.loadAllDocuments()
            var metadata = try await metadataTask
            let documents = try await documentsTask ?? []
            let summaries = documents.map { document in
                let display = Self.storedDisplayMetadata(from: document.metadata)
                let claims = StorageManager.toClaimsModel(
                    doc: document,
                    uiCulture: wallet.eudiWalletConfig.uiCulture,
                    modelFactory: wallet.modelFactory
                )
                return EudiWalletDocumentSummary(
                    id: document.id,
                    documentType: document.docType,
                    displayName: document.displayName,
                    format: document.docDataFormat.rawValue,
                    status: document.status.rawValue,
                    configurationID: display?.configurationID,
                    issuerIdentifier: display?.issuerIdentifier,
                    display: display?.display,
                    validFrom: claims?.validFrom,
                    validUntil: claims?.validUntil
                )
            }
            let summariesByID = Dictionary(summaries.map { ($0.id, $0) }, uniquingKeysWith: { first, _ in first })
            for index in metadata.indices {
                let record = metadata[index]
                guard let documentID = record.walletDocumentID,
                      let summary = summariesByID[documentID] else { continue }
                let validFrom = record.validFrom ?? summary.validFrom
                let validUntil = record.validUntil ?? summary.validUntil
                guard validFrom != record.validFrom || validUntil != record.validUntil else { continue }
                let updated = Self.copy(record, validFrom: validFrom, validUntil: validUntil)
                try? await configuration.metadataRepository.replaceMetadata(updated)
                metadata[index] = updated
            }
            var pending: [EudiPendingIssuance] = []
            for document in documents where document.status == .pending {
                let claims = StorageManager.toClaimsModel(
                    doc: document,
                    uiCulture: wallet.eudiWalletConfig.uiCulture,
                    modelFactory: wallet.modelFactory
                )
                guard let requestURI = document.authorizePresentationUrl,
                      let record = metadata.first(where: { $0.walletDocumentID == document.id }) else {
                    throw EudiWalletKitAdapterError.invalidPendingIssuance
                }
                let id = await operationalState.upsertPending(
                    documentID: document.id,
                    issuerName: record.issuerIdentifier,
                    profileID: record.profileID,
                    metadataCredentialID: record.id,
                    presentationRequestURI: requestURI
                )
                pending.append(EudiPendingIssuance(
                    id: id,
                    document: EudiWalletDocumentSummary(
                        id: document.id,
                        documentType: document.docType,
                        displayName: document.displayName,
                        format: document.docDataFormat.rawValue,
                        status: document.status.rawValue,
                        configurationID: record.configurationID,
                        issuerIdentifier: record.issuerIdentifier,
                        display: record.display,
                        validFrom: claims?.validFrom,
                        validUntil: claims?.validUntil
                    )
                ))
            }
            return EudiWalletStartupSnapshot(
                metadata: metadata,
                documents: summaries,
                pendingIssuances: pending
            )
        }
    }

    private func loadDocumentSummariesUnlocked() async throws -> [EudiWalletDocumentSummary] {
        if operationalConfiguration != nil { try await reconcilePendingOperationsUnlocked() }
        let documents = try await wallet.loadAllDocuments() ?? []
        return documents.map { document in
            let display = Self.storedDisplayMetadata(from: document.metadata)
            let claims = StorageManager.toClaimsModel(
                doc: document,
                uiCulture: wallet.eudiWalletConfig.uiCulture,
                modelFactory: wallet.modelFactory
            )
            return EudiWalletDocumentSummary(
                id: document.id,
                documentType: document.docType,
                displayName: document.displayName,
                format: document.docDataFormat.rawValue,
                status: document.status.rawValue,
                configurationID: display?.configurationID,
                issuerIdentifier: display?.issuerIdentifier,
                display: display?.display,
                validFrom: claims?.validFrom,
                validUntil: claims?.validUntil
            )
        }
    }

    public func deleteAllDocuments() async throws {
        try await operationalState.performLifecycleOperation { [self] in
            try await deleteAllDocumentsUnlocked()
        }
    }

    private func deleteAllDocumentsUnlocked() async throws {
        let configuration = try requireOperationalConfiguration()
        try await reconcilePendingOperationsUnlocked()
        let documents = try await wallet.loadAllDocuments() ?? []
        let metadata = try await configuration.metadataRepository.credentials()
        let deletionEvent = makeAuditEvent(
            configuration: configuration,
            operation: .credentialDeletion,
            outcome: .completed,
            counterparty: nil,
            disclosedClaimIDs: [],
            credentialIDs: metadata.compactMap { $0.walletDocumentID == nil ? nil : $0.id }
        )
        var recovery = WalletOperationRecovery(
            kind: .deletion,
            affectedDocuments: documents.map {
                WalletDocumentRecoveryReference(id: $0.id, status: $0.status.rawValue)
            },
            metadataCredentialIDs: metadata.compactMap {
                $0.walletDocumentID == nil ? nil : $0.id
            },
            pendingAuditEvent: deletionEvent
        )
        do {
            try await configuration.recoveryStore.saveRecovery(recovery)
            for document in documents {
                try await deleteSDKDocument(id: document.id, status: document.status.rawValue)
            }
            for record in metadata where record.walletDocumentID != nil {
                try await configuration.metadataRepository.deleteMetadata(id: record.id)
            }
            recovery = WalletOperationRecovery(
                id: recovery.id,
                kind: .deletion,
                affectedDocuments: recovery.affectedDocuments,
                metadataCredentialIDs: recovery.metadataCredentialIDs,
                metadataCommitted: true,
                pendingAuditEvent: deletionEvent,
                createdAt: recovery.createdAt
            )
            try await configuration.recoveryStore.replaceRecovery(recovery)
            try await configuration.auditRepository.append(deletionEvent)
            try await configuration.recoveryStore.deleteRecovery(id: recovery.id)
        } catch {
            do { try await reconcilePendingOperationsUnlocked() } catch {
                throw EudiWalletKitAdapterError.recoveryRequired
            }
            throw EudiWalletKitAdapterError.documentDeletionFailed
        }
    }

    public func deleteDocument(id: String, status: String) async throws {
        try await operationalState.performLifecycleOperation { [self] in
            try await deleteDocumentUnlocked(id: id, status: status)
        }
    }

    private func deleteDocumentUnlocked(id: String, status: String) async throws {
        let configuration = try requireOperationalConfiguration()
        try await reconcilePendingOperationsUnlocked()
        guard !id.isEmpty else { throw EudiWalletKitAdapterError.invalidDocumentReference }
        let document = try await (wallet.loadAllDocuments() ?? []).first(where: { $0.id == id })
        let metadata = try await configuration.metadataRepository.credentials().first {
            $0.walletDocumentID == id
        }
        guard document != nil || metadata != nil else {
            throw EudiWalletKitAdapterError.invalidDocumentReference
        }
        let actualStatus = document?.status.rawValue ?? status
        let deletionEvent = makeAuditEvent(
            configuration: configuration,
            operation: .credentialDeletion,
            outcome: .completed,
            counterparty: nil,
            disclosedClaimIDs: [],
            credentialIDs: metadata.map { [$0.id] } ?? []
        )
        var recovery = WalletOperationRecovery(
            kind: .deletion,
            affectedDocuments: [WalletDocumentRecoveryReference(id: id, status: actualStatus)],
            metadataCredentialIDs: metadata.map { [$0.id] } ?? [],
            pendingAuditEvent: deletionEvent
        )
        do {
            try await configuration.recoveryStore.saveRecovery(recovery)
            if document != nil { try await deleteSDKDocument(id: id, status: actualStatus) }
            if let metadata {
                try await configuration.metadataRepository.deleteMetadata(id: metadata.id)
            }
            recovery = WalletOperationRecovery(
                id: recovery.id,
                kind: .deletion,
                affectedDocuments: recovery.affectedDocuments,
                metadataCredentialIDs: recovery.metadataCredentialIDs,
                metadataCommitted: true,
                pendingAuditEvent: deletionEvent,
                createdAt: recovery.createdAt
            )
            try await configuration.recoveryStore.replaceRecovery(recovery)
            try await configuration.auditRepository.append(deletionEvent)
            try await configuration.recoveryStore.deleteRecovery(id: recovery.id)
        } catch {
            do { try await reconcilePendingOperationsUnlocked() } catch {
                throw EudiWalletKitAdapterError.recoveryRequired
            }
            throw EudiWalletKitAdapterError.documentDeletionFailed
        }
    }

    public func resolveIssuanceOffer(uri: String) async throws -> EudiIssuanceOffer {
        let configuration = try requireOperationalConfiguration()
        let uri = try configuration.validateIssuanceOfferURI(uri)
        let model = try await EudiNetworkScope.$current.withValue(.issuance) {
            try await wallet.resolveOfferUrlDocTypes(
                offerUri: uri,
                authFlowRedirectionURI: configuration.authorizationRedirectURI
            )
        }
        guard !model.docModels.isEmpty else {
            throw EudiWalletKitAdapterError.emptyIssuanceOffer
        }
        let id = await operationalState.insert(uri: uri, model: model)
        let issuerURL = Self.credentialIssuerURL(from: uri)
        return EudiIssuanceOffer(
            id: id,
            issuerName: model.issuerName,
            issuerURL: issuerURL,
            issuerLogoURL: Self.safeDisplayURL(model.issuerLogoUrl, relativeTo: issuerURL),
            documents: model.docModels.map {
                EudiIssuanceOfferDocument(
                    configurationID: $0.credentialConfigurationIdentifier,
                    documentType: $0.docTypeOrVct ?? $0.credentialConfigurationIdentifier,
                    displayName: $0.displayName,
                    supportedAlgorithms: $0.algValuesSupported,
                    display: Self.offerDisplayMetadata(
                        from: $0.credentialMetadata?.display,
                        issuerURL: issuerURL
                    )
                )
            },
            transactionCode: model.txCodeSpec.map {
                EudiTransactionCodeRequirement(
                    inputMode: $0.inputMode.rawValue,
                    length: $0.length,
                    displayDescription: $0.description
                )
            }
        )
    }

    public func issueResolvedOffer(
        id: UUID,
        profileID: String,
        selectedConfigurationIDs: Set<String>,
        transactionCode: String?,
        promptMessage: String
    ) async throws -> EudiIssuanceResult {
        try await operationalState.performLifecycleOperation { [self] in
            try await issueResolvedOfferUnlocked(
                id: id,
                profileID: profileID,
                selectedConfigurationIDs: selectedConfigurationIDs,
                transactionCode: transactionCode,
                promptMessage: promptMessage
            )
        }
    }

    private func issueResolvedOfferUnlocked(
        id: UUID,
        profileID: String,
        selectedConfigurationIDs: Set<String>,
        transactionCode: String?,
        promptMessage: String
    ) async throws -> EudiIssuanceResult {
        let configuration = try requireOperationalConfiguration()
        let prompt = promptMessage.trimmingCharacters(in: .whitespacesAndNewlines)
        let profileID = profileID.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !prompt.isEmpty else { throw EudiWalletKitAdapterError.invalidPrompt }
        guard !profileID.isEmpty, profileID == trustProfileID else {
            throw EudiWalletKitAdapterError.invalidProfile
        }
        guard let offer = await operationalState.offer(id: id) else {
            throw EudiWalletKitAdapterError.unknownOrConsumedOffer
        }
        let selected = offer.model.docModels.filter {
            selectedConfigurationIDs.contains($0.credentialConfigurationIdentifier)
        }
        guard !selected.isEmpty, selected.count == selectedConfigurationIDs.count else {
            throw EudiWalletKitAdapterError.invalidOfferSelection
        }
        if let requirement = offer.model.txCodeSpec {
            let neutralRequirement = EudiTransactionCodeRequirement(
                inputMode: requirement.inputMode.rawValue,
                length: requirement.length,
                displayDescription: requirement.description
            )
            guard let transactionCode, neutralRequirement.accepts(transactionCode) else {
                throw EudiWalletKitAdapterError.invalidTransactionCode
            }
        } else if transactionCode != nil {
            throw EudiWalletKitAdapterError.unexpectedTransactionCode
        }
        guard await operationalState.consume(id: id) != nil else {
            throw EudiWalletKitAdapterError.unknownOrConsumedOffer
        }
        try await reconcilePendingOperationsUnlocked()
        let baselineDocuments = try await wallet.loadAllDocuments() ?? []
        var recovery = WalletOperationRecovery(
            kind: .issuance,
            baselineDocumentIDs: Set(baselineDocuments.map(\.id))
        )
        try await configuration.recoveryStore.saveRecovery(recovery)
        let response = try await { () async throws in
            do {
                return try await EudiNetworkScope.$current.withValue(.issuance) {
                    try await wallet.issueDocumentsByOfferUrl(
                        offerUri: offer.uri,
                        docTypes: selected,
                        txCodeValue: transactionCode,
                        promptMessage: prompt
                    )
                }
            } catch {
                do { try await reconcilePendingOperationsUnlocked() } catch {
                    throw EudiWalletKitAdapterError.recoveryRequired
                }
                throw error
            }
        }()
        let documents = response.documents
        let summaries: [EudiWalletDocumentSummary] = documents.map { document in
            let claims = StorageManager.toClaimsModel(
                doc: document,
                uiCulture: wallet.eudiWalletConfig.uiCulture,
                modelFactory: wallet.modelFactory
            )
            let configurationID = selected.first(where: { offered in
                let matchesType = offered.docTypeOrVct == document.docType
                let matchesConfiguration = offered.credentialConfigurationIdentifier == document.docType
                return matchesType || matchesConfiguration
            })?.credentialConfigurationIdentifier
            return EudiWalletDocumentSummary(
                id: document.id,
                documentType: document.docType,
                displayName: document.displayName,
                format: document.docDataFormat.rawValue,
                status: document.status.rawValue,
                configurationID: configurationID,
                issuerIdentifier: offer.model.issuerName,
                display: Self.storedDisplayMetadata(from: document.metadata)?.display,
                validFrom: claims?.validFrom,
                validUntil: claims?.validUntil
            )
        }
        recovery = WalletOperationRecovery(
            id: recovery.id,
            kind: .issuance,
            baselineDocumentIDs: recovery.baselineDocumentIDs,
            affectedDocuments: summaries.map {
                WalletDocumentRecoveryReference(id: $0.id, status: $0.status)
            },
            createdAt: recovery.createdAt
        )
        do {
            try await configuration.recoveryStore.replaceRecovery(recovery)
        } catch {
            do { try await reconcilePendingOperationsUnlocked() } catch {
                throw EudiWalletKitAdapterError.recoveryRequired
            }
            throw EudiWalletKitAdapterError.metadataPersistenceFailed
        }
        var metadataRecords: [CredentialRecord] = []
        do {
            for summary in summaries {
                let record = try await metadataRecord(summary: summary, profileID: profileID)
                try await configuration.metadataRepository.saveMetadata(record)
                metadataRecords.append(record)
            }
        } catch {
            do { try await reconcilePendingOperationsUnlocked() } catch {
                throw EudiWalletKitAdapterError.recoveryRequired
            }
            throw EudiWalletKitAdapterError.metadataPersistenceFailed
        }
        var pendingIssuances: [EudiPendingIssuance] = []
        for document in documents where document.status == .pending {
            guard let requestURI = document.authorizePresentationUrl,
                  let summary = summaries.first(where: { $0.id == document.id }),
                  let metadata = metadataRecords.first(where: { $0.walletDocumentID == document.id }) else {
                throw EudiWalletKitAdapterError.invalidPendingIssuance
            }
            let pendingID = await operationalState.upsertPending(
                documentID: document.id,
                issuerName: offer.model.issuerName,
                profileID: profileID,
                metadataCredentialID: metadata.id,
                presentationRequestURI: requestURI
            )
            pendingIssuances.append(EudiPendingIssuance(
                id: pendingID,
                document: summary
            ))
        }
        let issuedDocumentIDs = Set(summaries.filter { $0.status == "issued" }.map { $0.id })
        let issuedCredentialIDs = metadataRecords.filter {
            guard let documentID = $0.walletDocumentID else { return false }
            return issuedDocumentIDs.contains(documentID)
        }.map { $0.id }
        let completionEvent = issuedCredentialIDs.isEmpty ? nil : makeAuditEvent(
            configuration: configuration,
            operation: .issuance,
            outcome: .completed,
            counterparty: offer.model.issuerName,
            disclosedClaimIDs: [],
            credentialIDs: issuedCredentialIDs
        )
        recovery = WalletOperationRecovery(
            id: recovery.id,
            kind: .issuance,
            baselineDocumentIDs: recovery.baselineDocumentIDs,
            affectedDocuments: recovery.affectedDocuments,
            metadataCredentialIDs: metadataRecords.map(\.id),
            metadataCommitted: true,
            pendingAuditEvent: completionEvent,
            createdAt: recovery.createdAt
        )
        do {
            try await configuration.recoveryStore.replaceRecovery(recovery)
            if let completionEvent { try await configuration.auditRepository.append(completionEvent) }
            try await configuration.recoveryStore.deleteRecovery(id: recovery.id)
        } catch {
            do { try await reconcilePendingOperationsUnlocked() } catch {
                throw EudiWalletKitAdapterError.recoveryRequired
            }
        }
        let warningCount = response.wrpIssuerWarnings?.values.reduce(0) { $0 + $1.count } ?? 0
        return EudiIssuanceResult(
            documents: summaries,
            metadata: metadataRecords,
            warningCount: warningCount,
            pendingIssuances: pendingIssuances
        )
    }

    /// Completes or rolls back operations that crossed Wallet Kit and application storage
    /// boundary before a process interruption or persistence failure.
    public func reconcilePendingOperations() async throws {
        try await operationalState.performLifecycleOperation { [self] in
            try await reconcilePendingOperationsUnlocked()
        }
    }

    private func reconcilePendingOperationsUnlocked() async throws {
        let configuration = try requireOperationalConfiguration()
        let recoveries: [WalletOperationRecovery]
        do {
            recoveries = try await configuration.recoveryStore.recoveries()
        } catch {
            throw EudiWalletKitAdapterError.recoveryRequired
        }
        guard !recoveries.isEmpty else { return }

        for recovery in recoveries.sorted(by: { $0.createdAt < $1.createdAt }) {
            do {
                switch recovery.kind {
                case .issuance:
                    if !recovery.metadataCommitted {
                        let documents = try await wallet.loadAllDocuments() ?? []
                        let references = recovery.affectedDocuments.isEmpty
                            ? documents.filter { !recovery.baselineDocumentIDs.contains($0.id) }.map {
                                WalletDocumentRecoveryReference(id: $0.id, status: $0.status.rawValue)
                            }
                            : recovery.affectedDocuments
                        for reference in references {
                            if documents.contains(where: { $0.id == reference.id }) {
                                try await deleteSDKDocument(id: reference.id, status: reference.status)
                            }
                            if let metadata = try await configuration.metadataRepository.credentials()
                                .first(where: { $0.walletDocumentID == reference.id }) {
                                try await configuration.metadataRepository.deleteMetadata(id: metadata.id)
                            }
                        }
                    }
                case .deferredIssuance, .pendingIssuance:
                    if !recovery.metadataCommitted {
                        let recoverableStatus = recovery.kind == .deferredIssuance ? "deferred" : "pending"
                        let documents = try await wallet.loadAllDocuments() ?? []
                        let original = recovery.affectedDocuments.first
                        let newlyCreated = documents.filter {
                            !recovery.baselineDocumentIDs.contains($0.id)
                        }.map {
                            WalletDocumentRecoveryReference(id: $0.id, status: $0.status.rawValue)
                        }
                        let changedOriginal = original.flatMap { reference in
                            documents.first(where: {
                                $0.id == reference.id && $0.status.rawValue != recoverableStatus
                            }).map {
                                WalletDocumentRecoveryReference(id: $0.id, status: $0.status.rawValue)
                            }
                        }
                        let pendingTransitionDetected = recovery.kind == .pendingIssuance &&
                            (!newlyCreated.isEmpty || changedOriginal != nil)
                        let candidateReferences = pendingTransitionDetected
                            ? EudiPendingIssuancePolicy.mergeObservedRecoveryReferences(
                                affected: recovery.affectedDocuments,
                                newlyCreated: newlyCreated,
                                changedOriginal: changedOriginal
                            )
                            : recovery.affectedDocuments.first?.status == recoverableStatus
                                ? newlyCreated + (changedOriginal.map { [$0] } ?? [])
                                : recovery.affectedDocuments
                        let references = candidateReferences
                        for reference in references {
                            if documents.contains(where: { $0.id == reference.id }) {
                                try await deleteSDKDocument(id: reference.id, status: reference.status)
                            }
                        }
                        if !references.isEmpty {
                            let existingIDs = Set(try await configuration.metadataRepository.credentials().map(\.id))
                            for id in recovery.metadataCredentialIDs where existingIDs.contains(id) {
                                try await configuration.metadataRepository.deleteMetadata(id: id)
                            }
                        }
                    } else if recovery.kind == .pendingIssuance,
                              let event = recovery.pendingAuditEvent {
                        let existingEventIDs = Set(try await configuration.auditRepository.events().map(\.id))
                        if !existingEventIDs.contains(event.id) {
                            try await configuration.auditRepository.append(event)
                        }
                    }
                case .deletion:
                    let documents = try await wallet.loadAllDocuments() ?? []
                    for reference in recovery.affectedDocuments
                    where documents.contains(where: { $0.id == reference.id }) {
                        try await deleteSDKDocument(id: reference.id, status: reference.status)
                    }
                    let existingIDs = Set(try await configuration.metadataRepository.credentials().map(\.id))
                    for id in recovery.metadataCredentialIDs where existingIDs.contains(id) {
                        try await configuration.metadataRepository.deleteMetadata(id: id)
                    }
                    if let event = recovery.pendingAuditEvent {
                        let existingEventIDs = Set(try await configuration.auditRepository.events().map(\.id))
                        if !existingEventIDs.contains(event.id) {
                            try await configuration.auditRepository.append(event)
                        }
                    }
                case .audit:
                    if recovery.metadataCommitted, let event = recovery.pendingAuditEvent {
                        let existingEventIDs = Set(try await configuration.auditRepository.events().map(\.id))
                        if !existingEventIDs.contains(event.id) {
                            try await configuration.auditRepository.append(event)
                        }
                    }
                }
                if recovery.metadataCommitted, let event = recovery.pendingAuditEvent {
                    let existingEventIDs = Set(try await configuration.auditRepository.events().map(\.id))
                    if !existingEventIDs.contains(event.id) {
                        try await configuration.auditRepository.append(event)
                    }
                }
                try await configuration.recoveryStore.deleteRecovery(id: recovery.id)
            } catch {
                throw EudiWalletKitAdapterError.recoveryRequired
            }
        }
    }

    public func loadPendingIssuances() async throws -> [EudiPendingIssuance] {
        try await operationalState.performLifecycleOperation { [self] in
            try await loadPendingIssuancesUnlocked()
        }
    }

    private func loadPendingIssuancesUnlocked() async throws -> [EudiPendingIssuance] {
        let configuration = try requireOperationalConfiguration()
        try await reconcilePendingOperationsUnlocked()
        let metadata = try await configuration.metadataRepository.credentials()
        let documents = try await wallet.loadAllDocuments() ?? []
        var result: [EudiPendingIssuance] = []
        for document in documents where document.status == .pending {
            let claims = StorageManager.toClaimsModel(
                doc: document,
                uiCulture: wallet.eudiWalletConfig.uiCulture,
                modelFactory: wallet.modelFactory
            )
            guard let requestURI = document.authorizePresentationUrl,
                  let record = metadata.first(where: { $0.walletDocumentID == document.id }) else {
                throw EudiWalletKitAdapterError.invalidPendingIssuance
            }
            let id = await operationalState.upsertPending(
                documentID: document.id,
                issuerName: record.issuerIdentifier,
                profileID: record.profileID,
                metadataCredentialID: record.id,
                presentationRequestURI: requestURI
            )
            result.append(EudiPendingIssuance(
                id: id,
                document: EudiWalletDocumentSummary(
                    id: document.id,
                    documentType: document.docType,
                    displayName: document.displayName,
                    format: document.docDataFormat.rawValue,
                    status: document.status.rawValue,
                    configurationID: record.configurationID,
                    issuerIdentifier: record.issuerIdentifier,
                    display: record.display,
                    validFrom: claims?.validFrom,
                    validUntil: claims?.validUntil
                )
            ))
        }
        return result
    }

    public func resumePendingIssuance(
        id: UUID,
        presentationResult: EudiPresentationResult
    ) async throws -> EudiIssuanceResult {
        try await operationalState.performLifecycleOperation { [self] in
            try await resumePendingIssuanceUnlocked(
                id: id,
                presentationResult: presentationResult
            )
        }
    }

    private func resumePendingIssuanceUnlocked(
        id: UUID,
        presentationResult: EudiPresentationResult
    ) async throws -> EudiIssuanceResult {
        let configuration = try requireOperationalConfiguration()
        try await reconcilePendingOperationsUnlocked()
        guard presentationResult.userAccepted,
              presentationResult.pendingIssuanceID == id,
              let redirectURL = presentationResult.redirectURI,
              let pending = await operationalState.pending(id: id),
              let document = try await wallet.loadDocument(id: pending.documentID, status: .pending) else {
            throw EudiWalletKitAdapterError.invalidPendingIssuanceResume
        }
        guard let existing = try await configuration.metadataRepository.credentials().first(where: {
            $0.id == pending.metadataCredentialID && $0.walletDocumentID == pending.documentID
        }) else {
            throw EudiWalletKitAdapterError.missingDocumentMetadata
        }
        let baselineDocuments = try await wallet.loadAllDocuments() ?? []
        var recovery = WalletOperationRecovery(
            kind: .pendingIssuance,
            baselineDocumentIDs: Set(baselineDocuments.map(\.id)),
            affectedDocuments: [WalletDocumentRecoveryReference(id: document.id, status: "pending")],
            metadataCredentialIDs: [existing.id]
        )
        try await configuration.recoveryStore.saveRecovery(recovery)
        let options = try await wallet.getDocumentCredentialOptions(documentId: document.id)
        let resumed = try await { () async throws in
            do {
                return try await EudiNetworkScope.$current.withValue(.issuance) {
                    try await wallet.resumePendingIssuance(
                        issuerName: pending.issuerName,
                        pendingDoc: document,
                        webUrl: redirectURL,
                        credentialOptions: options
                    )
                }
            } catch {
                do { try await reconcilePendingOperationsUnlocked() } catch {
                    throw EudiWalletKitAdapterError.recoveryRequired
                }
                throw error
            }
        }()
        let resumedClaims = StorageManager.toClaimsModel(
            doc: resumed,
            uiCulture: wallet.eudiWalletConfig.uiCulture,
            modelFactory: wallet.modelFactory
        )
        let summary = EudiWalletDocumentSummary(
            id: resumed.id,
            documentType: resumed.docType,
            displayName: resumed.displayName,
            format: resumed.docDataFormat.rawValue,
            status: resumed.status.rawValue,
            configurationID: existing.configurationID,
            issuerIdentifier: pending.issuerName,
            display: Self.storedDisplayMetadata(from: resumed.metadata)?.display ?? existing.display,
            validFrom: resumedClaims?.validFrom,
            validUntil: resumedClaims?.validUntil
        )
        let repeatedPendingRequestURI: String?
        do {
            repeatedPendingRequestURI = try EudiPendingIssuancePolicy.nextPresentationURI(
                status: summary.status,
                candidate: resumed.authorizePresentationUrl
            )
        } catch {
            let rollbackReferences = EudiPendingIssuancePolicy.recoveryReferences(
                originalDocumentID: pending.documentID,
                resumedDocumentID: summary.id,
                resumedStatus: summary.status
            )
            let rollback = WalletOperationRecovery(
                id: recovery.id,
                kind: .issuance,
                baselineDocumentIDs: recovery.baselineDocumentIDs,
                affectedDocuments: rollbackReferences,
                metadataCredentialIDs: [existing.id],
                createdAt: recovery.createdAt
            )
            do {
                try await configuration.recoveryStore.replaceRecovery(rollback)
                try await reconcilePendingOperationsUnlocked()
                await operationalState.removePending(id: id)
            } catch {
                throw EudiWalletKitAdapterError.recoveryRequired
            }
            throw error
        }
        recovery = WalletOperationRecovery(
            id: recovery.id,
            kind: .pendingIssuance,
            baselineDocumentIDs: recovery.baselineDocumentIDs,
            affectedDocuments: EudiPendingIssuancePolicy.recoveryReferences(
                originalDocumentID: pending.documentID,
                resumedDocumentID: summary.id,
                resumedStatus: summary.status
            ),
            metadataCredentialIDs: [existing.id],
            createdAt: recovery.createdAt
        )
        do {
            try await configuration.recoveryStore.replaceRecovery(recovery)
        } catch {
            do {
                try await reconcilePendingOperationsUnlocked()
                await operationalState.removePending(id: id)
            } catch {
                throw EudiWalletKitAdapterError.recoveryRequired
            }
            throw EudiWalletKitAdapterError.metadataPersistenceFailed
        }
        let updated = try await metadataRecord(
            summary: summary,
            profileID: pending.profileID,
            id: existing.id,
            createdAt: existing.createdAt
        )
        do {
            try await configuration.metadataRepository.replaceMetadata(updated)
        } catch {
            do { try await reconcilePendingOperationsUnlocked() } catch {
                throw EudiWalletKitAdapterError.recoveryRequired
            }
            throw EudiWalletKitAdapterError.metadataPersistenceFailed
        }
        let completionAuditEvent = resumed.status == .issued ? makeAuditEvent(
            configuration: configuration,
            operation: .issuance,
            outcome: .completed,
            counterparty: pending.issuerName,
            disclosedClaimIDs: [],
            credentialIDs: [updated.id]
        ) : nil
        recovery = WalletOperationRecovery(
            id: recovery.id,
            kind: .pendingIssuance,
            baselineDocumentIDs: recovery.baselineDocumentIDs,
            affectedDocuments: recovery.affectedDocuments,
            metadataCredentialIDs: [updated.id],
            metadataCommitted: true,
            pendingAuditEvent: completionAuditEvent,
            createdAt: recovery.createdAt
        )
        do {
            try await configuration.recoveryStore.replaceRecovery(recovery)
            if let completionAuditEvent {
                try await configuration.auditRepository.append(completionAuditEvent)
            }
            try await configuration.recoveryStore.deleteRecovery(id: recovery.id)
        } catch {
            do { try await reconcilePendingOperationsUnlocked() } catch {
                throw EudiWalletKitAdapterError.recoveryRequired
            }
        }
        var stillPending: [EudiPendingIssuance] = []
        if let requestURI = repeatedPendingRequestURI {
            await operationalState.replacePending(
                id: id,
                documentID: resumed.id,
                issuerName: pending.issuerName,
                profileID: pending.profileID,
                metadataCredentialID: updated.id,
                presentationRequestURI: requestURI
            )
            stillPending = [EudiPendingIssuance(
                id: id,
                document: summary
            )]
        } else if resumed.status == .issued {
            await operationalState.removePending(id: id)
        }
        return EudiIssuanceResult(
            documents: [summary],
            metadata: [updated],
            warningCount: 0,
            pendingIssuances: stillPending
        )
    }

    public func retryDeferredIssuance(
        issuerName: String,
        documentID: String
    ) async throws -> EudiWalletDocumentSummary {
        try await operationalState.performLifecycleOperation { [self] in
            try await retryDeferredIssuanceUnlocked(
                issuerName: issuerName,
                documentID: documentID
            )
        }
    }

    private func retryDeferredIssuanceUnlocked(
        issuerName: String,
        documentID: String
    ) async throws -> EudiWalletDocumentSummary {
        let configuration = try requireOperationalConfiguration()
        let issuerName = issuerName.trimmingCharacters(in: .whitespacesAndNewlines)
        try await reconcilePendingOperationsUnlocked()
        guard !issuerName.isEmpty, !documentID.isEmpty,
              let document = try await wallet.loadDocument(id: documentID, status: .deferred) else {
            throw EudiWalletKitAdapterError.invalidDocumentReference
        }
        guard let existing = try await configuration.metadataRepository.credentials().first(where: {
            $0.walletDocumentID == documentID
        }) else {
            throw EudiWalletKitAdapterError.missingDocumentMetadata
        }
        let baselineDocuments = try await wallet.loadAllDocuments() ?? []
        var recovery = WalletOperationRecovery(
            kind: .deferredIssuance,
            baselineDocumentIDs: Set(baselineDocuments.map(\.id)),
            affectedDocuments: [WalletDocumentRecoveryReference(id: documentID, status: "deferred")],
            metadataCredentialIDs: [existing.id]
        )
        try await configuration.recoveryStore.saveRecovery(recovery)
        let options = try await wallet.getDocumentCredentialOptions(documentId: documentID)
        let result = try await { () async throws in
            do {
                return try await EudiNetworkScope.$current.withValue(.issuance) {
                    try await wallet.requestDeferredIssuance(
                        issuerName: issuerName,
                        deferredDoc: document,
                        credentialOptions: options
                    )
                }
            } catch {
                do { try await reconcilePendingOperationsUnlocked() } catch {
                    throw EudiWalletKitAdapterError.recoveryRequired
                }
                throw error
            }
        }()
        let resultClaims = StorageManager.toClaimsModel(
            doc: result,
            uiCulture: wallet.eudiWalletConfig.uiCulture,
            modelFactory: wallet.modelFactory
        )
        let summary = EudiWalletDocumentSummary(
            id: result.id,
            documentType: result.docType,
            displayName: result.displayName,
            format: result.docDataFormat.rawValue,
            status: result.status.rawValue,
            configurationID: existing.configurationID,
            issuerIdentifier: issuerName,
            display: Self.storedDisplayMetadata(from: result.metadata)?.display ?? existing.display,
            validFrom: resultClaims?.validFrom,
            validUntil: resultClaims?.validUntil
        )
        recovery = WalletOperationRecovery(
            id: recovery.id,
            kind: .deferredIssuance,
            baselineDocumentIDs: recovery.baselineDocumentIDs,
            affectedDocuments: [WalletDocumentRecoveryReference(id: summary.id, status: summary.status)],
            metadataCredentialIDs: [existing.id],
            createdAt: recovery.createdAt
        )
        do {
            try await configuration.recoveryStore.replaceRecovery(recovery)
        } catch {
            do { try await reconcilePendingOperationsUnlocked() } catch {
                throw EudiWalletKitAdapterError.recoveryRequired
            }
            throw EudiWalletKitAdapterError.metadataPersistenceFailed
        }
        let updated = try await metadataRecord(
            summary: summary,
            profileID: existing.profileID,
            id: existing.id,
            createdAt: existing.createdAt
        )
        do {
            try await configuration.metadataRepository.replaceMetadata(updated)
        } catch {
            do { try await reconcilePendingOperationsUnlocked() } catch {
                throw EudiWalletKitAdapterError.recoveryRequired
            }
            throw EudiWalletKitAdapterError.metadataPersistenceFailed
        }
        let completionEvent = summary.status == "issued" ? makeAuditEvent(
            configuration: configuration,
            operation: .issuance,
            outcome: .completed,
            counterparty: issuerName,
            disclosedClaimIDs: [],
            credentialIDs: [updated.id]
        ) : nil
        recovery = WalletOperationRecovery(
            id: recovery.id,
            kind: .deferredIssuance,
            baselineDocumentIDs: recovery.baselineDocumentIDs,
            affectedDocuments: recovery.affectedDocuments,
            metadataCredentialIDs: [updated.id],
            metadataCommitted: true,
            pendingAuditEvent: completionEvent,
            createdAt: recovery.createdAt
        )
        do {
            try await configuration.recoveryStore.replaceRecovery(recovery)
            if let completionEvent { try await configuration.auditRepository.append(completionEvent) }
            try await configuration.recoveryStore.deleteRecovery(id: recovery.id)
        } catch {
            do { try await reconcilePendingOperationsUnlocked() } catch {
                throw EudiWalletKitAdapterError.recoveryRequired
            }
        }
        return summary
    }

    public func beginOpenID4VPPresentation(
        requestURI: String
    ) async throws -> EudiPresentationRequest {
        try await beginOpenID4VPPresentation(
            requestURI: requestURI,
            pendingIssuanceID: nil
        )
    }

    public func beginPendingIssuancePresentation(
        id: UUID
    ) async throws -> EudiPresentationRequest {
        guard let pending = await operationalState.pending(id: id) else {
            throw EudiWalletKitAdapterError.unknownPendingIssuance
        }
        return try await beginOpenID4VPPresentation(
            requestURI: pending.presentationRequestURI,
            pendingIssuanceID: id
        )
    }

    private func beginOpenID4VPPresentation(
        requestURI: String,
        pendingIssuanceID: UUID?
    ) async throws -> EudiPresentationRequest {
        let configuration = try requireOperationalConfiguration()
        let requestURI = try pendingIssuanceID == nil
            ? configuration.validatePresentationRequestURI(requestURI)
            : configuration.validatePendingIssuancePresentationURI(requestURI)
        let flow: EudiNetworkFlow = pendingIssuanceID == nil ? .presentation : .presentationDuringIssuance
        let session = await EudiNetworkScope.$current.withValue(flow) {
            await wallet.beginPresentation(flow: .openid4vp(qrCode: Data(requestURI.utf8)))
        }
        guard let requests = await EudiNetworkScope.$current.withValue(flow, operation: {
            await session.receiveRequest()
        }) else {
            if let error = session.uiError {
                throw EudiWalletKitAdapterError.presentationRequestFailedWithReason(
                    "\(error.code.rawValue): \(error.description)"
                )
            }
            throw EudiWalletKitAdapterError.presentationRequestFailed
        }
        let requester = requests.compactMap(\.requestName).first
        let options = Self.presentationOptions(requests: requests, session: session)
        let id = await operationalState.insert(
            session: session,
            requester: requester,
            pendingIssuanceID: pendingIssuanceID,
            options: options
        )
        let summaries = try await loadDocumentSummaries()
        return Self.presentationRequest(
            id: id, session: session, requester: requester, requests: requests,
            summaries: summaries, profileID: trustProfileID, options: options
        )
    }

    public func beginBLEEngagement() async throws -> EudiBLEEngagement {
        _ = try requireOperationalConfiguration()
        let session = await wallet.beginPresentation(flow: .ble)
        try await session.startQrEngagement()
        guard let engagement = session.deviceEngagement, !engagement.isEmpty else {
            throw EudiWalletKitAdapterError.bleEngagementFailed
        }
        let id = await operationalState.insert(session: session, requester: nil)
        return EudiBLEEngagement(id: id, qrEngagement: engagement)
    }

    public func receiveBLEPresentationRequest(
        id: UUID
    ) async throws -> EudiPresentationRequest {
        _ = try requireOperationalConfiguration()
        guard let entry = await operationalState.presentation(id: id) else {
            throw EudiWalletKitAdapterError.unknownPresentation
        }
        guard let requests = await EudiNetworkScope.$current.withValue(.presentation, operation: {
            await entry.session.receiveRequest()
        }) else {
            throw EudiWalletKitAdapterError.presentationRequestFailed
        }
        let requester = requests.compactMap(\.requestName).first
        await operationalState.setRequester(id: id, requester: requester)
        let options = Self.presentationOptions(requests: requests, session: entry.session)
        await operationalState.setOptions(id: id, options: options)
        let summaries = try await loadDocumentSummaries()
        return Self.presentationRequest(
            id: id, session: entry.session, requester: requester, requests: requests,
            summaries: summaries, profileID: trustProfileID, options: options
        )
    }

    public func submitPresentation(
        id: UUID,
        selectedOptionID: String?,
        selectedClaimIDs: Set<String>,
        userAccepted: Bool
    ) async throws -> EudiPresentationResult {
        try await operationalState.performLifecycleOperation { [self] in
            try await submitPresentationUnlocked(
                id: id,
                selectedOptionID: selectedOptionID,
                selectedClaimIDs: selectedClaimIDs,
                userAccepted: userAccepted
            )
        }
    }

    private func submitPresentationUnlocked(
        id: UUID,
        selectedOptionID: String?,
        selectedClaimIDs: Set<String>,
        userAccepted: Bool
    ) async throws -> EudiPresentationResult {
        let configuration = try requireOperationalConfiguration()
        try await reconcilePendingOperationsUnlocked()
        guard let entry = await operationalState.presentation(id: id) else {
            throw EudiWalletKitAdapterError.unknownPresentation
        }
        let session = entry.session
        let selectedOption = selectedOptionID.flatMap { id in entry.options.first { $0.id == id } }
        guard !userAccepted || selectedOption != nil else {
            throw EudiWalletKitAdapterError.invalidClaimSelection
        }
        let availableClaims = selectedOption?.claims ?? []
        guard userAccepted || selectedClaimIDs.isEmpty else {
            throw EudiWalletKitAdapterError.rejectedPresentationHasClaims
        }
        guard selectedClaimIDs.isSubset(of: Set(availableClaims.map(\.id))) else {
            throw EudiWalletKitAdapterError.invalidClaimSelection
        }
        let required = Set(availableClaims.filter(\.required).map(\.id))
        guard !userAccepted || required.isSubset(of: selectedClaimIDs) else {
            throw EudiWalletKitAdapterError.requiredClaimMissing
        }
        let selectedIndex = selectedOption.flatMap { option in entry.options.firstIndex { $0.id == option.id } }
        let selectedElements = selectedIndex.map { session.disclosedDocumentSets[$0].docElements } ?? []
        Self.applySelection(selectedClaimIDs, to: selectedElements)
        let auditEvent = makeAuditEvent(
            configuration: configuration,
            operation: .presentation,
            outcome: userAccepted ? .completed : .rejected,
            counterparty: session.readerLegalName ?? session.readerCertIssuer ?? entry.requester,
            disclosedClaimIDs: userAccepted ? Array(selectedClaimIDs) : []
        )
        let auditRecovery = WalletOperationRecovery(
            kind: .audit,
            metadataCommitted: false,
            pendingAuditEvent: auditEvent
        )
        do {
            try await configuration.recoveryStore.saveRecovery(auditRecovery)
        } catch {
            throw EudiWalletKitAdapterError.auditPersistenceFailedAfterOperation
        }
        guard await operationalState.consumePresentation(id: id) != nil else {
            try? await configuration.recoveryStore.deleteRecovery(id: auditRecovery.id)
            throw EudiWalletKitAdapterError.unknownPresentation
        }
        let items = userAccepted ? selectedElements.items : [:]
        let redirect = LockedRedirect()
        do {
            let flow: EudiNetworkFlow = entry.pendingIssuanceID == nil
                ? .presentation
                : .presentationDuringIssuance
            try await EudiNetworkScope.$current.withValue(flow) {
                try await session.sendResponse(
                    userAccepted: userAccepted,
                    itemsToSend: items,
                    onSuccess: { redirect.set($0) }
                )
            }
        } catch {
            do {
                try await configuration.recoveryStore.deleteRecovery(id: auditRecovery.id)
            } catch {
                // An uncommitted audit intent is safely discarded by reconciliation.
            }
            throw error
        }
        do {
            if entry.pendingIssuanceID != nil, userAccepted, redirect.value == nil {
                throw EudiWalletKitAdapterError.invalidPendingIssuanceResume
            }
            if let redirectURL = redirect.value {
                let origin = try Self.canonicalHTTPSOrigin(
                    redirectURL.absoluteString,
                    requireOriginOnly: false
                )
                let allowedOrigins = entry.pendingIssuanceID == nil
                    ? configuration.allowedVerifierOrigins
                    : configuration.allowedIssuerOrigins
                guard allowedOrigins.contains(origin) else {
                    throw entry.pendingIssuanceID == nil
                        ? EudiWalletKitAdapterError.unapprovedVerifier
                        : EudiWalletKitAdapterError.unapprovedIssuer
                }
            }
        } catch {
            try? await configuration.recoveryStore.deleteRecovery(id: auditRecovery.id)
            throw error
        }
        let committedAuditRecovery = WalletOperationRecovery(
            id: auditRecovery.id,
            kind: .audit,
            metadataCommitted: true,
            pendingAuditEvent: auditEvent,
            createdAt: auditRecovery.createdAt
        )
        do {
            try await configuration.recoveryStore.replaceRecovery(committedAuditRecovery)
            try await configuration.auditRepository.append(auditEvent)
            try await configuration.recoveryStore.deleteRecovery(id: auditRecovery.id)
        } catch {
            throw EudiWalletKitAdapterError.auditPersistenceFailedAfterOperation
        }
        return EudiPresentationResult(
            redirectURI: redirect.value,
            disclosedDocumentIDs: userAccepted ? Array(items.keys).sorted() : [],
            pendingIssuanceID: entry.pendingIssuanceID,
            userAccepted: userAccepted,
            authorizationCode: redirect.value.flatMap { url in
                URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems?
                    .first(where: { $0.name == "code" || $0.name == "authorization_code" })?.value
            }
        )
    }

    private func requireOperationalConfiguration() throws -> EudiOperationalConfiguration {
        guard let operationalConfiguration else {
            throw EudiWalletKitAdapterError.missingOperationalConfiguration
        }
        return operationalConfiguration
    }

    private func makeAuditEvent(
        configuration: EudiOperationalConfiguration,
        operation: AuditOperation,
        outcome: AuditOutcome,
        counterparty: String?,
        disclosedClaimIDs: [String],
        credentialIDs: [CredentialID] = []
    ) -> AuditEvent {
        return AuditEvent(
            operation: operation,
            outcome: outcome,
            occurredAt: Date(),
            counterpartyIdentifierDigest: counterparty.map { AuditDigest.sha256($0) },
            credentialIDs: credentialIDs,
            disclosedClaimDigests: disclosedClaimIDs.sorted().map { AuditDigest.sha256($0) },
            policy: configuration.auditPolicy,
            policyVersion: configuration.auditPolicyVersion,
            reasonCode: outcome == .rejected ? .userRejected : nil
        )
    }

    private struct StoredDisplayResolution {
        let configurationID: String
        let issuerIdentifier: String
        let display: CredentialDisplayMetadata?
    }

    private struct StoredDocMetadata: Decodable {
        let credentialIssuerIdentifier: String
        let configurationIdentifier: String
        let display: [StoredDisplayMetadata]?
    }

    private struct StoredDisplayMetadata: Decodable {
        let localeIdentifier: String?
        let logo: StoredLogoMetadata?
        let description: String?
        let backgroundColor: String?
        let textColor: String?
        let backgroundImageURL: String?
    }

    private struct StoredLogoMetadata: Decodable {
        let urlString: String?
        let alternativeText: String?
    }

    private static func offerDisplayMetadata(
        from displays: [Display]?,
        issuerURL: URL?
    ) -> EudiIssuanceOfferDisplay? {
        guard let display = preferredDisplay(displays, locale: { $0.locale?.identifier }) else {
            return nil
        }
        return EudiIssuanceOfferDisplay(
            description: display.description,
            backgroundColor: display.backgroundColor,
            textColor: display.textColor,
            logoURL: safeDisplayURL(display.logo?.uri, relativeTo: issuerURL),
            logoAlternativeText: display.logo?.alternativeText,
            backgroundImageURL: safeDisplayURL(display.backgroundImage?.url, relativeTo: issuerURL)
        )
    }

    private static func credentialIssuerURL(from offerURI: String) -> URL? {
        guard let components = URLComponents(string: offerURI) else { return nil }
        if components.scheme?.lowercased() == "https" {
            return safeDisplayURL(components.url, relativeTo: nil)
        }
        guard let value = components.queryItems?.first(where: { $0.name == "credential_offer" })?.value,
              let data = value.data(using: .utf8),
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let issuer = object["credential_issuer"] as? String else { return nil }
        return safeDisplayURL(issuer, relativeTo: nil)
    }

    private static func safeDisplayURL(_ source: String?, relativeTo issuerURL: URL?) -> URL? {
        guard let source else { return nil }
        return safeDisplayURL(URL(string: source, relativeTo: issuerURL)?.absoluteURL, relativeTo: issuerURL)
    }

    private static func safeDisplayURL(_ source: URL?, relativeTo issuerURL: URL?) -> URL? {
        guard let source,
              source.scheme?.lowercased() == "https",
              source.host != nil,
              source.user == nil,
              source.password == nil,
              source.fragment == nil else { return nil }
        if let issuerURL, let issuerHost = issuerURL.host?.lowercased() {
            guard source.host?.lowercased() == issuerHost else { return nil }
        }
        return source
    }

    private static func storedDisplayMetadata(from data: Data?) -> StoredDisplayResolution? {
        guard let data,
              let metadata = try? JSONDecoder().decode(StoredDocMetadata.self, from: data) else {
            return nil
        }
        let selected = preferredDisplay(metadata.display, locale: { $0.localeIdentifier })
        let display = selected.map {
            CredentialDisplayMetadata(
                locale: $0.localeIdentifier,
                description: $0.description,
                backgroundColor: $0.backgroundColor,
                textColor: $0.textColor,
                logo: displayImage(from: $0.logo?.urlString, alternativeText: $0.logo?.alternativeText),
                backgroundImage: displayImage(from: $0.backgroundImageURL)
            )
        }
        return StoredDisplayResolution(
            configurationID: metadata.configurationIdentifier,
            issuerIdentifier: metadata.credentialIssuerIdentifier,
            display: display
        )
    }

    static func credentialDisplayMetadata(
        fromWalletKitMetadata data: Data?
    ) -> CredentialDisplayMetadata? {
        storedDisplayMetadata(from: data)?.display
    }

    private static func preferredDisplay<T>(
        _ displays: [T]?,
        locale: (T) -> String?
    ) -> T? {
        guard let displays, !displays.isEmpty else { return nil }
        let language = Locale.current.language.languageCode?.identifier
        return displays.first {
            guard let identifier = locale($0) else { return false }
            return Locale(identifier: identifier).language.languageCode?.identifier == language
        } ?? displays.first
    }

    private static func displayImage(
        from source: String?,
        alternativeText: String? = nil
    ) -> CredentialDisplayImage? {
        guard let source,
              source.lowercased().hasPrefix("data:"),
              let comma = source.firstIndex(of: ",") else { return nil }
        let metadata = source[source.index(source.startIndex, offsetBy: 5)..<comma]
            .lowercased()
        guard metadata.split(separator: ";").contains("base64") else { return nil }
        let payload = String(source[source.index(after: comma)...])
        guard payload.utf8.count <= 1_398_104,
              let data = Data(base64Encoded: payload),
              !data.isEmpty,
              data.count <= 1_048_576,
              let mediaType = validatedImageMediaType(data) else { return nil }
        return CredentialDisplayImage(
            mediaType: mediaType,
            data: data,
            alternativeText: alternativeText
        )
    }

    private static func validatedImageMediaType(_ data: Data) -> String? {
        if data.starts(with: [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]) {
            return "image/png"
        }
        if data.starts(with: [0xff, 0xd8, 0xff]) { return "image/jpeg" }
        if data.count >= 12,
           String(decoding: data.prefix(4), as: UTF8.self) == "RIFF",
           String(decoding: data.dropFirst(8).prefix(4), as: UTF8.self) == "WEBP" {
            return "image/webp"
        }
        return nil
    }

    private func metadataRecord(
        summary: EudiWalletDocumentSummary,
        profileID: String,
        id: CredentialID = CredentialID(),
        createdAt: Date = Date()
    ) async throws -> CredentialRecord {
        guard let configuration = operationalConfiguration else {
            throw EudiWalletKitAdapterError.missingOperationalConfiguration
        }
        let format: CredentialFormat
        switch summary.format {
        case "cbor": format = .mdoc
        case "sjwt": format = .sdJWTVC
        default: throw EudiWalletKitAdapterError.unsupportedDocumentFormat
        }
        let status = try await configuration.statusProvider.status(for: summary)
        return CredentialRecord(
            id: id,
            configurationID: summary.configurationID ?? summary.documentType,
            walletDocumentID: summary.id,
            displayName: summary.displayName ?? summary.documentType,
            format: format,
            profileID: profileID,
            issuerIdentifier: summary.issuerIdentifier ?? "unknown-issuer",
            cryptographicValidity: .valid,
            issuerTrust: .trusted,
            status: status,
            createdAt: createdAt,
            display: summary.display,
            validFrom: summary.validFrom,
            validUntil: summary.validUntil
        )
    }

    private static func copy(
        _ record: CredentialRecord,
        validFrom: Date?,
        validUntil: Date?
    ) -> CredentialRecord {
        CredentialRecord(
            id: record.id, configurationID: record.configurationID,
            walletDocumentID: record.walletDocumentID, backendID: record.backendID,
            backendDocumentID: record.backendDocumentID, displayName: record.displayName,
            format: record.format, profileID: record.profileID,
            issuerIdentifier: record.issuerIdentifier, subjectIdentifier: record.subjectIdentifier,
            holderBinding: record.holderBinding, cryptographicValidity: record.cryptographicValidity,
            issuerTrust: record.issuerTrust, status: record.status,
            legalClassification: record.legalClassification, createdAt: record.createdAt,
            displayClaims: record.displayClaims, display: record.display, refresh: record.refresh,
            validFrom: validFrom, validUntil: validUntil
        )
    }

    private func deleteSDKDocument(id: String, status: String) async throws {
        switch status {
        case "issued": try await wallet.deleteDocument(id: id, status: .issued)
        case "pending": try await wallet.deleteDocument(id: id, status: .pending)
        case "deferred": try await wallet.deleteDocument(id: id, status: .deferred)
        default: throw EudiWalletKitAdapterError.invalidDocumentReference
        }
    }

    static func validatedOfferURI(
        _ value: String,
        allowedOrigins: Set<String>
    ) throws -> String {
        guard value.utf8.count <= 8_192,
              let inputComponents = URLComponents(string: value),
              let inputScheme = inputComponents.scheme?.lowercased(),
              let normalized = normalizedURI(
                value,
                replacingSchemes: ["haip-vci": "openid-credential-offer"]
              ),
              let components = URLComponents(string: normalized),
              let scheme = components.scheme?.lowercased(),
              components.user == nil, components.password == nil,
              inputScheme == "https" || inputScheme == "openid-credential-offer" || inputScheme == "haip-vci",
              scheme == "https" || scheme == "openid-credential-offer" else {
            throw EudiWalletKitAdapterError.invalidOfferURI
        }
        let origin: String?
        if scheme == "https" {
            origin = try? canonicalHTTPSOrigin(value, requireOriginOnly: false)
        } else if scheme == "openid-credential-offer" {
            origin = embeddedOrigin(
                components: components,
                uriParameter: "credential_offer_uri",
                objectParameter: "credential_offer",
                issuerField: "credential_issuer"
            )
        } else {
            origin = nil
        }
        guard let origin, allowedOrigins.contains("*") || allowedOrigins.contains(origin) else {
            throw EudiWalletKitAdapterError.unapprovedIssuer
        }
        return normalized
    }

    static func validatedPresentationURI(
        _ value: String,
        allowedOrigins: Set<String>
    ) throws -> String {
        guard value.utf8.count <= 16_384,
              let inputComponents = URLComponents(string: value),
              let inputScheme = inputComponents.scheme?.lowercased(),
              let normalized = normalizedURI(
                value,
                replacingSchemes: [
                    "haip-vp": "openid4vp",
                    "eudi-openid4vp": "openid4vp",
                    "mdoc-openid4vp": "openid4vp",
                ]
              ),
              let components = URLComponents(string: normalized),
              let scheme = components.scheme?.lowercased(),
              components.user == nil, components.password == nil,
              ["https", "openid4vp", "haip-vp", "eudi-openid4vp", "mdoc-openid4vp"].contains(inputScheme) else {
            throw EudiWalletKitAdapterError.invalidPresentationURI
        }
        if scheme == "https" {
            guard let origin = try? canonicalHTTPSOrigin(value, requireOriginOnly: false),
                   allowedOrigins.contains("*") || allowedOrigins.contains(origin) else {
                throw EudiWalletKitAdapterError.unapprovedVerifier
            }
        } else if scheme == "openid4vp" {
            if let requestURI = components.queryItems?.first(where: { $0.name == "request_uri" })?.value {
                guard let origin = try? canonicalHTTPSOrigin(requestURI, requireOriginOnly: false),
                       allowedOrigins.contains("*") || allowedOrigins.contains(origin) else {
                    throw EudiWalletKitAdapterError.unapprovedVerifier
                }
            } else if let request = components.queryItems?.first(where: { $0.name == "request" })?.value,
                      !request.isEmpty {
                // Wallet Kit verifies the JAR signature before presentation. This
                // preflight only constrains its declared callback to an approved origin.
                guard let origin = signedPresentationRequestOrigin(request),
                      allowedOrigins.contains("*") || allowedOrigins.contains(origin) else {
                    throw EudiWalletKitAdapterError.unapprovedVerifier
                }
            } else {
                throw EudiWalletKitAdapterError.invalidPresentationURI
            }
        } else {
            throw EudiWalletKitAdapterError.invalidPresentationURI
        }
        return normalized
    }

    private static func normalizedURI(
        _ value: String,
        replacingSchemes replacements: [String: String]
    ) -> String? {
        guard let components = URLComponents(string: value),
              let scheme = components.scheme?.lowercased(),
              let separator = value.firstIndex(of: ":") else { return nil }
        guard let replacement = replacements[scheme] else { return value }
        // Deliberately normalize only at this SDK boundary. Preserve the URI
        // byte-for-byte after the scheme separator so encoded request values
        // are never decoded, re-encoded, or otherwise rewritten here.
        return replacement + String(value[separator...])
    }

    private static func signedPresentationRequestOrigin(_ compactJWT: String) -> String? {
        let parts = compactJWT.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 3 else { return nil }
        var base64 = String(parts[1]).replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        base64 += String(repeating: "=", count: (4 - base64.count % 4) % 4)
        guard let data = Data(base64Encoded: base64),
              let payload = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let responseURI = payload["response_uri"] as? String,
              let responseOrigin = try? canonicalHTTPSOrigin(responseURI, requireOriginOnly: false),
              let clientID = payload["client_id"] as? String,
              clientID.hasPrefix("redirect_uri:") else {
            return nil
        }
        let clientURI = String(clientID.dropFirst("redirect_uri:".count))
        guard let clientOrigin = try? canonicalHTTPSOrigin(clientURI, requireOriginOnly: false),
              clientOrigin == responseOrigin else {
            return nil
        }
        return responseOrigin
    }

    private static func embeddedOrigin(
        components: URLComponents,
        uriParameter: String,
        objectParameter: String,
        issuerField: String
    ) -> String? {
        if let uri = components.queryItems?.first(where: { $0.name == uriParameter })?.value,
           let origin = try? canonicalHTTPSOrigin(uri, requireOriginOnly: false) {
            return origin
        }
        guard let object = components.queryItems?.first(where: { $0.name == objectParameter })?.value,
              let data = object.data(using: .utf8),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let issuer = json[issuerField] as? String,
              let origin = try? canonicalHTTPSOrigin(issuer, requireOriginOnly: false) else {
            return nil
        }
        return origin
    }

    fileprivate static func canonicalHTTPSOrigin(
        _ value: String,
        requireOriginOnly: Bool = true
    ) throws -> String {
        guard let input = URLComponents(string: value),
              input.scheme?.lowercased() == "https",
              let host = input.host?.lowercased(), !host.isEmpty,
              input.user == nil, input.password == nil,
              !requireOriginOnly ||
                ((input.path.isEmpty || input.path == "/") && input.query == nil && input.fragment == nil) else {
            throw EudiWalletKitAdapterError.invalidOperationalConfiguration
        }
        var origin = URLComponents()
        origin.scheme = "https"
        origin.host = host
        if let port = input.port, port != 443 { origin.port = port }
        guard let result = origin.string else {
            throw EudiWalletKitAdapterError.invalidOperationalConfiguration
        }
        return result
    }

    private static func presentationRequest(
        id: UUID,
        session: PresentationSession,
        requester: String?,
        requests: [UserRequestInfo],
        summaries: [EudiWalletDocumentSummary],
        profileID: String,
        options: [EudiPresentationOption]
    ) -> EudiPresentationRequest {
        let requestedClaims = options.first?.claims ?? claims(session: session)
        let documentIDs = Set(requestedClaims.map(\.documentID))
        return EudiPresentationRequest(
            id: id,
            verifierName: session.readerCertIssuer ?? requester,
            verifierLegalName: session.readerLegalName,
            verifierCertificateValid: session.readerCertIssuerValid,
            claims: requestedClaims,
            warningCount: session.disclosedDocumentSets.reduce(0) {
                $0 + ($1.warnings?.count ?? 0)
            },
            transactionData: transactionData(requests),
            credentials: summaries.filter { documentIDs.contains($0.id) }.map {
                EudiPresentationCredential(
                    id: $0.id,
                    displayName: $0.displayName ?? $0.documentType,
                    issuerIdentifier: $0.issuerIdentifier,
                    configurationID: $0.configurationID,
                    format: $0.format.lowercased().contains("mdoc") || $0.format.lowercased().contains("cbor")
                        ? .mdoc
                        : .sdJWTVC,
                    profileID: profileID,
                    representation: $0.format,
                    receivedAt: .distantPast,
                    display: $0.display
                )
            },
            options: options
        )
    }

    private static func presentationOptions(
        requests: [UserRequestInfo],
        session: PresentationSession
    ) -> [EudiPresentationOption] {
        zip(requests, session.disclosedDocumentSets).enumerated().map { index, pair in
            let elements = pair.1.docElements
            let optionClaims = claims(elements: elements)
            return EudiPresentationOption(
                id: pair.0.requestName ?? "option-\(index)",
                credentialIDs: Array(Set(optionClaims.map(\.documentID))).sorted(),
                claims: optionClaims
            )
        }
    }

    private static func transactionData(_ requests: [UserRequestInfo]) -> [EudiTransactionDataPresentation] {
        var result: [EudiTransactionDataPresentation] = []
        for request in requests {
            guard let transactionData = request.transactionDataRequested else { continue }
            for documentID in transactionData.keys.sorted() {
                guard let valuesByType = transactionData[documentID] else { continue }
                for type in valuesByType.keys.sorted() {
                    guard let json = valuesByType[type],
                          let object = json.dictionaryObject else { continue }
                    let index = result.count
                    let converted = object.mapValues(transactionValue)
                    let purpose = object["purpose"] as? String
                    let reference = object["transaction_id"] as? String
                    let credentialIDs = object["credential_ids"] as? [String] ?? [documentID]
                    let fields = converted.keys.sorted()
                        .filter { !["type", "purpose", "transaction_id", "credential_ids"].contains($0) }
                        .map {
                            EudiTransactionDataField(
                                id: "native-\(index).\($0)",
                                key: humanizedTransactionKey($0),
                                value: converted[$0] ?? .null
                            )
                        }
                    result.append(EudiTransactionDataPresentation(
                        id: "native-transaction-\(index)",
                        type: type,
                        title: transactionTitle(type),
                        purpose: purpose,
                        credentialIDs: credentialIDs,
                        reference: reference,
                        fields: fields
                    ))
                }
            }
        }
        return result
    }

    private static func transactionValue(_ value: Any) -> EudiTransactionDataValue {
        switch value {
        case let value as String: return .string(value)
        case let value as Bool: return .bool(value)
        case let value as NSNumber: return .number(value.stringValue)
        case let value as [Any]: return .array(value.map(transactionValue))
        case let value as [String: Any]: return .object(value.mapValues(transactionValue))
        case _ as NSNull: return .null
        default: return .string(String(describing: value))
        }
    }

    private static func humanizedTransactionKey(_ key: String) -> String {
        key.split(separator: "_").map { $0.capitalized }.joined(separator: " ")
    }

    private static func transactionTitle(_ type: String) -> String {
        type.localizedCaseInsensitiveContains("payment") ? "Payment authorization" : "Transaction details"
    }

    private static func claims(session: PresentationSession) -> [EudiRequestedClaim] {
        claims(elements: session.disclosedDocumentSets.flatMap(\.docElements))
    }

    private static func claims(elements: [DocElements]) -> [EudiRequestedClaim] {
        elements.flatMap { document in
            switch document {
            case let .msoMdoc(mdoc):
                return mdoc.nameSpacedElements.flatMap { namespace in
                    namespace.elements.map {
                        let path = [namespace.nameSpace, $0.elementIdentifier]
                        return EudiRequestedClaim(
                            id: claimID(documentID: mdoc.docId, path: path),
                            documentID: mdoc.docId,
                            documentType: mdoc.docType,
                            displayName: mdoc.displayName,
                            claimPath: path,
                            displayValue: $0.stringValue,
                            required: !$0.isOptional,
                            intentToRetain: $0.intentToRetain
                        )
                    }
                }
            case let .sdJwt(sdjwt):
                return flatten(
                    sdjwt.sdJwtElements,
                    documentID: sdjwt.docId,
                    documentType: sdjwt.vct,
                    displayName: sdjwt.displayName
                )
            }
        }
    }

    private static func flatten(
        _ elements: [SdJwtElement],
        documentID: String,
        documentType: String,
        displayName: String?
    ) -> [EudiRequestedClaim] {
        elements.flatMap { element in
            let own = EudiRequestedClaim(
                id: claimID(documentID: documentID, path: element.elementPath),
                documentID: documentID,
                documentType: documentType,
                displayName: displayName,
                claimPath: element.elementPath,
                displayValue: element.stringValue,
                required: !element.isOptional,
                intentToRetain: element.intentToRetain
            )
            return [own] + flatten(
                element.nestedElements ?? [],
                documentID: documentID,
                documentType: documentType,
                displayName: displayName
            )
        }
    }

    private static func claimID(documentID: String, path: [String]) -> String {
        ([documentID] + path).joined(separator: "\u{1f}")
    }

    private static func applySelection(
        _ selectedClaimIDs: Set<String>,
        to elements: [DocElements]
    ) {
        for document in elements {
            switch document {
            case let .msoMdoc(mdoc):
                for namespace in mdoc.nameSpacedElements {
                    for element in namespace.elements {
                        element.isSelected = selectedClaimIDs.contains(claimID(
                            documentID: mdoc.docId,
                            path: [namespace.nameSpace, element.elementIdentifier]
                        ))
                    }
                }
            case let .sdJwt(sdjwt):
                applySelection(selectedClaimIDs, documentID: sdjwt.docId, elements: sdjwt.sdJwtElements)
            }
        }
    }

    private static func applySelection(
        _ selectedClaimIDs: Set<String>,
        documentID: String,
        elements: [SdJwtElement]
    ) {
        for element in elements {
            element.isSelected = selectedClaimIDs.contains(claimID(
                documentID: documentID,
                path: element.elementPath
            ))
            applySelection(
                selectedClaimIDs,
                documentID: documentID,
                elements: element.nestedElements ?? []
            )
        }
    }

}

private final class LockedRedirect: @unchecked Sendable {
    private let lock = NSLock()
    private var storage: URL?

    var value: URL? { lock.withLock { storage } }
    func set(_ value: URL?) { lock.withLock { storage = value } }
}

public enum EudiWalletKitAdapterError: Error, Equatable, Sendable {
    case invalidServiceName
    case missingTrustAnchors
    case invalidTrustAnchor
    case invalidTrustSource
    case unapprovedTrustAnchor
    case initializationFailed
    case invalidOperationalConfiguration
    case missingOperationalConfiguration
    case attestationEncodingFailed
    case invalidOfferURI
    case emptyIssuanceOffer
    case unknownOrConsumedOffer
    case invalidPendingIssuance
    case unknownPendingIssuance
    case invalidPendingIssuanceResume
    case unexpectedPendingIssuanceStatus
    case invalidOfferSelection
    case invalidTransactionCode
    case unexpectedTransactionCode
    case invalidPrompt
    case invalidPresentationURI
    case presentationRequestFailed
    case presentationRequestFailedWithReason(String)
    case bleEngagementFailed
    case unknownPresentation
    case rejectedPresentationHasClaims
    case invalidClaimSelection
    case requiredClaimMissing
    case invalidDocumentReference
    case unapprovedIssuer
    case unapprovedVerifier
    case invalidNetworkRequest
    case invalidNetworkResponse
    case unapprovedNetworkDestination
    case missingNetworkFlowContext
    case invalidProfile
    case metadataPersistenceFailed
    case documentDeletionFailed
    case recoveryRequired
    case lifecycleOperationInProgress
    case missingDocumentMetadata
    case unsupportedDocumentFormat
    case auditPersistenceFailedAfterOperation
}
