import Foundation
import OSLog
import EbsiW3CBackend
import EudiWalletKitAdapter
import IdentityDomain
import ProtocolEngine
import WalletDomain
import WalletVault

struct WalletAppDependencies: Sendable {
    typealias EudiInitializer = @Sendable () async -> EudiInitializationResult
    private static let eudiLogger = Logger(subsystem: "io.oari.wallet", category: "eudi-startup")

    let credentials: any CredentialMetadataRepository
    let audit: any AuditRepository
    let localAuthenticator: any LocalAuthenticator
    let appLockAuthenticator: any AppLockAuthenticating
    let eudiWallet: (any EudiWalletOperating)?
    let eudiAvailability: EudiWalletAvailability
    let eudiInitializer: EudiInitializer?
    let openID4VCWallet: (any OpenID4VCOperating)?

    init(
        credentials: any CredentialMetadataRepository,
        audit: any AuditRepository,
        localAuthenticator: any LocalAuthenticator,
        appLockAuthenticator: any AppLockAuthenticating = SystemLocalAuthenticator(),
        eudiWallet: (any EudiWalletOperating)?,
        eudiAvailability: EudiWalletAvailability,
        eudiInitializer: EudiInitializer? = nil,
        openID4VCWallet: (any OpenID4VCOperating)?
    ) {
        self.credentials = credentials
        self.audit = audit
        self.localAuthenticator = localAuthenticator
        self.appLockAuthenticator = appLockAuthenticator
        self.eudiWallet = eudiWallet
        self.eudiAvailability = eudiAvailability
        self.eudiInitializer = eudiInitializer
        self.openID4VCWallet = openID4VCWallet
    }

    static func make(configuration: AppConfiguration = .current()) -> Result<WalletAppDependencies, Error> {
#if DEBUG
        switch configuration.fixture {
        case .empty:
            return .success(fixture(credentials: [], events: []))
        case .populated:
            return .success(populatedFixture())
        case .storageFailure:
            return .failure(FixtureError.storageUnavailable)
        case .production:
            break
        }
#endif
        return Result {
            let root = try FileManager.default.url(
                for: .applicationSupportDirectory,
                in: .userDomainMask,
                appropriateFor: nil,
                create: true
            ).appendingPathComponent("OARIWallet", isDirectory: true)
            let keyStore = CachedVaultKeyStore(
                wrapping: KeychainVaultKeyStore(service: "io.oari.wallet.vault")
            )
            let metadataRepository = try EncryptedCredentialMetadataRepository(
                directory: root.appendingPathComponent("credential-metadata", isDirectory: true),
                keyStore: keyStore
            )
            let auditRepository = try EncryptedAuditRepository(
                directory: root.appendingPathComponent("audit", isDirectory: true),
                keyStore: keyStore
            )
            let eudiInitializer: EudiInitializer = {
                await Task.detached(priority: .utility) {
                    do {
                        let startedAt = ContinuousClock.now
                        let recoveryStore = try EncryptedWalletOperationRecoveryStore(
                            directory: root.appendingPathComponent("eudi-operation-recovery", isDirectory: true),
                            keyStore: keyStore
                        )
                        let attestationProvider = ReferenceDemoWalletAttestationsProvider()
                        let demo = try EudiReferenceDemoConfiguration.makeWalletConfiguration(
                            attestationProvider: attestationProvider
                        )
                        Self.eudiLogger.info(
                            "Reference Demo configuration ready in \(startedAt.duration(to: .now), privacy: .public)"
                        )
                        let adapterStartedAt = ContinuousClock.now
                        let operationalConfiguration = try EudiOperationalConfiguration(
                            clientID: EudiReferenceDemoConfiguration.clientID,
                            authorizationRedirectURI: EudiReferenceDemoConfiguration.redirectURI,
                            attestationProvider: attestationProvider,
                            auditRepository: auditRepository,
                            auditPolicy: .productionConsent,
                            auditPolicyVersion: AuditPolicyVersion(rawValue: 1),
                            metadataRepository: metadataRepository,
                            recoveryStore: recoveryStore,
                            statusProvider: ReferenceDemoCredentialStatusProvider(),
                            allowedIssuerOrigins: EudiReferenceDemoConfiguration.issuerOrigins,
                            allowedVerifierOrigins: [
                                "https://verifier.eudiw.dev",
                                "https://verifier-backend.eudiw.dev",
                            ],
                            allowedApplicationRedirectOrigins: ["https://wallet-provider.eudiw.dev"],
                            allowUnregisteredDevelopmentCounterparties: true
                        )
                        let adapter = try demo.baseline.makeWallet(
                            trustProfileID: EudiReferenceDemoConfiguration.profileID,
                            operationalConfiguration: operationalConfiguration
                        )
                        Self.eudiLogger.info(
                            "Wallet Kit constructed in \(adapterStartedAt.duration(to: .now), privacy: .public)"
                        )
                        return .success(LiveEudiWalletService(adapter: adapter))
                    } catch {
                        return .failure(String(describing: error))
                    }
                }.value
            }
            let openID4VCWallet = try makeW3CWallet(
                root: root,
                keyStore: keyStore,
                metadataRepository: metadataRepository,
                auditRepository: auditRepository
            )
            return WalletAppDependencies(
                credentials: metadataRepository,
                audit: auditRepository,
                localAuthenticator: SystemLocalAuthenticator(),
                eudiWallet: nil,
                eudiAvailability: .configurationRequired("EUDI Reference Demo is initializing…"),
                eudiInitializer: eudiInitializer,
                openID4VCWallet: openID4VCWallet
            )
        }
    }

    private static func makeW3CWallet(
        root: URL,
        keyStore: any VaultKeyStore,
        metadataRepository: any CredentialMetadataRepository,
        auditRepository: any AuditRepository
    ) throws -> any OpenID4VCOperating {
        let composition = try W3CBackendComposition.make()
        let endpointRegistry = try EBSIEndpointRegistry(
            policy: composition.environmentPolicy,
            endpoints: [composition.endpoint],
            approvedProductionEndpoints: composition.approvedProductionEndpoints
        )
        let registryClient = try MultiEndpointEBSIRegistryClient(
            registry: endpointRegistry,
            httpClient: URLSessionBoundedHTTPSClient()
        )
        let openID4VCStore = try EncryptedEbsiCredentialStore(
            directory: root.appendingPathComponent("ebsi-credentials", isDirectory: true),
            keyStore: keyStore
        )
        let transport = URLSessionOpenID4VCTransport()
        let resolver = CompositeDIDResolver(ebsi: EBSIDIDResolver(client: registryClient))
        let keyProvider = DeviceBoundKeyProvider(applicationTagPrefix: "io.oari.wallet.ebsi.key")
        let replayProtection = try EncryptedOpenID4VPReplayStore(
            directory: root.appendingPathComponent("presentation-replay", isDirectory: true),
            keyStore: keyStore
        )
        let deferredRepository = try EncryptedDeferredIssuanceRepository(
            directory: root.appendingPathComponent("deferred-issuance", isDirectory: true),
            keyStore: keyStore
        )
        let backend = OpenID4VCW3CBackend(
            transport: transport,
            trustEvaluator: HTTPSCredentialIssuerServiceTrustEvaluator(),
            credentialSignerTrustEvaluator: EBSITIRCredentialSignerTrustEvaluator(
                tirBaseURL: composition.endpoint.trustedIssuersRegistryURL,
                transport: transport,
                resolver: resolver
            ),
            keyProvider: keyProvider,
            credentialStore: openID4VCStore,
            credentialValidator: NativeW3CCredentialValidator(
                resolver: resolver, transport: transport, allowsDIDIssuerDelegation: true
            ),
            profile: try .vcdm2JWTVC(),
            clientConfiguration: try OpenID4VCClientConfiguration(
                clientID: W3CBackendComposition.authorizationClientID,
                redirectURI: W3CBackendComposition.authorizationRedirectURI
            ),
            additionalProfiles: try W3CBackendComposition.additionalProfiles(),
            clientSecurity: DefaultOID4VCIClientSecurity(
                keyProvider: DeviceBoundKeyProvider(applicationTagPrefix: "io.oari.wallet.oid4vci.security")
            ),
            transportProfileRegistry: composition.transportProfileRegistry,
            holderIdentityProvider: PersistentW3CHolderIdentityProvider(
                keyProvider: keyProvider, referenceStore: KeychainW3CHolderIdentityReferenceStore()
            ),
            presentationRequestValidator: NativeOpenID4VPRequestObjectValidator(resolver: resolver),
            presentationReplayProtection: replayProtection,
            trustEnvironment: composition.environmentPolicy == .production ? .production : .development
        )
        return LiveOpenID4VCService(
            backend: backend,
            metadata: metadataRepository,
            audit: auditRepository,
            deferredRepository: deferredRepository
        )
    }

#if DEBUG
    private static func fixture(
        credentials: [CredentialRecord],
        events: [AuditEvent]
    ) -> WalletAppDependencies {
        WalletAppDependencies(
            credentials: FixtureCredentialRepository(credentials: credentials),
            audit: FixtureAuditRepository(events: events),
            localAuthenticator: FixtureLocalAuthenticator(),
            eudiWallet: nil,
            eudiAvailability: .configurationRequired("Preview mode does not contact credential services."),
            openID4VCWallet: nil
        )
    }

    private static func populatedFixture() -> WalletAppDependencies {
        let date = Date(timeIntervalSince1970: 1_754_524_800)
        let record = CredentialRecord(
            configurationID: "exampleLegalPersonID",
            displayName: "Example Legal Person ID",
            format: .jwtVC,
            profileID: "openid4vc-final-vcdm2-jwt-vc-ebsi-1",
            issuerIdentifier: "did:ebsi:fixture-issuer",
            cryptographicValidity: .valid,
            issuerTrust: .trusted,
            status: .valid,
            legalClassification: .provisional,
            issuedAt: date,
            expiresAt: date.addingTimeInterval(31_536_000),
            createdAt: date
        )
        return fixture(
            credentials: [record],
            events: [
                AuditEvent(
                    operation: .issuance,
                    outcome: .completed,
                    occurredAt: date,
                    credentialIDs: [record.id],
                    policy: .development,
                    policyVersion: AuditPolicyVersion(rawValue: 1)
                ),
            ]
        )
    }
#endif
}

enum EudiInitializationResult: Sendable {
    case success(any EudiWalletOperating)
    case failure(String)
}

#if DEBUG
private enum FixtureError: Error { case storageUnavailable }
private struct FixtureLocalAuthenticator: LocalAuthenticator {
    func authenticate(reason: String) async throws {}
}

private actor FixtureCredentialRepository: CredentialMetadataRepository {
    private var storage: [CredentialID: CredentialRecord]

    init(credentials: [CredentialRecord]) {
        storage = Dictionary(uniqueKeysWithValues: credentials.map { ($0.id, $0) })
    }

    func credentials() async throws -> [CredentialRecord] {
        storage.values.sorted { $0.createdAt > $1.createdAt }
    }

    func saveMetadata(_ credential: CredentialRecord) async throws {
        storage[credential.id] = credential
    }
    func replaceMetadata(_ credential: CredentialRecord) async throws {
        storage[credential.id] = credential
    }
    func deleteMetadata(id: CredentialID) async throws { storage[id] = nil }
}

private actor FixtureAuditRepository: AuditRepository {
    private var storage: [AuditEvent]
    init(events: [AuditEvent]) { storage = events }
    func events() async throws -> [AuditEvent] { storage }
    func append(_ event: AuditEvent) async throws { storage.append(event) }
    func deleteAll() async throws { storage = [] }
}
#endif
