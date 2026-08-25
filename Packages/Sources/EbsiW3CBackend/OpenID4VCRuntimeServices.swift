import CryptoKit
import Foundation
import IdentityDomain
import TrustDomain

public final class URLSessionOpenID4VCTransport: NSObject, OpenID4VCHTTPTransport, URLSessionTaskDelegate, @unchecked Sendable {
    private lazy var session: URLSession = {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.httpShouldSetCookies = false
        configuration.httpCookieAcceptPolicy = .never
        configuration.urlCache = nil
        configuration.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        return URLSession(configuration: configuration, delegate: self, delegateQueue: nil)
    }()

    public override init() {}

    public func send(
        url: URL,
        method: String,
        headers: [String: String],
        body: Data?
    ) async throws -> OpenID4VCHTTPResponse {
        try Self.validatePublicHTTPS(url)
        var request = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 30)
        request.httpMethod = method
        request.httpBody = body
        request.allHTTPHeaderFields = headers
        let (bytes, response) = try await session.bytes(for: request)
        guard let response = response as? HTTPURLResponse,
              !(300..<400).contains(response.statusCode) else {
            throw OpenID4VCBackendError.invalidResponse
        }
        var data = Data()
        data.reserveCapacity(max(0, min(Int(response.expectedContentLength), 1_048_576)))
        for try await byte in bytes {
            guard data.count < 1_048_576 else { throw OpenID4VCBackendError.invalidResponse }
            data.append(byte)
        }
        let responseHeaders = response.allHeaderFields.reduce(into: [String: String]()) {
            if let key = $1.key as? String { $0[key] = String(describing: $1.value) }
        }
        return OpenID4VCHTTPResponse(statusCode: response.statusCode, body: data, headers: responseHeaders)
    }

    public func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping (URLRequest?) -> Void
    ) {
        completionHandler(nil)
    }

    private static func validatePublicHTTPS(_ url: URL) throws {
        guard let scheme = url.scheme?.lowercased(), let host = url.host?.lowercased(),
              scheme == "https" || (scheme == "http" && (host == "127.0.0.1" || host == "localhost")),
              url.user == nil, url.password == nil, url.fragment == nil,
              host != "localhost", host != "::1", !host.hasSuffix(".local"),
              !Self.isPrivateIPv4Literal(host), !Self.isReservedIPv6Literal(host) else {
            throw OpenID4VCBackendError.unsafeEndpoint
        }
    }

    private static func isPrivateIPv4Literal(_ host: String) -> Bool {
        let parts = host.split(separator: ".").compactMap { UInt8($0) }
        guard parts.count == 4 else { return false }
        return parts[0] == 10 || parts[0] == 127 ||
            (parts[0] == 169 && parts[1] == 254) ||
            (parts[0] == 172 && (16...31).contains(parts[1])) ||
            (parts[0] == 192 && parts[1] == 168) || parts[0] >= 224
    }

    private static func isReservedIPv6Literal(_ host: String) -> Bool {
        guard host.contains(":") else { return false }
        let value = host.lowercased()
        return value == "::" || value == "::1" || value.hasPrefix("fc") ||
            value.hasPrefix("fd") || value.hasPrefix("fe8") || value.hasPrefix("fe9") ||
            value.hasPrefix("fea") || value.hasPrefix("feb") || value.hasPrefix("ff")
    }
}

/// Trust boundary for the OpenID4VCI HTTPS service itself. Metadata and endpoint
/// origin binding are enforced by the backend before this evaluator is called;
/// accreditation of the credential signer is evaluated separately after the
/// signed credential has been received and verified.
public struct HTTPSCredentialIssuerServiceTrustEvaluator: CredentialIssuerServiceTrustEvaluating, Sendable {
    public init() {}

    public func evaluate(issuer: String, at date: Date) async -> TrustVerdict {
        guard let url = URL(string: issuer),
              url.scheme?.lowercased() == "https",
              url.host != nil,
              url.user == nil,
              url.password == nil,
              url.query == nil,
              url.fragment == nil else {
            return .invalid(reasons: [.malformedEvidence], evidence: [])
        }
        let digest = SHA256.hash(data: Data(issuer.utf8)).map { String(format: "%02x", $0) }.joined()
        return .trusted(evidence: [TrustEvidence(
            source: .ebsiRegistry,
            sourceIdentifier: issuer,
            result: .valid,
            checkedAt: date,
            expiresAt: date.addingTimeInterval(300),
            evidenceDigest: digest
        )])
    }
}

public struct EBSITIRCredentialSignerTrustEvaluator: CredentialIssuerServiceTrustEvaluating, Sendable {
    private let tirBaseURL: URL
    private let transport: any OpenID4VCHTTPTransport
    private let resolver: (any DIDResolver)?
    private let approvedIssuerDIDs: Set<String>?

    public init(
        tirBaseURL: URL,
        transport: any OpenID4VCHTTPTransport,
        resolver: any DIDResolver,
        approvedIssuerDIDs: Set<String>? = nil
    ) {
        self.tirBaseURL = tirBaseURL
        self.transport = transport
        self.resolver = resolver
        self.approvedIssuerDIDs = approvedIssuerDIDs
    }

    public func evaluate(issuer: String, at date: Date) async -> TrustVerdict {
        guard Self.isSafeEBSIDID(issuer), Self.isSafeCollectionURL(tirBaseURL),
              let resolver else {
            return .untrusted(reasons: [.issuerNotAccredited], evidence: [])
        }
        if let approvedIssuerDIDs, !approvedIssuerDIDs.contains(issuer) {
            return .untrusted(reasons: [.issuerNotAccredited], evidence: [])
        }

        let issuerURL = tirBaseURL.appendingPathComponent(issuer, isDirectory: false)
        var evidenceData = Data()
        do {
            let issuerResponse = try await transport.send(
                url: issuerURL, method: "GET", headers: [:], body: nil
            )
            evidenceData.append(issuerResponse.body)
            guard issuerResponse.statusCode == 200 else {
                return issuerResponse.statusCode == 404
                    ? Self.untrustedEvidence(for: tirBaseURL, body: evidenceData, at: date)
                    : .indeterminate(reasons: [.trustSourceUnavailable], evidence: [])
            }
            guard let registration = try? JSONDecoder().decode(
                TIRIssuerRegistration.self, from: issuerResponse.body
            ), registration.did == issuer else {
                return .indeterminate(reasons: [.malformedEvidence], evidence: [])
            }
            guard registration.hasAttributes else {
                return Self.untrustedEvidence(for: tirBaseURL, body: evidenceData, at: date)
            }

            // Never dereference the registry's `attributes` or `href` values:
            // deployed registries may advertise http URLs. Build every URL from
            // the pinned HTTPS collection and validated opaque identifiers.
            let attributesURL = issuerURL.appendingPathComponent("attributes", isDirectory: false)
            let listResponse = try await transport.send(
                url: attributesURL, method: "GET", headers: [:], body: nil
            )
            evidenceData.append(listResponse.body)
            guard listResponse.statusCode == 200 else {
                return listResponse.statusCode == 404
                    ? Self.untrustedEvidence(for: tirBaseURL, body: evidenceData, at: date)
                    : .indeterminate(reasons: [.trustSourceUnavailable], evidence: [])
            }
            guard let list = try? JSONDecoder().decode(TIRAttributeList.self, from: listResponse.body),
                  list.items.count <= 100 else {
                return .indeterminate(reasons: [.malformedEvidence], evidence: [])
            }
            guard !list.items.isEmpty else {
                return Self.untrustedEvidence(for: tirBaseURL, body: evidenceData, at: date)
            }

            var sourceUnavailable = false
            for item in list.items where Self.isSafeAttributeID(item.id) {
                let attributeURL = attributesURL.appendingPathComponent(item.id, isDirectory: false)
                do {
                    let response = try await transport.send(
                        url: attributeURL, method: "GET", headers: [:], body: nil
                    )
                    evidenceData.append(response.body)
                    guard response.statusCode == 200 else {
                        sourceUnavailable = sourceUnavailable || response.statusCode >= 500
                        continue
                    }
                    guard let envelope = try? JSONDecoder().decode(TIRAttributeEnvelope.self, from: response.body),
                          envelope.did == issuer,
                          await Self.isValidAccreditation(
                            envelope.attribute.body,
                            registeredIssuer: issuer,
                            resolver: resolver,
                            at: date
                          ) else { continue }
                    let evidence = Self.evidence(
                        for: tirBaseURL, result: .valid, body: evidenceData, at: date
                    )
                    return .trusted(evidence: [evidence])
                } catch {
                    sourceUnavailable = true
                }
            }
            if sourceUnavailable {
                return .indeterminate(reasons: [.trustSourceUnavailable], evidence: [])
            }
            let evidence = Self.evidence(for: tirBaseURL, result: .invalid, body: evidenceData, at: date)
            return .invalid(reasons: [.invalidSignature], evidence: [evidence])
        } catch {
            return .indeterminate(reasons: [.trustSourceUnavailable], evidence: [])
        }
    }

    private static func isValidAccreditation(
        _ jwt: String,
        registeredIssuer: String,
        resolver: any DIDResolver,
        at date: Date
    ) async -> Bool {
        guard let payload = decodeJWTPayload(jwt),
              let signer = payload["iss"]?.string,
              isSafeEBSIDID(signer),
              payload["sub"]?.string == registeredIssuer,
              let expiration = payload["exp"]?.numericValue,
              expiration.isFinite, expiration > date.timeIntervalSince1970,
              let notBefore = payload["nbf"]?.numericValue,
              notBefore.isFinite, notBefore <= date.timeIntervalSince1970,
              let inspected = inspectAccreditation(jwt, payload: payload, at: date),
               containsString(inspected.credential["type"], "VerifiableAccreditation"),
               credentialIssuer(inspected.credential["issuer"]) == signer,
               credentialSubjects(inspected.credential["credentialSubject"]).contains(registeredIssuer),
               let expirationDateValue = inspected.credential[inspected.expirationProperty]?.string,
               let expirationDate = parseVCDMDate(expirationDateValue),
               expirationDate > date,
               abs(expirationDate.timeIntervalSince1970 - expiration) <= 1,
               let issuanceDateValue = inspected.credential[inspected.issuanceProperty]?.string,
               let issuanceDate = parseVCDMDate(issuanceDateValue),
               issuanceDate <= date,
               abs(issuanceDate.timeIntervalSince1970 - notBefore) <= 1,
               let document = try? await resolver.resolve(signer),
              document.id == signer,
              let methods = try? verificationMethods(in: document), !methods.isEmpty else {
            return false
        }
        return (try? EbsiJWSVerifier().verify(
            compactJWS: jwt,
            methods: methods,
            requirements: EbsiJWSRequirements(
                 allowedAlgorithms: [.es256, .es256K, .rs256],
                requiredRelationship: .assertionMethod,
                expectedController: signer,
                 expectedIssuer: signer,
                 expectedType: inspected.isVCDM2 ? "vc+jwt" : nil,
                validationDate: date
            )
        )) != nil
    }

    private static func inspectAccreditation(
        _ jwt: String,
        payload: [String: AnySendableJSON],
        at date: Date
    ) -> (credential: [String: AnySendableJSON], issuanceProperty: String, expirationProperty: String, isVCDM2: Bool)? {
        if payload["vc"] != nil {
            guard let profile = try? EbsiCredentialProfile.vcdm11Jwt(),
                  let credential = try? EbsiCredentialInspector().inspectCompactJWT(
                    jwt, profile: profile, validationDate: date
                  ) else { return nil }
            return (credential, "issuanceDate", "expirationDate", false)
        }
        guard let profile = try? EbsiCredentialProfile(
            id: "ebsi-tir-vcdm2-accreditation",
            dataModel: .v2_0,
            representation: .vcdm2Jwt,
            allowedAlgorithms: [.es256, .es256K, .rs256],
            context: "https://www.w3.org/ns/credentials/v2"
        ), let credential = try? EbsiCredentialInspector().inspectCompactJWT(
            jwt, profile: profile, validationDate: date
        ) else { return nil }
        return (credential, "validFrom", "validUntil", true)
    }

    private static func parseVCDMDate(_ value: String) -> Date? {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let date = formatter.date(from: value) { return date }
        formatter.formatOptions = [.withInternetDateTime]
        return formatter.date(from: value)
    }

    private static func containsString(_ value: AnySendableJSON?, _ expected: String) -> Bool {
        switch value {
        case let .string(item): item == expected
        case let .array(items): items.contains {
            if case let .string(item) = $0 { return item == expected }
            return false
        }
        default: false
        }
    }

    private static func verificationMethods(in document: DIDDocument) throws -> [EbsiVerificationMethod] {
        try document.verificationMethod.map { method in
            guard method.publicKeyJwk.kty == "EC", let y = method.publicKeyJwk.y else {
                throw EbsiCredentialError.algorithmNotAllowed
            }
            let key: EbsiVerificationKey = switch method.publicKeyJwk.crv {
            case "P-256": .p256(x: try decodeBase64URL(method.publicKeyJwk.x), y: try decodeBase64URL(y))
            case "secp256k1": .secp256k1(x: try decodeBase64URL(method.publicKeyJwk.x), y: try decodeBase64URL(y))
            default: throw EbsiCredentialError.algorithmNotAllowed
            }
            return EbsiVerificationMethod(
                id: method.id,
                controller: method.controller,
                key: key,
                relationships: document.assertionMethod.contains(method.id) ? [.assertionMethod] : []
            )
        }
    }

    private static func decodeJWTPayload(_ jwt: String) -> [String: AnySendableJSON]? {
        let parts = jwt.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 3, let data = try? decodeBase64URL(String(parts[1])) else { return nil }
        return try? JSONDecoder().decode([String: AnySendableJSON].self, from: data)
    }

    private static func decodeBase64URL(_ value: String) throws -> Data {
        var encoded = value.replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        encoded += String(repeating: "=", count: (4 - encoded.count % 4) % 4)
        guard let data = Data(base64Encoded: encoded) else { throw EbsiCredentialError.malformedCredential }
        return data
    }

    private static func credentialIssuer(_ value: AnySendableJSON?) -> String? {
        value?.string ?? value?.object?["id"]?.string
    }

    private static func credentialSubjects(_ value: AnySendableJSON?) -> [String] {
        switch value {
        case let .object(subject): subject["id"]?.string.map { [$0] } ?? []
        case let .array(subjects): subjects.compactMap { $0.object?["id"]?.string }
        default: []
        }
    }

    private static func isSafeCollectionURL(_ url: URL) -> Bool {
        url.scheme?.lowercased() == "https" && url.host != nil &&
            url.user == nil && url.password == nil && url.query == nil && url.fragment == nil &&
            url.lastPathComponent == "issuers"
    }

    private static func isSafeEBSIDID(_ did: String) -> Bool {
        let prefix = "did:ebsi:"
        guard did.hasPrefix(prefix), did.count > prefix.count else { return false }
        return did.dropFirst(prefix.count).unicodeScalars.allSatisfy {
            CharacterSet.alphanumerics.contains($0)
        }
    }

    private static func isSafeAttributeID(_ id: String) -> Bool {
        !id.isEmpty && id.count <= 128 && id.unicodeScalars.allSatisfy {
            CharacterSet.alphanumerics.contains($0) || $0 == "-" || $0 == "_"
        }
    }

    private static func evidence(
        for source: URL, result: TrustEvidenceResult, body: Data, at date: Date
    ) -> TrustEvidence {
        TrustEvidence(
            source: .ebsiRegistry,
            sourceIdentifier: source.absoluteString,
            result: result,
            checkedAt: date,
            expiresAt: date.addingTimeInterval(300),
            evidenceDigest: SHA256.hash(data: body).map { String(format: "%02x", $0) }.joined()
        )
    }

    private static func untrustedEvidence(for source: URL, body: Data, at date: Date) -> TrustVerdict {
        .untrusted(
            reasons: [.issuerNotAccredited],
            evidence: [evidence(for: source, result: .notFound, body: body, at: date)]
        )
    }
}

private struct TIRIssuerRegistration: Decodable {
    let did: String
    let hasAttributes: Bool
}

private struct TIRAttributeList: Decodable {
    struct Item: Decodable { let id: String }
    let items: [Item]
}

private struct TIRAttributeEnvelope: Decodable {
    struct Attribute: Decodable { let body: String }
    let did: String
    let attribute: Attribute
}

public struct NativeW3CCredentialValidator: W3CCredentialValidating, Sendable {
    private let resolver: any DIDResolver
    private let transport: (any OpenID4VCHTTPTransport)?
    private let allowsDIDIssuerDelegation: Bool

    public init(
        resolver: any DIDResolver,
        transport: (any OpenID4VCHTTPTransport)? = nil,
        allowsDIDIssuerDelegation: Bool = false
    ) {
        self.resolver = resolver
        self.transport = transport
        self.allowsDIDIssuerDelegation = allowsDIDIssuerDelegation
    }

    public func validate(
        rawCredential: Data,
        profile: EbsiCredentialProfile,
        expectedIssuer: String? = nil,
        expectedHolderDID: String,
        at date: Date
    ) async throws -> String {
        let compact = String(decoding: rawCredential, as: UTF8.self)
        if profile.representation == .dcSdJwt || profile.representation == .vcdm2SdJwt {
            let payload = try EbsiCredentialInspector().inspectSDJWT(
                compact,
                requiresHolderBinding: profile.requiresSDJWTHolderBinding
            )
            let issuer = try Self.issuer(fromSDJWT: payload)
            try validateIssuerBinding(signedIssuer: issuer, expectedIssuer: expectedIssuer)
            let methods = try await verificationMethods(for: issuer)
            do {
                _ = try EbsiJWSVerifier().verify(
                    compactJWS: String(compact.split(separator: "~").first!),
                    methods: methods,
                    requirements: EbsiJWSRequirements(
                        allowedAlgorithms: profile.allowedAlgorithms,
                        requiredRelationship: .assertionMethod,
                        expectedController: issuer,
                        expectedIssuer: issuer,
                        validationDate: date
                    )
                )
            } catch EbsiCredentialError.algorithmNotAllowed {
                throw EbsiCredentialError.algorithmNotAllowed
            } catch {
                throw EbsiCredentialError.invalidSignature
            }
            return issuer
        }
        let credential = try EbsiCredentialInspector().inspectCompactJWT(
            compact,
            profile: profile,
            validationDate: date
        )
        let issuer = try Self.issuer(from: credential)
        try validateIssuerBinding(signedIssuer: issuer, expectedIssuer: expectedIssuer)
        let methods = try await verificationMethods(for: issuer)
        do {
            _ = try EbsiJWSVerifier().verify(
                compactJWS: compact,
                methods: methods,
                requirements: EbsiJWSRequirements(
                    allowedAlgorithms: profile.allowedAlgorithms,
                    requiredRelationship: .assertionMethod,
                    expectedController: issuer,
                    // VCDM 1.1 JWT VC keeps its legacy nested `vc` behavior;
                    // VC-JOSE registered claims are consistency-checked by the
                    // VCDM2 inspector when they are present.
                    expectedIssuer: nil,
                    expectedType: profile.representation == .vcdm2Jwt ? "vc+jwt" : nil,
                    validationDate: date
                )
            )
        } catch EbsiCredentialError.algorithmNotAllowed { throw EbsiCredentialError.algorithmNotAllowed }
        catch { throw EbsiCredentialError.invalidSignature }
        guard Self.subjectIDs(from: credential).contains(expectedHolderDID) else {
            throw EbsiCredentialError.invalidHolderBinding
        }
        return issuer
    }

    private func validateIssuerBinding(signedIssuer: String, expectedIssuer: String?) throws {
        // OpenID4VCI's credential issuer URL and the VC issuer identifier may
        // differ (for example, an HTTPS issuer endpoint issuing for a DID).
        guard let expectedIssuer else { return }
        if signedIssuer == expectedIssuer { return }
        guard allowsDIDIssuerDelegation, signedIssuer.hasPrefix("did:") else {
            throw EbsiCredentialError.issuerMismatch
        }
    }

    private static func issuer(from credential: [String: AnySendableJSON]) throws -> String {
        if let issuer = credential["issuer"]?.string { return issuer }
        if let issuer = credential["issuer"]?.object?["id"]?.string { return issuer }
        throw EbsiCredentialError.profileMismatch
    }

    private static func issuer(fromSDJWT payload: [String: AnySendableJSON]) throws -> String {
        guard let issuer = payload["iss"]?.string else { throw EbsiCredentialError.profileMismatch }
        return issuer
    }

    private static func subjectIDs(from credential: [String: AnySendableJSON]) -> [String] {
        switch credential["credentialSubject"] {
        case let .object(subject): return subject["id"]?.string.map { [$0] } ?? []
        case let .array(subjects): return subjects.compactMap { $0.object?["id"]?.string }
        default: return []
        }
    }

    private static func decodeBase64URL(_ value: String) throws -> Data {
        var value = value.replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        value += String(repeating: "=", count: (4 - value.count % 4) % 4)
        guard let result = Data(base64Encoded: value) else { throw EbsiCredentialError.malformedCredential }
        return result
    }

    private func verificationMethods(for issuer: String) async throws -> [EbsiVerificationMethod] {
        if issuer.hasPrefix("did:") {
            let document: DIDDocument
            do {
                document = try await resolver.resolve(issuer)
            } catch {
                throw EbsiCredentialError.issuerDIDUnresolved
            }
            let methods = try document.verificationMethod.compactMap { method -> EbsiVerificationMethod? in
                guard method.publicKeyJwk.kty == "EC", let encodedY = method.publicKeyJwk.y else {
                    return nil
                }
                let key: EbsiVerificationKey
                switch method.publicKeyJwk.crv {
                case "P-256":
                    key = .p256(
                        x: try Self.decodeBase64URL(method.publicKeyJwk.x),
                        y: try Self.decodeBase64URL(encodedY)
                    )
                case "secp256k1":
                    key = .secp256k1(
                        x: try Self.decodeBase64URL(method.publicKeyJwk.x),
                        y: try Self.decodeBase64URL(encodedY)
                    )
                default:
                    return nil
                }
                var relationships: Set<EbsiVerificationRelationship> = []
                if document.assertionMethod.contains(method.id) { relationships.insert(.assertionMethod) }
                if document.authentication.contains(method.id) { relationships.insert(.authentication) }
                return EbsiVerificationMethod(
                    id: method.id,
                    controller: method.controller,
                    key: key,
                    relationships: relationships
                )
            }
            guard !methods.isEmpty else { throw EbsiCredentialError.algorithmNotAllowed }
            return methods
        }
        guard let issuerURL = URL(string: issuer),
              issuerURL.scheme?.lowercased() == "https",
              issuerURL.host != nil,
              issuerURL.user == nil,
              issuerURL.password == nil,
              issuerURL.query == nil,
              issuerURL.fragment == nil,
              let transport else {
            throw EbsiCredentialError.issuerSigningKeysUnresolved
        }

        let metadataURLs = Self.issuerMetadataURLs(for: issuerURL)
        for metadataURL in metadataURLs {
            let metadataResponse: OpenID4VCHTTPResponse
            do {
                metadataResponse = try await transport.send(
                    url: metadataURL,
                    method: "GET",
                    headers: [:],
                    body: nil
                )
            } catch {
                continue
            }
            guard metadataResponse.statusCode == 200,
                  let metadata = try? JSONDecoder().decode(JWTIssuerMetadata.self, from: metadataResponse.body),
                  metadata.issuer == issuer,
                  let jwksURL = URL(string: metadata.jwksURI),
                  jwksURL.scheme?.lowercased() == "https",
                  jwksURL.host?.lowercased() == issuerURL.host?.lowercased(),
                  jwksURL.port == issuerURL.port,
                  jwksURL.user == nil,
                  jwksURL.password == nil else {
                continue
            }

            let keysResponse: OpenID4VCHTTPResponse
            do {
                keysResponse = try await transport.send(url: jwksURL, method: "GET", headers: [:], body: nil)
            } catch {
                throw EbsiCredentialError.issuerSigningKeysUnresolved
            }
            guard keysResponse.statusCode == 200,
                  let set = try? JSONDecoder().decode(JWKSet.self, from: keysResponse.body) else {
                throw EbsiCredentialError.issuerSigningKeysUnresolved
            }
            let signingKeys = set.keys.filter {
                $0.kty == "EC" && $0.crv == "P-256" &&
                    ($0.use == nil || $0.use == "sig") &&
                    ($0.alg == nil || $0.alg == "ES256")
            }
            guard !signingKeys.isEmpty else { throw EbsiCredentialError.algorithmNotAllowed }
            let keyIDs = signingKeys.compactMap(\.kid)
            guard keyIDs.count == signingKeys.count,
                  Set(keyIDs).count == keyIDs.count else {
                throw EbsiCredentialError.issuerSigningKeysUnresolved
            }
            return try signingKeys.map { key in
                guard let kid = key.kid, !kid.isEmpty,
                      let x = key.x, let y = key.y else {
                    throw EbsiCredentialError.issuerSigningKeysUnresolved
                }
                return EbsiVerificationMethod(
                    id: kid,
                    controller: issuer,
                    key: .p256(
                        x: try Self.decodeBase64URL(x),
                        y: try Self.decodeBase64URL(y)
                    ),
                    relationships: [.assertionMethod]
                )
            }
        }
        throw EbsiCredentialError.issuerSigningKeysUnresolved
    }

    private static func issuerMetadataURLs(for issuerURL: URL) -> [URL] {
        func standard(_ name: String) -> URL? {
            var components = URLComponents()
            components.scheme = issuerURL.scheme
            components.host = issuerURL.host
            components.port = issuerURL.port
            components.path = "/.well-known/\(name)" + issuerURL.path
            return components.url
        }

        return [
            standard("jwt-vc-issuer"),
            standard("oauth-authorization-server"),
            standard("openid-configuration"),
            issuerURL.appendingPathComponent(".well-known/openid-configuration"),
            issuerURL.appendingPathComponent(".well-known/oauth-authorization-server"),
        ].compactMap { $0 }
    }
}

private struct JWTIssuerMetadata: Decodable {
    let issuer: String?
    let jwksURI: String
    enum CodingKeys: String, CodingKey { case issuer, jwksURI = "jwks_uri" }
}

private struct JWKSet: Decodable {
    struct Key: Decodable {
        let kid: String?
        let kty: String?
        let crv: String?
        let x: String?
        let y: String?
        let use: String?
        let alg: String?
    }
    let keys: [Key]
}
