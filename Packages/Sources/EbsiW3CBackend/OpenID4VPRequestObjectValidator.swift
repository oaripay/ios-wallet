import Foundation
import IdentityDomain

public struct OpenID4VPTransactionData: Equatable, Sendable {
    public let encoded: String
    public let decoded: [String: AnySendableJSON]

    public init(encoded: String, decoded: [String: AnySendableJSON]) {
        self.encoded = encoded
        self.decoded = decoded
    }
}

public struct VerifiedOpenID4VPRequestObject: Equatable, Sendable {
    public let clientID: String
    /// The `iss` claim of the Request Object. OpenID4VP requires wallets to
    /// ignore it for identification, but it is retained so callers can accept
    /// the dynamic-discovery audience rule (`aud` == `iss`) from Section 5.8.
    public let issuer: String?
    public let audience: String?
    public let responseType: String?
    public let responseMode: String
    public let responseURI: String?
    public let nonce: String
    public let state: String?
    public let dcqlQuery: [String: AnySendableJSON]
    /// Presentation signing algorithms advertised by the verifier, keyed by credential format.
    public let vpFormatsSupported: [String: Set<String>]?
    /// DID that controlled the verification method used for the Request Object.
    /// `nil` when the Client Identifier Prefix does not provide a verifiable
    /// key (for example `redirect_uri:`), in which case the caller must anchor
    /// trust in the envelope instead (response URI binding).
    public let signingDID: String?
    public let issuedAt: Date?
    public let expiresAt: Date?
    /// Exact encoded and decoded `transaction_data` entries.
    public let transactionData: [OpenID4VPTransactionData]

    public init(
        clientID: String,
        issuer: String? = nil,
        audience: String? = nil,
        responseType: String? = nil,
        responseMode: String,
        responseURI: String?,
        nonce: String,
        state: String?,
        dcqlQuery: [String: AnySendableJSON],
        vpFormatsSupported: [String: Set<String>]? = nil,
        signingDID: String? = nil,
        issuedAt: Date? = nil,
        expiresAt: Date? = nil,
        transactionData: [OpenID4VPTransactionData] = []
    ) {
        self.clientID = clientID
        self.issuer = issuer
        self.audience = audience
        self.responseType = responseType
        self.responseMode = responseMode
        self.responseURI = responseURI
        self.nonce = nonce
        self.state = state
        self.dcqlQuery = dcqlQuery
        self.vpFormatsSupported = vpFormatsSupported
        self.signingDID = signingDID
        self.issuedAt = issuedAt
        self.expiresAt = expiresAt
        self.transactionData = transactionData
    }
}

public protocol OpenID4VPRequestObjectValidating: Sendable {
    func validate(compactJWT: String, at date: Date) async throws -> VerifiedOpenID4VPRequestObject
}

public struct NativeOpenID4VPRequestObjectValidator: OpenID4VPRequestObjectValidating {
    private let resolver: any DIDResolver

    public init(resolver: any DIDResolver) { self.resolver = resolver }

    public func validate(compactJWT: String, at date: Date) async throws -> VerifiedOpenID4VPRequestObject {
        let parts = compactJWT.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 3,
              let headerData = Self.decodeBase64URL(String(parts[0])),
              let payloadData = Self.decodeBase64URL(String(parts[1])),
              let header = try? JSONDecoder().decode([String: AnySendableJSON].self, from: headerData),
              let payload = try? JSONDecoder().decode([String: AnySendableJSON].self, from: payloadData),
              header["typ"]?.string == "oauth-authz-req+jwt",
              let clientID = payload["client_id"]?.string,
               let responseMode = payload["response_mode"]?.string,
               let nonce = payload["nonce"]?.string,
               let dcqlQuery = payload["dcql_query"]?.object else {
            throw OpenID4VCBackendError.invalidPresentationChallenge(reason: "signed request object was malformed")
        }
        // OpenID4VP defines transaction_data as a non-empty array of base64url
        // strings, each encoding a JSON object.
        let transactionData = try Self.decodedTransactionData(from: payload["transaction_data"])
        guard Self.isValidURLSafeValue(nonce), Self.hasValidOptionalURLSafeValue(payload["state"]) else {
            throw OpenID4VCBackendError.invalidPresentationChallenge(reason: "signed request nonce or state was invalid")
        }
        let vpFormatsSupported = try Self.vpFormatsSupported(from: payload["client_metadata"])
        let timestamp = Int(date.timeIntervalSince1970)
        if case let .number(issuedAt)? = payload["iat"], Int(issuedAt) > timestamp + 60 {
            throw OpenID4VCBackendError.invalidPresentationChallenge(reason: "signed request object was issued in the future")
        }
        if case let .number(expiresAt)? = payload["exp"], Int(expiresAt) <= timestamp {
            throw OpenID4VCBackendError.invalidPresentationChallenge(reason: "signed request object expired")
        }
        if Self.signingDID(from: clientID) == nil {
            // OpenID4VP Section 5.9.3: requests using the redirect_uri Client
            // Identifier Prefix cannot carry a wallet-verifiable signature
            // because there is no mechanism to obtain a trusted key. The JWT
            // envelope is still required (typ, claims syntax, lifetime), but
            // its signature is not verified; callers MUST anchor trust in the
            // response URI binding of the envelope instead.
            guard Self.redirectURIClient(from: clientID) != nil else {
                throw OpenID4VCBackendError.invalidPresentationChallenge(reason: "unsupported client_id prefix")
            }
            return VerifiedOpenID4VPRequestObject(
                clientID: clientID,
                issuer: payload["iss"]?.string,
                audience: payload["aud"]?.string,
                responseType: payload["response_type"]?.string,
                responseMode: responseMode,
                responseURI: payload["response_uri"]?.string,
                nonce: nonce,
                state: payload["state"]?.string,
                dcqlQuery: dcqlQuery,
                vpFormatsSupported: vpFormatsSupported,
                signingDID: nil,
                issuedAt: payload["iat"]?.numericValue.map { Date(timeIntervalSince1970: $0) },
                expiresAt: payload["exp"]?.numericValue.map { Date(timeIntervalSince1970: $0) },
                transactionData: transactionData
            )
        }
        guard let signingDID = Self.signingDID(from: clientID) else {
            throw OpenID4VCBackendError.invalidPresentationChallenge(reason: "unsupported client_id prefix")
        }
        guard let kid = header["kid"]?.string else {
            throw OpenID4VCBackendError.invalidPresentationChallenge(reason: "signed request object was malformed")
        }
        guard Self.isDIDURL(kid, under: signingDID) else {
            throw OpenID4VCBackendError.invalidPresentationChallenge(reason: "signed request kid was not bound to client_id")
        }
        let document: DIDDocument
        do {
            document = try await resolver.resolve(signingDID)
        } catch {
            throw OpenID4VCBackendError.invalidPresentationChallenge(reason: "signed request issuer DID could not be resolved")
        }
        guard document.id == signingDID else {
            throw OpenID4VCBackendError.invalidPresentationChallenge(reason: "resolved DID document id did not match client_id")
        }
        let methodIDs = document.verificationMethod.map(\.id)
        guard Set(methodIDs).count == methodIDs.count else {
            throw OpenID4VCBackendError.invalidPresentationChallenge(reason: "resolved DID document contained duplicate verification method ids")
        }
        guard let methodIndex = methodIDs.firstIndex(of: kid) else {
            throw OpenID4VCBackendError.invalidPresentationChallenge(reason: "signed request kid was not found in the DID document")
        }
        let selected = document.verificationMethod[methodIndex]
        let authentication = Set(document.authentication.map { Self.normalizedReference($0, documentID: document.id) })
        guard authentication.contains(kid),
              selected.controller == signingDID,
              selected.publicKeyJwk.kty == "EC",
              selected.publicKeyJwk.crv == "P-256",
              let y = selected.publicKeyJwk.y else {
            throw OpenID4VCBackendError.invalidPresentationChallenge(reason: "signed request used an unsupported authentication key")
        }
        let xData = try Self.requiredBase64URL(selected.publicKeyJwk.x)
        let yData = try Self.requiredBase64URL(y)
        guard xData.count == 32, yData.count == 32 else {
            throw OpenID4VCBackendError.invalidPresentationChallenge(reason: "signed request key was malformed")
        }
        let methods = [EbsiVerificationMethod(
            id: kid,
            controller: selected.controller,
            key: .p256(x: xData, y: yData),
            relationships: [.authentication]
        )]
        let verified: VerifiedEbsiJWS
        do {
            verified = try EbsiJWSVerifier().verify(
                compactJWS: compactJWT,
                methods: methods,
                requirements: EbsiJWSRequirements(
                    allowedAlgorithms: [.es256],
                    requiredRelationship: .authentication,
                    expectedController: signingDID,
                    expectedIssuer: nil,
                    validationDate: date
                )
            )
        } catch {
            throw OpenID4VCBackendError.invalidPresentationChallenge(reason: "signed request signature was invalid")
        }
        guard verified.methodID == kid else {
            throw OpenID4VCBackendError.invalidPresentationChallenge(reason: "signed request kid was not bound to its issuer")
        }
        return VerifiedOpenID4VPRequestObject(
            clientID: clientID,
            issuer: payload["iss"]?.string,
            audience: payload["aud"]?.string,
            responseType: payload["response_type"]?.string,
            responseMode: responseMode,
            responseURI: payload["response_uri"]?.string,
            nonce: nonce,
            state: payload["state"]?.string,
            dcqlQuery: dcqlQuery,
            vpFormatsSupported: vpFormatsSupported,
            signingDID: signingDID,
            issuedAt: payload["iat"]?.numericValue.map { Date(timeIntervalSince1970: $0) },
            expiresAt: payload["exp"]?.numericValue.map { Date(timeIntervalSince1970: $0) },
            transactionData: transactionData
        )
    }

    /// Decodes the OpenID4VP `transaction_data` parameter: a non-empty array
    /// of base64url strings, each encoding a plain JSON object.
    private static func decodedTransactionData(
        from value: AnySendableJSON?
    ) throws -> [OpenID4VPTransactionData] {
        guard let value else { return [] }
        guard case let .array(entries) = value else {
            throw OpenID4VCBackendError.invalidPresentationChallenge(reason: "transaction_data was malformed")
        }
        guard !entries.isEmpty, entries.count <= 16 else {
            throw OpenID4VCBackendError.invalidPresentationChallenge(reason: "transaction_data was malformed")
        }
        var totalEncodedBytes = 0
        return try entries.map { entry in
            guard let encoded = entry.string,
                  !encoded.isEmpty, encoded.utf8.count <= 131_072,
                  encoded.utf8.allSatisfy({
                      (0x30...0x39).contains($0) || (0x41...0x5A).contains($0) ||
                          (0x61...0x7A).contains($0) || $0 == 0x2D || $0 == 0x5F
                  }),
                  let data = Self.decodeBase64URL(encoded),
                  let object = try? JSONDecoder().decode([String: AnySendableJSON].self, from: data) else {
                throw OpenID4VCBackendError.invalidPresentationChallenge(reason: "transaction_data was malformed")
            }
            totalEncodedBytes += encoded.utf8.count
            guard totalEncodedBytes <= 262_144,
                  isSafeTransactionValue(.object(object), depth: 0, remainingNodes: 2_000) else {
                throw OpenID4VCBackendError.invalidPresentationChallenge(reason: "transaction_data exceeded safe display limits")
            }
            return OpenID4VPTransactionData(encoded: encoded, decoded: object)
        }
    }

    private static func isSafeTransactionValue(
        _ value: AnySendableJSON,
        depth: Int,
        remainingNodes: Int
    ) -> Bool {
        guard depth <= 16, remainingNodes > 0 else { return false }
        switch value {
        case let .object(object):
            guard object.count <= 250 else { return false }
            var remaining = remainingNodes - 1
            for child in object.values {
                guard isSafeTransactionValue(child, depth: depth + 1, remainingNodes: remaining) else { return false }
                remaining -= 1
            }
            return remaining >= 0
        case let .array(values):
            guard values.count <= 250 else { return false }
            var remaining = remainingNodes - 1
            for child in values {
                guard isSafeTransactionValue(child, depth: depth + 1, remainingNodes: remaining) else { return false }
                remaining -= 1
            }
            return remaining >= 0
        case let .string(value): return value.utf8.count <= 65_536
        case .number, .bool, .null: return true
        }
    }

    /// Parses a `redirect_uri:` Client Identifier and returns the embedded
    /// HTTPS URL when the value is well-formed.
    static func redirectURIClient(from clientID: String) -> URL? {
        let prefix = "redirect_uri:"
        guard clientID.hasPrefix(prefix) else { return nil }
        let raw = String(clientID.dropFirst(prefix.count))
        guard let url = URL(string: raw),
              url.scheme?.lowercased() == "https",
              url.host != nil,
              url.user == nil, url.password == nil, url.fragment == nil else { return nil }
        return url
    }

    private static func signingDID(from clientID: String) -> String? {
        let prefix = "decentralized_identifier:"
        guard clientID.hasPrefix(prefix) else { return nil }
        let did = String(clientID.dropFirst(prefix.count))
        guard did.hasPrefix("did:"), did.count > 4,
              !did.contains(where: { $0 == "#" || $0 == "/" || $0 == "?" || $0.isWhitespace }),
              did.unicodeScalars.allSatisfy({ $0.isASCII }) else { return nil }
        return did
    }

    private static func isDIDURL(_ kid: String, under did: String) -> Bool {
        let prefix = did + "#"
        guard kid.hasPrefix(prefix), kid.count > prefix.count else { return false }
        let fragment = kid.dropFirst(prefix.count)
        return !fragment.contains("#") && fragment.unicodeScalars.allSatisfy { $0.isASCII && !$0.properties.isWhitespace }
    }

    private static func normalizedReference(_ reference: String, documentID: String) -> String {
        reference.hasPrefix("#") ? documentID + reference : reference
    }

    private static func isValidURLSafeValue(_ value: String) -> Bool {
        guard (1...512).contains(value.utf8.count) else { return false }
        return value.unicodeScalars.allSatisfy { scalar in
            switch scalar.value {
            case 0x30...0x39, 0x41...0x5A, 0x61...0x7A, 0x2D, 0x2E, 0x5F, 0x7E: true
            default: false
            }
        }
    }

    private static func hasValidOptionalURLSafeValue(_ value: AnySendableJSON?) -> Bool {
        guard let value else { return true }
        guard let string = value.string else { return false }
        return isValidURLSafeValue(string)
    }

    private static func vpFormatsSupported(
        from clientMetadata: AnySendableJSON?
    ) throws -> [String: Set<String>]? {
        guard let clientMetadata else { return nil }
        guard let metadata = clientMetadata.object else { throw malformedMetadata() }
        guard let formatsValue = metadata["vp_formats_supported"] else { return nil }
        guard let formats = formatsValue.object else { throw malformedMetadata() }
        var result: [String: Set<String>] = [:]
        for (format, value) in formats {
            guard !format.isEmpty, let parameters = value.object else { throw malformedMetadata() }
            let preferredNames: [String]
            switch format {
            case "dc+sd-jwt":
                preferredNames = ["kb-jwt_alg_values", "kb_jwt_alg_values", "kb-jwt_alg_values_supported"]
            default:
                preferredNames = ["alg_values", "alg_values_supported"]
            }
            var algorithms = Set<String>()
            for name in preferredNames where parameters[name] != nil {
                guard case let .array(values)? = parameters[name],
                      values.allSatisfy({ $0.string != nil }) else { throw malformedMetadata() }
                algorithms.formUnion(values.compactMap(\.string))
            }
            result[format] = algorithms
        }
        return result
    }

    private static func malformedMetadata() -> OpenID4VCBackendError {
        .invalidPresentationChallenge(reason: "signed request client_metadata was malformed")
    }

    private static func requiredBase64URL(_ value: String) throws -> Data {
        guard let data = decodeBase64URL(value) else {
            throw OpenID4VCBackendError.invalidPresentationChallenge(reason: "signed request key was malformed")
        }
        return data
    }

    private static func decodeBase64URL(_ value: String) -> Data? {
        var encoded = value.replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        encoded += String(repeating: "=", count: (4 - encoded.count % 4) % 4)
        return Data(base64Encoded: encoded)
    }
}
