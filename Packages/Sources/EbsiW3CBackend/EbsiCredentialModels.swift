import Foundation

public enum W3CDataModelVersion: String, Codable, Equatable, Sendable {
    case v1_1 = "1.1"
    case v2_0 = "2.0"
}

public enum EbsiCredentialRepresentation: String, Codable, Equatable, Sendable {
    case jwtVcJson = "jwt_vc_json"
    case jwtVcJsonLd = "jwt_vc_json-ld"
    case dataIntegrity = "ldp_vc"
    case vcdm2SdJwt = "vcdm2_sd_jwt"
    case dcSdJwt = "dc+sd-jwt"
    case vcdm2Jwt = "application/vc+jwt"
}

public enum EbsiKeyAlgorithm: String, Codable, Equatable, Sendable {
    case es256 = "ES256"
    case es256K = "ES256K"
    case rs256 = "RS256"
}

public struct EbsiCredentialProfile: Codable, Equatable, Identifiable, Sendable {
    public let id: String
    public let dataModel: W3CDataModelVersion
    public let representation: EbsiCredentialRepresentation
    public let allowedAlgorithms: Set<EbsiKeyAlgorithm>
    public let allowedCryptosuites: Set<String>
    public let context: String
    public let schemaType: String?
    public let statusType: String?
    public let termsOfUseType: String?

    public init(
        id: String,
        dataModel: W3CDataModelVersion,
        representation: EbsiCredentialRepresentation,
        allowedAlgorithms: Set<EbsiKeyAlgorithm>,
        allowedCryptosuites: Set<String> = [],
        context: String,
        schemaType: String? = nil,
        statusType: String? = nil,
        termsOfUseType: String? = nil
    ) throws {
        guard !id.isEmpty, !allowedAlgorithms.isEmpty || !allowedCryptosuites.isEmpty else {
            throw EbsiCredentialError.invalidProfile
        }
        self.id = id
        self.dataModel = dataModel
        self.representation = representation
        self.allowedAlgorithms = allowedAlgorithms
        self.allowedCryptosuites = allowedCryptosuites
        self.context = context
        self.schemaType = schemaType
        self.statusType = statusType
        self.termsOfUseType = termsOfUseType
    }

    public static func vcdm2JWTVC() throws -> EbsiCredentialProfile {
        try EbsiCredentialProfile(
            id: "ebsi-vcdm2-jwt-vc",
            dataModel: .v2_0,
            representation: .vcdm2Jwt,
            allowedAlgorithms: [.es256],
            context: "https://www.w3.org/ns/credentials/v2",
            // Development authority schema/status metadata is diagnostic. The
            // cryptographic/profile checks remain mandatory, but absent or varying
            // registry metadata must not reject a valid development credential.
            schemaType: nil,
            statusType: nil,
            // The live issuer.dev.oari.io authority omits termsOfUse while still
            // producing a valid VCDM2/JWT credential. Trust/accreditation is a
            // separate development diagnostic and must not reject this credential.
            termsOfUseType: nil
        )
    }

    /// Generic OpenID4VCI jwt_vc_json carrying a VCDM 2.0 credential.
    /// This is deliberately distinct from the application/vc+jwt EBSI profile.
    public static func vcdm2JWTVCJSON() throws -> EbsiCredentialProfile {
        try EbsiCredentialProfile(
            id: "vcdm2-jwt-vc-json",
            dataModel: .v2_0,
            representation: .jwtVcJson,
            allowedAlgorithms: [.es256],
            context: "https://www.w3.org/ns/credentials/v2"
        )
    }

    public static func vcdm11Jwt() throws -> EbsiCredentialProfile {
        try EbsiCredentialProfile(
            id: "ebsi-vcdm11-jwt-vc",
            dataModel: .v1_1,
            representation: .jwtVcJson,
            allowedAlgorithms: [.es256, .es256K, .rs256],
            context: "https://www.w3.org/2018/credentials/v1"
        )
    }

    public static func vcdm2SdJWT() throws -> EbsiCredentialProfile {
        try EbsiCredentialProfile(
            id: "ebsi-vcdm2-sd-jwt",
            dataModel: .v2_0,
            representation: .vcdm2SdJwt,
            allowedAlgorithms: [.es256, .es256K],
            context: "https://www.w3.org/ns/credentials/v2"
        )
    }

    public static func dcSdJWTVC() throws -> EbsiCredentialProfile {
        try EbsiCredentialProfile(
            id: "ietf-dc-sd-jwt-vc",
            dataModel: .v2_0,
            representation: .dcSdJwt,
            allowedAlgorithms: [.es256],
            context: "urn:ietf:params:oauth:token-type:sd-jwt"
        )
    }

    var requiresSDJWTHolderBinding: Bool { representation == .vcdm2SdJwt }
}

public enum EbsiCredentialError: Error, Equatable, Sendable {
    case invalidProfile
    case malformedCredential
    case profileMismatch
    case algorithmNotAllowed
    case unsupportedRepresentation
    case verificationFailed
    case issuerMismatch
    case issuerDIDUnresolved
    case issuerSigningKeysUnresolved
    case invalidSignature
    case invalidHolderBinding
    case backendUnavailable
}

public struct StoredEbsiCredential: Codable, Equatable, Identifiable, Sendable {
    public let id: UUID
    public let profileID: String
    public let representation: EbsiCredentialRepresentation
    public let rawCredential: Data
    public let holderKeyReference: String
    public let receivedAt: Date

    public init(
        id: UUID = UUID(),
        profileID: String,
        representation: EbsiCredentialRepresentation,
        rawCredential: Data,
        holderKeyReference: String,
        receivedAt: Date = Date()
    ) {
        self.id = id
        self.profileID = profileID
        self.representation = representation
        self.rawCredential = rawCredential
        self.holderKeyReference = holderKeyReference
        self.receivedAt = receivedAt
    }
}

public protocol EbsiCredentialStore: Sendable {
    func credentials() async throws -> [StoredEbsiCredential]
    func save(_ credential: StoredEbsiCredential) async throws
    func delete(id: UUID) async throws
    /// Implementations used for refresh must commit this as one durable replacement.
    func replace(id: UUID, with credential: StoredEbsiCredential) async throws
}

public extension EbsiCredentialStore {
    func replace(id: UUID, with credential: StoredEbsiCredential) async throws {
        guard id == credential.id else { throw EbsiCredentialError.malformedCredential }
        try await delete(id: id)
        try await save(credential)
    }
}

public struct EbsiCredentialInspector: Sendable {
    public init() {}

    public func inspectCompactJWT(
        _ compactJWT: String,
        profile: EbsiCredentialProfile,
        validationDate: Date? = nil
    ) throws -> [String: AnySendableJSON] {
        let parts = compactJWT.split(separator: ".")
        guard parts.count == 3,
              let header = try Self.decodeJSON(String(parts[0])),
              let payload = try Self.decodeJSON(String(parts[1])) else {
            throw EbsiCredentialError.malformedCredential
        }
        guard let algorithm = header["alg"]?.string.flatMap(EbsiKeyAlgorithm.init(rawValue:)),
              profile.allowedAlgorithms.contains(algorithm) else {
            throw EbsiCredentialError.algorithmNotAllowed
        }
        guard profile.representation == .jwtVcJson ||
                profile.representation == .jwtVcJsonLd ||
                profile.representation == .vcdm2Jwt else {
            throw EbsiCredentialError.unsupportedRepresentation
        }
        if profile.representation == .vcdm2Jwt {
            guard header["typ"]?.string == "vc+jwt", payload["vc"] == nil else {
                throw EbsiCredentialError.profileMismatch
            }
            try Self.validateVCDM2Credential(payload, context: profile.context, at: validationDate)
        }
        var credential = payload["vc"]?.object ?? payload
        if profile.dataModel == .v1_1 {
            if let type = header["typ"]?.string, type != "JWT" {
                throw EbsiCredentialError.profileMismatch
            }
            credential = try Self.reconstructVCDM11Credential(credential, payload: payload)
            try Self.validateVCDM11Credential(
                credential, payload: payload, context: profile.context, at: validationDate
            )
        }
        guard credential["@context"]?.contains(string: profile.context) == true,
              credential["type"]?.contains(string: "VerifiableCredential") == true else {
            throw EbsiCredentialError.profileMismatch
        }
        if let schemaType = profile.schemaType,
           credential["credentialSchema"]?.object?["type"]?.string != schemaType {
            throw EbsiCredentialError.profileMismatch
        }
        if let statusType = profile.statusType,
           credential["credentialStatus"]?.object?["type"]?.string != statusType {
            throw EbsiCredentialError.profileMismatch
        }
        if let termsOfUseType = profile.termsOfUseType,
           credential["termsOfUse"]?.object?["type"]?.string != termsOfUseType {
            throw EbsiCredentialError.profileMismatch
        }
        return credential
    }

    private static func validateVCDM11Credential(
        _ credential: [String: AnySendableJSON],
        payload: [String: AnySendableJSON],
        context expectedContext: String,
        at validationDate: Date?
    ) throws {
        guard case let .array(contexts)? = credential["@context"],
              contexts.first?.string == expectedContext,
              contexts.allSatisfy({ $0.string != nil || $0.object != nil }),
              hasVCDM2Type(credential["type"]),
              let issuer = issuerIdentifier(credential["issuer"]),
              isURI(issuer),
              let subjects = credentialSubjects(credential["credentialSubject"]) else {
            throw EbsiCredentialError.profileMismatch
        }

        // VCDM 1.1 uses issuanceDate/expirationDate, unlike VCDM 2.0.
        guard let issuanceDate = try dateTimeProperty("issuanceDate", in: credential) else {
            throw EbsiCredentialError.profileMismatch
        }
        let expirationDate = try dateTimeProperty("expirationDate", in: credential)
        if let expirationDate, issuanceDate >= expirationDate {
            throw EbsiCredentialError.profileMismatch
        }
        if let validationDate {
            if validationDate < issuanceDate { throw EbsiCredentialError.profileMismatch }
            if let expirationDate, validationDate >= expirationDate {
                throw EbsiCredentialError.profileMismatch
            }
        }

        if let tokenIssuer = payload["iss"] {
            guard tokenIssuer.string == issuer else { throw EbsiCredentialError.profileMismatch }
        }
        if let subject = payload["sub"] {
            guard let subject = subject.string,
                  subjects.compactMap({ $0["id"]?.string }).contains(subject) else {
                throw EbsiCredentialError.profileMismatch
            }
        }
        if let tokenID = payload["jti"] {
            guard let tokenID = tokenID.string, credential["id"]?.string == tokenID else {
                throw EbsiCredentialError.profileMismatch
            }
        }
        try validateNumericDateClaim("nbf", value: payload["nbf"], matches: issuanceDate)
        try validateNumericDateClaim("exp", value: payload["exp"], matches: expirationDate)
    }

    private static func reconstructVCDM11Credential(
        _ source: [String: AnySendableJSON],
        payload: [String: AnySendableJSON]
    ) throws -> [String: AnySendableJSON] {
        var credential = source
        if credential["issuer"] == nil, let issuer = payload["iss"]?.string {
            credential["issuer"] = .string(issuer)
        }
        if credential["credentialSubject"] == nil, let subject = payload["sub"]?.string {
            credential["credentialSubject"] = .object(["id": .string(subject)])
        }
        if credential["id"] == nil, let identifier = payload["jti"]?.string {
            credential["id"] = .string(identifier)
        }
        if credential["issuanceDate"] == nil, let notBefore = payload["nbf"]?.numericValue {
            guard notBefore.isFinite else { throw EbsiCredentialError.profileMismatch }
            credential["issuanceDate"] = .string(formatDateTime(Date(timeIntervalSince1970: notBefore)))
        }
        if credential["expirationDate"] == nil, let expiration = payload["exp"]?.numericValue {
            guard expiration.isFinite else { throw EbsiCredentialError.profileMismatch }
            credential["expirationDate"] = .string(formatDateTime(Date(timeIntervalSince1970: expiration)))
        }
        return credential
    }

    private static func validateVCDM2Credential(
        _ credential: [String: AnySendableJSON],
        context expectedContext: String,
        at validationDate: Date?
    ) throws {
        guard case let .array(contexts)? = credential["@context"],
              contexts.first?.string == expectedContext,
              contexts.allSatisfy({ $0.string != nil || $0.object != nil }),
              Self.hasVCDM2Type(credential["type"]),
              let issuer = Self.issuerIdentifier(credential["issuer"]),
              Self.isURI(issuer),
              let subjects = Self.credentialSubjects(credential["credentialSubject"]) else {
            throw EbsiCredentialError.profileMismatch
        }

        let validFrom = try Self.dateTimeProperty("validFrom", in: credential)
        let validUntil = try Self.dateTimeProperty("validUntil", in: credential)
        if let validFrom, let validUntil, validFrom > validUntil {
            throw EbsiCredentialError.profileMismatch
        }
        if let validationDate {
            if let validFrom, validationDate < validFrom { throw EbsiCredentialError.profileMismatch }
            if let validUntil, validationDate >= validUntil { throw EbsiCredentialError.profileMismatch }
        }

        // VC-JOSE registered claims are optional, but when used they must be
        // equivalent to their VCDM properties rather than introducing a second
        // issuer, subject, identifier, or validity period.
        if credential["iss"] != nil, credential["iss"]?.string != issuer {
            throw EbsiCredentialError.profileMismatch
        }
        if let subject = credential["sub"] {
            guard let subject = subject.string,
                   subjects.compactMap({ $0["id"]?.string }).contains(subject) else {
                throw EbsiCredentialError.profileMismatch
            }
        }
        if let tokenID = credential["jti"] {
            guard let tokenID = tokenID.string, credential["id"]?.string == tokenID else {
                throw EbsiCredentialError.profileMismatch
            }
        }
        try Self.validateNumericDateClaim("nbf", value: credential["nbf"], matches: validFrom)
        try Self.validateNumericDateClaim("exp", value: credential["exp"], matches: validUntil)
    }

    private static func hasVCDM2Type(_ value: AnySendableJSON?) -> Bool {
        switch value {
        case let .string(type): type == "VerifiableCredential"
        case let .array(types):
            !types.isEmpty && types.allSatisfy { $0.string != nil } &&
                types.contains { $0.string == "VerifiableCredential" }
        default: false
        }
    }

    private static func issuerIdentifier(_ value: AnySendableJSON?) -> String? {
        switch value {
        case let .string(issuer): issuer.isEmpty ? nil : issuer
        case let .object(issuer): issuer["id"]?.string.flatMap { $0.isEmpty ? nil : $0 }
        default: nil
        }
    }

    private static func credentialSubjects(
        _ value: AnySendableJSON?
    ) -> [[String: AnySendableJSON]]? {
        switch value {
        case let .object(subject): return [subject]
        case let .array(subjects):
            let objects = subjects.compactMap(\.object)
            return !objects.isEmpty && objects.count == subjects.count ? objects : nil
        default: return nil
        }
    }

    private static func isURI(_ value: String) -> Bool {
        guard !value.contains(where: { $0.isWhitespace }),
              let components = URLComponents(string: value) else { return false }
        return components.scheme?.isEmpty == false
    }

    private static func dateTimeProperty(
        _ name: String,
        in credential: [String: AnySendableJSON]
    ) throws -> Date? {
        guard let value = credential[name] else { return nil }
        guard let string = value.string, let date = parseDateTime(string) else {
            throw EbsiCredentialError.profileMismatch
        }
        return date
    }

    private static func parseDateTime(_ value: String) -> Date? {
        let fractional = ISO8601DateFormatter()
        fractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let result = fractional.date(from: value) { return result }
        let standard = ISO8601DateFormatter()
        standard.formatOptions = [.withInternetDateTime]
        return standard.date(from: value)
    }

    private static func formatDateTime(_ value: Date) -> String {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter.string(from: value)
    }

    private static func validateNumericDateClaim(
        _ name: String,
        value: AnySendableJSON?,
        matches date: Date?
    ) throws {
        guard let value else { return }
        guard let number = value.numericValue, number.isFinite, let date,
              abs(number - date.timeIntervalSince1970) < 0.001 else {
            throw EbsiCredentialError.profileMismatch
        }
    }

    public func inspectSDJWT(
        _ value: String,
        requiresHolderBinding: Bool = true
    ) throws -> [String: AnySendableJSON] {
        guard let issuer = value.split(separator: "~").first else {
            throw EbsiCredentialError.malformedCredential
        }
        let parts = issuer.split(separator: ".")
        guard parts.count == 3,
              let payload = try Self.decodeJSON(String(parts[1])) else {
            throw EbsiCredentialError.malformedCredential
        }
        guard payload["iss"]?.string != nil,
              payload["vct"]?.string != nil else {
            throw EbsiCredentialError.profileMismatch
        }
        if requiresHolderBinding, payload["cnf"]?.object == nil {
            throw EbsiCredentialError.profileMismatch
        }
        return payload
    }

    private static func decodeJSON(_ value: String) throws -> [String: AnySendableJSON]? {
        var base64 = value.replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        base64 += String(repeating: "=", count: (4 - base64.count % 4) % 4)
        guard let data = Data(base64Encoded: base64) else { return nil }
        return try JSONDecoder().decode([String: AnySendableJSON].self, from: data)
    }

    private static func algorithm(in compactJWT: String) throws -> EbsiKeyAlgorithm? {
        let parts = compactJWT.split(separator: ".")
        guard let encoded = parts.first,
              let header = try decodeJSON(String(encoded)) else { return nil }
        return header["alg"]?.string.flatMap(EbsiKeyAlgorithm.init(rawValue:))
    }
}

public enum AnySendableJSON: Codable, Equatable, Sendable {
    case string(String)
    case number(Double)
    case bool(Bool)
    case object([String: AnySendableJSON])
    case array([AnySendableJSON])
    case null

    public init(from decoder: any Decoder) throws {
        let value = try decoder.singleValueContainer()
        if value.decodeNil() { self = .null }
        else if let object = try? value.decode([String: AnySendableJSON].self) { self = .object(object) }
        else if let array = try? value.decode([AnySendableJSON].self) { self = .array(array) }
        else if let string = try? value.decode(String.self) { self = .string(string) }
        else if let bool = try? value.decode(Bool.self) { self = .bool(bool) }
        else if let number = try? value.decode(Double.self) { self = .number(number) }
        else { throw EbsiCredentialError.malformedCredential }
    }

    public func encode(to encoder: any Encoder) throws {
        var value = encoder.singleValueContainer()
        switch self {
        case let .string(v): try value.encode(v)
        case let .number(v): try value.encode(v)
        case let .bool(v): try value.encode(v)
        case let .object(v): try value.encode(v)
        case let .array(v): try value.encode(v)
        case .null: try value.encodeNil()
        }
    }

    public var string: String? { if case let .string(value) = self { value } else { nil } }
    var numericValue: Double? { if case let .number(value) = self { value } else { nil } }
    public var object: [String: AnySendableJSON]? { if case let .object(value) = self { value } else { nil } }
    var displayString: String? {
        switch self {
        case let .string(value): value
        case let .number(value): String(value)
        case let .bool(value): value ? "Yes" : "No"
        case let .array(values): values.compactMap(\.displayString).joined(separator: ", ")
        default: nil
        }
    }
    func contains(string: String) -> Bool {
        switch self {
        case let .string(value): value == string
        case let .array(values): values.contains { $0.string == string }
        default: false
        }
    }
}
