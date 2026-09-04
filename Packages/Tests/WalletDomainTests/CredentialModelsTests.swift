import Foundation
import Testing
@testable import WalletDomain

struct CredentialModelsTests {
    @Test("Credential state dimensions remain independent")
    func independentCredentialState() throws {
        let createdAt = Date(timeIntervalSince1970: 1_700_000_000)
        let record = CredentialRecord(
            configurationID: "exampleLegalPersonID",
            displayName: "Legal person identity",
            format: .jwtVC,
            profileID: "example-development-v1",
            issuerIdentifier: "did:ebsi:issuer",
            cryptographicValidity: .valid,
            issuerTrust: .untrusted,
            status: .indeterminate,
            legalClassification: .provisional,
            createdAt: createdAt
        )

        let decoded = try JSONDecoder().decode(
            CredentialRecord.self,
            from: JSONEncoder().encode(record)
        )

        #expect(decoded == record)
        #expect(decoded.cryptographicValidity == .valid)
        #expect(decoded.issuerTrust == .untrusted)
        #expect(decoded.status == .indeterminate)
        #expect(decoded.legalClassification == .provisional)
        #expect(decoded.legalClassification.rawValue == "provisional")
        #expect(LegalClassification.w3cCredential.rawValue == "w3cCredential")
    }

    @Test("Supported credential formats do not collapse into one representation")
    func formatsAreDistinct() {
        #expect(Set(CredentialFormat.allCases).count == 3)
        #expect(CredentialFormat.jwtVC != .sdJWTVC)
        #expect(CredentialFormat.sdJWTVC != .mdoc)
    }

    @Test("Offline display artwork round trips and legacy records remain readable")
    func displayArtworkCompatibility() throws {
        let image = CredentialDisplayImage(
            mediaType: "image/png",
            data: Data([0x89, 0x50, 0x4e, 0x47]),
            alternativeText: "Issuer mark"
        )
        let record = CredentialRecord(
            configurationID: "pid",
            displayName: "PID",
            format: .sdJWTVC,
            profileID: "test",
            issuerIdentifier: "https://issuer.example",
            createdAt: Date(timeIntervalSince1970: 1_700_000_000),
            display: CredentialDisplayMetadata(
                locale: "en",
                description: "Identity credential",
                backgroundColor: "#003366",
                textColor: "#ffffff",
                logo: image,
                backgroundImage: image
            )
        )
        #expect(try JSONDecoder().decode(
            CredentialRecord.self,
            from: JSONEncoder().encode(record)
        ) == record)

        var legacy = try #require(JSONSerialization.jsonObject(
            with: JSONEncoder().encode(record)
        ) as? [String: Any])
        legacy["display"] = nil
        let decodedLegacy = try JSONDecoder().decode(
            CredentialRecord.self,
            from: JSONSerialization.data(withJSONObject: legacy)
        )
        #expect(decodedLegacy.display == nil)
    }

    @Test("Legacy credentials default to manual refresh and scheduling metadata round trips")
    func refreshMetadataCompatibility() throws {
        let record = CredentialRecord(
            configurationID: "pid", displayName: "PID", format: .jwtVC,
            profileID: "w3c", issuerIdentifier: "https://issuer.example",
            createdAt: Date(timeIntervalSince1970: 1_700_000_000),
            refresh: CredentialRefreshMetadata(
                mode: .automatic, state: .scheduled,
                nextRefreshAt: Date(timeIntervalSince1970: 1_800_000_000),
                lastAttemptAt: Date(timeIntervalSince1970: 1_700_000_100),
                lastSuccessfulRefreshAt: Date(timeIntervalSince1970: 1_700_000_050),
                consecutiveFailures: 2
            )
        )
        #expect(try JSONDecoder().decode(
            CredentialRecord.self, from: JSONEncoder().encode(record)
        ) == record)

        var legacy = try #require(JSONSerialization.jsonObject(
            with: JSONEncoder().encode(record)
        ) as? [String: Any])
        legacy.removeValue(forKey: "refresh")
        let decoded = try JSONDecoder().decode(
            CredentialRecord.self, from: JSONSerialization.data(withJSONObject: legacy)
        )
        #expect(decoded.refresh == .manual)
        #expect(decoded.refresh.mode == .manual)
    }

    @Test("Normalized validity round trips and legacy date keys migrate")
    func validityCompatibility() throws {
        let validFrom = Date(timeIntervalSince1970: 1_700_000_000)
        let validUntil = Date(timeIntervalSince1970: 1_800_000_000)
        let record = CredentialRecord(
            configurationID: "pid", displayName: "PID", format: .sdJWTVC,
            profileID: "eudi", issuerIdentifier: "https://issuer.example",
            createdAt: validFrom, validFrom: validFrom, validUntil: validUntil
        )
        let encoded = try JSONEncoder().encode(record)
        let object = try #require(JSONSerialization.jsonObject(with: encoded) as? [String: Any])
        #expect(object["validFrom"] != nil)
        #expect(object["validUntil"] != nil)
        #expect(object["issuedAt"] == nil)
        #expect(object["expiresAt"] == nil)
        #expect(try JSONDecoder().decode(CredentialRecord.self, from: encoded) == record)

        var legacy = object
        legacy["issuedAt"] = legacy.removeValue(forKey: "validFrom")
        legacy["expiresAt"] = legacy.removeValue(forKey: "validUntil")
        let migrated = try JSONDecoder().decode(
            CredentialRecord.self,
            from: JSONSerialization.data(withJSONObject: legacy)
        )
        #expect(migrated.validFrom == validFrom)
        #expect(migrated.validUntil == validUntil)
        #expect(migrated.issuedAt == validFrom)
        #expect(migrated.expiresAt == validUntil)
    }
}
