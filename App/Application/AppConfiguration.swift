import Foundation

struct AppConfiguration: Sendable {
    enum Fixture: String, Sendable {
        case production
        case empty
        case populated
        case storageFailure = "storage-failure"
    }

    let allowedHosts: Set<String>
    let fixture: Fixture
    let incomingURL: URL?
    let disablesAnimations: Bool
    let isUITesting: Bool

    static func current(
        arguments: [String] = ProcessInfo.processInfo.arguments
    ) -> AppConfiguration {
#if DEBUG
        let fixture = value(after: "--fixture", in: arguments)
            .flatMap(Fixture.init(rawValue:)) ?? .production
        let incomingURL = value(after: "--incoming-url", in: arguments).flatMap(URL.init(string:))
        let fixtureHosts: Set<String> = fixture == .production
            ? []
            : ["verifier.example", "issuer.example"]
        let allowedHosts = Set(["wallet.dev.oari.io"]).union(fixtureHosts)
#else
        let fixture = Fixture.production
        let incomingURL: URL? = nil
        let allowedHosts: Set<String> = []
#endif
        return AppConfiguration(
            allowedHosts: allowedHosts,
            fixture: fixture,
            incomingURL: incomingURL,
            disablesAnimations: arguments.contains("--disable-animations"),
            isUITesting: arguments.contains("--ui-tests")
        )
    }

    private static func value(after key: String, in arguments: [String]) -> String? {
        guard let index = arguments.firstIndex(of: key) else { return nil }
        let valueIndex = arguments.index(after: index)
        return valueIndex < arguments.endIndex ? arguments[valueIndex] : nil
    }
}
