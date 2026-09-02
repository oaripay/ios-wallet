import AuthenticationServices
import UIKit

/// Owns the browser session independently of SwiftUI view lifecycles.
@MainActor
final class WebAuthenticationCoordinator: NSObject, ASWebAuthenticationPresentationContextProviding {
    private var session: ASWebAuthenticationSession?
    private var pendingURL: URL?
    private var retryTask: Task<Void, Never>?
    private var retryCount = 0
    private var onCompletion: ((URL) -> Void)?
    private var onFailure: ((String) -> Void)?

    func start(
        url: URL,
        onCompletion: @escaping (URL) -> Void,
        onFailure: @escaping (String) -> Void
    ) {
        guard session == nil else { return }
        pendingURL = url
        retryCount = 0
        self.onCompletion = onCompletion
        self.onFailure = onFailure
        attemptStart()
    }

    private func attemptStart() {
        guard session == nil, let url = pendingURL else { return }
        guard let window = Self.activeKeyWindow,
              window.windowScene?.activationState == .foregroundActive,
              UIApplication.shared.applicationState == .active else {
            scheduleRetry()
            return
        }

        print("Starting web authorization: \(url.absoluteString)")

        let session = ASWebAuthenticationSession(
            url: url,
            callbackURLScheme: "https"
        ) { [weak self] callbackURL, error in
            guard let self else { return }
            print("Web authentication callback URL: \(callbackURL?.absoluteString ?? "nil")")
            print("Web authentication callback error: \(error?.localizedDescription ?? "nil")")
            self.session = nil
            self.pendingURL = nil
            self.retryTask?.cancel()
            self.retryTask = nil
            let completion = self.onCompletion
            let failure = self.onFailure
            self.onCompletion = nil
            self.onFailure = nil

            if error == nil, let callbackURL {
                completion?(callbackURL)
            } else if let authError = error as? ASWebAuthenticationSessionError,
                      authError.code == .canceledLogin {
                failure?("Issuer authentication was cancelled.")
            } else {
                failure?(error?.localizedDescription ?? "Issuer authentication could not be opened.")
            }
        }
        session.presentationContextProvider = self
        session.prefersEphemeralWebBrowserSession = false
        self.session = session

        guard session.start() else {
            self.session = nil
            scheduleRetry()
            return
        }
    }

    private func scheduleRetry() {
        guard retryTask == nil else { return }
        retryCount += 1
        guard retryCount <= 20 else {
            let failure = onFailure
            pendingURL = nil
            onCompletion = nil
            onFailure = nil
            failure?("Unable to start issuer authentication browser while the app was active.")
            return
        }
        retryTask = Task { [weak self] in
            try? await Task.sleep(for: .milliseconds(250))
            guard !Task.isCancelled else { return }
            self?.retryTask = nil
            self?.attemptStart()
        }
    }

    func cancel() {
        session?.cancel()
        retryTask?.cancel()
        session = nil
        pendingURL = nil
        retryTask = nil
        retryCount = 0
        onCompletion = nil
        onFailure = nil
    }

    func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        Self.activeKeyWindow ?? ASPresentationAnchor()
    }

    private static var activeKeyWindow: UIWindow? {
        UIApplication.shared.connectedScenes
            .compactMap { $0 as? UIWindowScene }
            .filter { $0.activationState == .foregroundActive }
            .flatMap(\.windows)
            .first(where: \.isKeyWindow)
    }
}
