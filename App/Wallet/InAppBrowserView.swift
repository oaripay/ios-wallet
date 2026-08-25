import SwiftUI
import WebKit

/// Presents issuer authorization pages inside the wallet instead of leaving the app.
struct InAppBrowserView: UIViewRepresentable {
    let url: URL

    func makeUIView(context: Context) -> WKWebView {
        let webView = WKWebView(frame: .zero, configuration: WKWebViewConfiguration())
        webView.allowsBackForwardNavigationGestures = true
        webView.load(URLRequest(url: url))
        return webView
    }

    func updateUIView(_ webView: WKWebView, context: Context) {
        guard webView.url != url else { return }
        webView.load(URLRequest(url: url))
    }

    static func dismantleUIView(_ webView: WKWebView, coordinator: ()) {
        webView.stopLoading()
        webView.navigationDelegate = nil
        webView.uiDelegate = nil
    }
}
