import XCTest

@MainActor
final class WalletUITests: XCTestCase {
    override func setUpWithError() throws {
        continueAfterFailure = false
    }

    func testEmptyWalletAndTabNavigation() {
        let app = launch(fixture: "empty")

        XCTAssertTrue(app.staticTexts["No credentials"].waitForExistence(timeout: 5))
        app.tabBars.buttons["History"].tap()
        XCTAssertTrue(element(app, "history.empty").waitForExistence(timeout: 2))
        app.tabBars.buttons["Settings"].tap()
        XCTAssertTrue(element(app, "settings.certification").waitForExistence(timeout: 2))
    }

    func testPopulatedWalletAndHistory() {
        let app = launch(fixture: "populated")

        XCTAssertTrue(app.staticTexts["Example Legal Person ID"].waitForExistence(timeout: 5))
        XCTAssertTrue(element(app, "wallet.credential.exampleLegalPersonID").exists)
        app.tabBars.buttons["History"].tap()
        XCTAssertTrue(app.staticTexts["Issuance"].waitForExistence(timeout: 2))
        XCTAssertTrue(app.staticTexts["Completed"].exists)
    }

    func testCredentialDetailExplainsUnavailableOperations() {
        let app = launch(fixture: "populated")
        let credential = element(app, "wallet.credential.exampleLegalPersonID")
        XCTAssertTrue(credential.waitForExistence(timeout: 5))
        credential.tap()
        XCTAssertTrue(app.navigationBars["Credential details"].waitForExistence(timeout: 2))
        XCTAssertTrue(element(app, "credential.operationsUnavailable").exists)
        XCTAssertFalse(app.buttons["Remove credential"].isEnabled)
    }

    func testMissingProfileIsVisibleInScannerAndSettings() {
        let app = launch(fixture: "empty")
        app.tabBars.buttons["Scan"].tap()
        XCTAssertTrue(element(app, "scanner.configurationRequired").waitForExistence(timeout: 2))
        app.tabBars.buttons["Settings"].tap()
        XCTAssertTrue(app.staticTexts["Profile installation required"].waitForExistence(timeout: 2))
    }

    func testFloatingCameraButtonIsAvailableFromWallet() {
        let app = launch(fixture: "populated")
        let camera = element(app, "root.scan-camera")
        XCTAssertTrue(camera.waitForExistence(timeout: 5))
        XCTAssertEqual(camera.label, "Scan QR code")
        camera.tap()
        XCTAssertTrue(element(app, "scanner.camera-close").waitForExistence(timeout: 5))
    }

    func testScannerRejectsUnknownHostAndReviewsApprovedRequest() {
        let app = launch(fixture: "empty")
        app.tabBars.buttons["Scan"].tap()
        let input = app.textFields["scanner.input"]
        XCTAssertTrue(input.waitForExistence(timeout: 2))

        input.tap()
        input.typeText("https://evil.example/present?request=x")
        app.buttons["scanner.redeem"].tap()
        XCTAssertTrue(element(app, "scanner.result.rejected").waitForExistence(timeout: 2))

        app.terminate()
        let approvedApp = launch(
            fixture: "empty",
            additionalArguments: [
                "--incoming-url",
                "https://verifier.example/present?request=x",
            ]
        )
        XCTAssertTrue(element(approvedApp, "scanner.result.presentation").waitForExistence(timeout: 2))
    }

    func testStorageFailureIsExplicit() {
        let app = launch(fixture: "storage-failure")
        XCTAssertTrue(element(app, "wallet.storage-error").waitForExistence(timeout: 5))
    }

    func testCameraFallbackIsExplicitOnSimulator() {
        let app = launch(fixture: "empty")
        app.tabBars.buttons["Scan"].tap()
        element(app, "scanner.camera").tap()
        XCTAssertTrue(
            element(app, "scanner.camera-unavailable")
                .waitForExistence(timeout: 5)
        )
    }

    func testIncomingPresentationURLRoutesToReviewEntry() {
        let app = launch(fixture: "empty")
        app.open(URL(string: "openid4vp://authorize?request=fixture")!)
        XCTAssertTrue(element(app, "scanner.result.presentation").waitForExistence(timeout: 5))
    }

    func testIncomingCredentialOfferURLRoutesToReviewEntry() {
        let app = launch(fixture: "empty")
        app.open(URL(string: "openid-credential-offer://authorize?credential_offer=fixture")!)
        XCTAssertTrue(element(app, "scanner.result.issuance").waitForExistence(timeout: 5))
    }

    func testIncomingHAIPLinksRouteToTheirReviewEntries() {
        let app = launch(fixture: "empty")
        app.open(URL(string: "haip-vci://authorize?credential_offer=fixture")!)
        XCTAssertTrue(element(app, "scanner.result.issuance").waitForExistence(timeout: 5))

        app.open(URL(string: "haip-vp://authorize?request=fixture")!)
        XCTAssertTrue(element(app, "scanner.result.presentation").waitForExistence(timeout: 5))

        app.open(URL(string: "eudi-openid4vp://authorize?request=fixture")!)
        XCTAssertTrue(element(app, "scanner.result.presentation").waitForExistence(timeout: 5))

        app.open(URL(string: "mdoc-openid4vp://authorize?request=fixture")!)
        XCTAssertTrue(element(app, "scanner.result.presentation").waitForExistence(timeout: 5))
    }

    private func launch(
        fixture: String,
        additionalArguments: [String] = []
    ) -> XCUIApplication {
        let app = XCUIApplication()
        app.launchArguments = ["--fixture", fixture, "--disable-animations", "--ui-tests"] + additionalArguments
        app.launch()
        return app
    }

    private func element(_ app: XCUIApplication, _ identifier: String) -> XCUIElement {
        app.descendants(matching: .any)[identifier]
    }
}
