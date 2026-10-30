import XCTest

/// The demo on a Simulator: a login, a short trip to the background, another
/// login in the same session. CI runs it against ci/fake-shield.mjs.
final class LoginFlowTests: XCTestCase {
    func testLoginSurvivesAShortTripToTheBackground() throws {
        let app = XCUIApplication()
        app.launchEnvironment = [
            "SHIELD_SITE_KEY": "pub_citest0000000000",
            "SHIELD_ENDPOINT": "http://localhost:8788/v1/shield/track",
            "SHIELD_DEMO_BACKEND": "http://localhost:8787",
        ]
        app.launch()

        let first = try logIn(app, typing: true)

        XCUIDevice.shared.press(.home)
        sleep(3)
        app.activate()
        XCTAssertTrue(app.buttons["Log out"].waitForExistence(timeout: 10))
        app.buttons["Log out"].tap()

        let second = try logIn(app, typing: false)
        XCTAssertEqual(first, second, "a short trip to the background changed the session")
    }

    private func logIn(_ app: XCUIApplication, typing: Bool) throws -> String {
        if typing {
            let email = app.textFields["Email"]
            XCTAssertTrue(email.waitForExistence(timeout: 10))
            email.tap()
            email.typeText("ci-user@example.com")
            let password = app.secureTextFields.firstMatch
            password.tap()
            password.typeText("ci-password-value")
        }
        let logIn = app.buttons["Log in"]
        XCTAssertTrue(logIn.waitForExistence(timeout: 10))
        logIn.tap()
        XCTAssertTrue(app.buttons["Log out"].waitForExistence(timeout: 15), "the login did not complete")

        let session = app.staticTexts.matching(NSPredicate(format: "label BEGINSWITH 'Session: '")).firstMatch
        XCTAssertTrue(session.waitForExistence(timeout: 5))
        return session.label
    }
}
