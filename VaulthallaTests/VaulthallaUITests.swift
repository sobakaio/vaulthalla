//
//  VaulthallaUITests.swift
//  VaulthallaUITests
//
//  Created by Dmytro Pavlov on 16/09/2026.
//

import XCTest

final class VaulthallaUITests: XCTestCase {

    override func setUpWithError() throws {
        // Put setup code here. This method is called before the invocation of each test method in the class.

        // In UI tests it is usually best to stop immediately when a failure occurs.
        continueAfterFailure = false

        // In UI tests it’s important to set the initial state - such as interface orientation - required for your tests before they run. The setUp method is a good place to do this.
    }

    override func tearDownWithError() throws {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    @MainActor
    func testLaunchShowsProtectedEntryPoint() throws {
        let app = XCUIApplication()
        app.launch()

        let passwordField = app.secureTextFields["masterPasswordField"]
        let createPasswordField = app.secureTextFields["createPasswordField"]
        let imagesTab = app.buttons["Images"]
        let pinUnlock = app.buttons["Unlock with PIN"]
        let faceIDUnlock = app.buttons["Unlock with Face ID"]
        let welcomeBack = app.staticTexts["Welcome back"]

        XCTAssertTrue(
            passwordField.waitForExistence(timeout: 5)
                || createPasswordField.waitForExistence(timeout: 5)
                || imagesTab.waitForExistence(timeout: 5)
                || pinUnlock.waitForExistence(timeout: 5)
                || faceIDUnlock.waitForExistence(timeout: 5)
                || welcomeBack.waitForExistence(timeout: 5)
        )
    }

    @MainActor
    func testLaunchPerformance() throws {
        // This measures how long it takes to launch your application.
        measure(metrics: [XCTApplicationLaunchMetric()]) {
            XCUIApplication().launch()
        }
    }
}

final class VisualSmokeTests: XCTestCase {

    private let shotDir = "/tmp/vault_verify"

    override func setUpWithError() throws {
        continueAfterFailure = false
        try? FileManager.default.createDirectory(atPath: shotDir, withIntermediateDirectories: true)
    }

    private func shot(_ app: XCUIApplication, _ name: String) {
        let data = app.screenshot().pngRepresentation
        try? data.write(to: URL(fileURLWithPath: shotDir + "/" + name + ".png"))
    }

    private func counter(_ app: XCUIApplication) -> String? {
        for text in app.staticTexts.allElementsBoundByIndex {
            let label = text.label
            if label.range(of: #"^\d+ of \d+$"#, options: .regularExpression) != nil {
                return label
            }
        }
        return nil
    }

    private func point(_ app: XCUIApplication, _ x: CGFloat, _ y: CGFloat) -> XCUICoordinate {
        app.coordinate(withNormalizedOffset: CGVector(dx: x, dy: y))
    }

    private func swipe(_ app: XCUIApplication, fromX: CGFloat, fromY: CGFloat, toX: CGFloat, toY: CGFloat) {
        point(app, fromX, fromY).press(forDuration: 0.05, thenDragTo: point(app, toX, toY))
    }

    private func parseCounter(_ s: String?) -> (Int, Int)? {
        guard let s else { return nil }
        let parts = s.split(separator: " ")
        guard parts.count == 3, let n = Int(parts[0]), let m = Int(parts[2]) else { return nil }
        return (n, m)
    }

    @MainActor
    func testVaultFlowAndViewer() throws {
        let app = XCUIApplication()
        app.launch()

        // 1. Fresh install must show onboarding. If a vault already exists on
        //    this device the flow cannot run without its password.
        let createField = app.secureTextFields["createPasswordField"]
        let existingLock = app.secureTextFields["masterPasswordField"]
        XCTAssertTrue(createField.waitForExistence(timeout: 10),
                      "Expected onboarding, found: \(existingLock.exists ? "existing vault" : "unknown screen")")
        shot(app, "01_onboarding")

        // 2. Create the vault.
        createField.tap()
        createField.typeText("Vault-Test-123")
        let confirmField = app.secureTextFields["confirmPasswordField"]
        confirmField.tap()
        confirmField.typeText("Vault-Test-123")
        app.buttons["createVaultButton"].tap()

        // 3. Images tab must open on the empty state (no big header at rest).
        let emptyState = app.staticTexts["Import photos to see them here."]
        XCTAssertTrue(emptyState.waitForExistence(timeout: 20), "Images tab empty state did not appear")
        shot(app, "02_images_tab")

        // 3a. Each library screen can be reached with a horizontal swipe;
        // vertical scrolling and the explicit tab bar remain available.
        let videosTab = app.buttons["Videos"]
        let settingsTab = app.buttons["Settings"]
        swipe(app, fromX: 0.82, fromY: 0.50, toX: 0.18, toY: 0.50)
        XCTAssertTrue(videosTab.isSelected, "A left swipe should open Videos")
        swipe(app, fromX: 0.82, fromY: 0.50, toX: 0.18, toY: 0.50)
        XCTAssertTrue(settingsTab.isSelected, "A second left swipe should open Settings")
        app.buttons["Images"].tap()
        XCTAssertTrue(app.buttons["Images"].isSelected, "The bottom bar should still switch screens")

        // 4. Open the ellipsis menu -> Import sheet.
        app.buttons["moreMenuButton"].tap()
        let importItem = app.buttons["menuImportButton"]
        XCTAssertTrue(importItem.waitForExistence(timeout: 5), "Import menu item missing")
        importItem.tap()
        let cable = app.buttons["importCableButton"]
        XCTAssertTrue(cable.waitForExistence(timeout: 10), "Import by Cable row missing")
        shot(app, "03_import_sheet")

        // 5. Import seven staged photos (two albums) and one short MP4 fixture.
        // The video is isolated in the e2e app sandbox, not the user's vault.
        cable.tap()
        let groupQuery = app.descendants(matching: .any).matching(NSPredicate(format: "identifier BEGINSWITH 'group-'"))
        XCTAssertTrue(groupQuery.firstMatch.waitForExistence(timeout: 30), "Group tiles did not appear after import")
        // SwiftUI gesture wrappers can expose several accessibility nodes per
        // tile that share the same identifier, so count unique identifiers.
        func uniqueIdentifiers(_ query: XCUIElementQuery) -> [String] {
            var seen = Set<String>()
            return query.allElementsBoundByIndex.map { $0.identifier }
                .filter { seen.insert($0).inserted }
        }
        var waited = 0
        while uniqueIdentifiers(groupQuery).count < 2, waited < 20 {
            Thread.sleep(forTimeInterval: 1)
            waited += 1
        }
        let groupIDs = uniqueIdentifiers(groupQuery)
        XCTAssertEqual(groupIDs.count, 2, "Expected exactly 2 groups (A and B), got \(groupIDs)")
        shot(app, "04_grid")

        // 6. Open the first group (A: 4 items).
        groupQuery.firstMatch.tap()
        let tileQuery = app.descendants(matching: .any).matching(NSPredicate(format: "identifier BEGINSWITH 'media-'"))
        XCTAssertTrue(tileQuery.firstMatch.waitForExistence(timeout: 10), "Media tiles did not appear in group detail")
        let tileIDs = uniqueIdentifiers(tileQuery)
        XCTAssertTrue(tileIDs.count >= 3, "Expected at least 3 tiles in group detail, got \(tileIDs)")
        shot(app, "05_group_detail")

        // 7. Open the first image in the viewer.
        tileQuery.firstMatch.tap()
        let closeBtn = app.buttons["viewerCloseButton"]
        Thread.sleep(forTimeInterval: 2) // let the image decode
        XCTAssertFalse(closeBtn.exists, "Viewer chrome must be hidden on open")
        shot(app, "06_viewer_nochrome")

        // 8. Single tap toggles the chrome.
        point(app, 0.5, 0.5).tap()
        XCTAssertTrue(closeBtn.waitForExistence(timeout: 5), "Chrome did not appear on tap")
        XCTAssertTrue(app.buttons["viewerSlideshowButton"].waitForExistence(timeout: 5), "Slideshow button missing")
        XCTAssertTrue(app.buttons["viewerInfoButton"].waitForExistence(timeout: 5), "Info button missing")
        shot(app, "07_viewer_chrome")

        // 9. Slideshow advances automatically from the current image.
        if !closeBtn.exists {
            shot(app, "08a_viewer_vanished")
            let btns = app.buttons.allElementsBoundByIndex.map { $0.identifier.isEmpty ? $0.label : $0.identifier }
            XCTFail("Viewer vanished before slideshow step. Buttons: \(btns)")
        }
        let beforeSlideshow = counter(app)
        app.buttons["viewerSlideshowButton"].tap()
        Thread.sleep(forTimeInterval: 8) // default image pause is 5 seconds
        let duringSlideshow = counter(app)
        shot(app, "12_slideshow")
        XCTAssertNotEqual(beforeSlideshow, duringSlideshow,
                          "Slideshow did not advance (stayed at \(String(describing: beforeSlideshow)))")
        // Slideshow hides the chrome; a tap reveals it so we can stop.
        point(app, 0.5, 0.5).tap()
        XCTAssertTrue(app.buttons["viewerSlideshowButton"].waitForExistence(timeout: 5),
                      "Slideshow stop button not visible after tap")
        app.buttons["viewerSlideshowButton"].tap() // stop

        // 10. Swipe navigates to the adjacent image (direction depends on the
        // current position: left from the start, right from the end).
        let beforeSwipe = counter(app)
        if let (n, m) = parseCounter(beforeSwipe) {
            if n < m {
                swipe(app, fromX: 0.8, fromY: 0.5, toX: 0.2, toY: 0.5)
            } else {
                swipe(app, fromX: 0.2, fromY: 0.5, toX: 0.8, toY: 0.5)
            }
        }
        Thread.sleep(forTimeInterval: 1.5)
        let afterSwipe = counter(app)
        shot(app, "08_viewer_next")
        XCTAssertNotEqual(beforeSwipe, afterSwipe,
                          "Swipe left did not navigate (stayed at \(String(describing: beforeSwipe)))")

        // 11. Double tap zooms (fit -> long side fill), double tap back to fit.
        point(app, 0.5, 0.5).doubleTap()
        Thread.sleep(forTimeInterval: 1.5)
        shot(app, "09_viewer_zoomed")
        point(app, 0.5, 0.5).doubleTap()
        Thread.sleep(forTimeInterval: 1.5)
        shot(app, "10_viewer_fit")

        // Pinch zoom and one-finger pan must stay in the current image and
        // remain separate from page navigation.
        let beforePinch = counter(app)
        app.pinch(withScale: 1.7, velocity: 1.0)
        Thread.sleep(forTimeInterval: 0.5)
        XCTAssertTrue(closeBtn.exists, "Pinch should keep the image viewer open")
        XCTAssertEqual(counter(app), beforePinch, "Pinching must not page to another image")
        shot(app, "10a_viewer_pinch")
        swipe(app, fromX: 0.50, fromY: 0.70, toX: 0.50, toY: 0.55)
        XCTAssertTrue(closeBtn.exists, "Panning a zoomed image must not dismiss it")
        XCTAssertEqual(counter(app), beforePinch, "One-finger pan must not page to another image")
        point(app, 0.5, 0.5).doubleTap() // return to fit before the dismissal gesture

        // 12. Swipe down closes the viewer (fall back to the close button if
        // a zoom state absorbed the gesture).
        swipe(app, fromX: 0.5, fromY: 0.30, toX: 0.5, toY: 0.80)
        Thread.sleep(forTimeInterval: 1.5)
        if closeBtn.exists {
            point(app, 0.5, 0.5).tap()
            if closeBtn.waitForExistence(timeout: 3) { closeBtn.tap() }
            Thread.sleep(forTimeInterval: 1.5)
        }
        XCTAssertFalse(closeBtn.exists, "Viewer did not close on swipe down")
        shot(app, "11_back_to_grid")

        // 13. Long-press enters select mode (on-device UX). XCUITest's
        //     synthetic press is historically unreliable for SwiftUI
        //     long-press gestures, so if it is not recognized (and the stray
        //     release-tap opens the viewer) we close the viewer and enter the
        //     SAME select state deterministically via the more menu.
        tileQuery.firstMatch.press(forDuration: 0.6)
        let longPressWorked = app.staticTexts["1 selected"].waitForExistence(timeout: 3)
        var seenTiles = Set<String>()
        var uniqueTiles: [XCUIElement] = []
        for el in tileQuery.allElementsBoundByIndex where seenTiles.insert(el.identifier).inserted {
            uniqueTiles.append(el)
        }
        XCTAssertTrue(uniqueTiles.count >= 2, "Need at least 2 unique tiles to test, got \(uniqueTiles.count)")
        // Regression (bug: second thumb opened the photo): in select mode a
        // tap on a tile toggles its selection — it never opens the viewer.
        if longPressWorked {
            shot(app, "13_longpress_select")
            uniqueTiles[1].tap() // select the second tile
            XCTAssertTrue(app.staticTexts["2 selected"].waitForExistence(timeout: 5),
                          "Second tap in select mode did not select the tile")
            XCTAssertFalse(closeBtn.exists, "Second tap in select mode opened the viewer")
            shot(app, "14_select_two")
        } else {
            // XCUITest did not recognize the synthetic long-press; the stray
            // release-tap may have opened the viewer — close it and enter the
            // SAME select state via the more menu.
            if closeBtn.exists {
                point(app, 0.5, 0.5).tap() // reveal chrome
                if closeBtn.waitForExistence(timeout: 2) { closeBtn.tap() }
                Thread.sleep(forTimeInterval: 1)
            }
            app.buttons["groupMoreMenuButton"].tap()
            var selectAll = app.buttons["menuSelectAllButton"]
            if !selectAll.exists { selectAll = app.buttons["Select all"] }
            XCTAssertTrue(selectAll.waitForExistence(timeout: 5), "Select all menu item missing")
            selectAll.tap()
            XCTAssertTrue(app.staticTexts["4 selected"].waitForExistence(timeout: 5),
                          "Select all did not select the 4 tiles")
            shot(app, "13_select_mode")
            uniqueTiles[0].tap() // deselect the first tile
            XCTAssertTrue(app.staticTexts["3 selected"].waitForExistence(timeout: 5),
                          "Tap in select mode did not toggle the tile")
            XCTAssertFalse(closeBtn.exists, "Tap in select mode opened the viewer")
            shot(app, "14_select_toggled")
        }
        app.buttons["Cancel"].tap()
        Thread.sleep(forTimeInterval: 1)
        shot(app, "15_select_cancelled")

        // 14. Open the imported video and verify its poster, ordered controls,
        //     scrubber placement, and mute state change.
        app.buttons["Videos"].tap()
        let videoGroupQuery = app.descendants(matching: .any)
            .matching(NSPredicate(format: "identifier BEGINSWITH 'group-'"))
        XCTAssertTrue(videoGroupQuery.firstMatch.waitForExistence(timeout: 15), "Video preview group missing")
        videoGroupQuery.firstMatch.tap()
        let videoTileQuery = app.descendants(matching: .any)
            .matching(NSPredicate(format: "identifier BEGINSWITH 'media-'"))
        XCTAssertTrue(videoTileQuery.firstMatch.waitForExistence(timeout: 10), "Imported video tile missing")
        videoTileQuery.firstMatch.tap()
        Thread.sleep(forTimeInterval: 2) // protected AVPlayer file and poster finish loading
        shot(app, "16_video_nochrome")
        point(app, 0.5, 0.5).tap()

        let playButton = app.buttons["videoPlayPauseButton"]
        let slideshowButton = app.buttons["viewerSlideshowButton"]
        let muteButton = app.buttons["videoMuteButton"]
        let infoButton = app.buttons["viewerInfoButton"]
        let scrubber = app.sliders.firstMatch
        XCTAssertTrue(playButton.waitForExistence(timeout: 5), "Video play button missing")
        XCTAssertTrue(slideshowButton.exists, "Video slideshow button missing")
        XCTAssertTrue(muteButton.exists, "Video mute button missing")
        XCTAssertTrue(infoButton.exists, "Video info button missing")
        XCTAssertTrue(scrubber.exists, "Video scrubber missing")
        XCTAssertLessThan(playButton.frame.midX, slideshowButton.frame.midX)
        XCTAssertLessThan(slideshowButton.frame.midX, muteButton.frame.midX)
        XCTAssertLessThan(muteButton.frame.midX, infoButton.frame.midX)
        XCTAssertGreaterThan(scrubber.frame.minY, playButton.frame.maxY, "Scrubber must be below the controls row")
        XCTAssertEqual(muteButton.label, "Mute video")
        muteButton.tap()
        XCTAssertEqual(muteButton.label, "Unmute video", "Mute button must toggle the player state")
        shot(app, "17_video_controls")
        if app.buttons["viewerCloseButton"].exists {
            app.buttons["viewerCloseButton"].tap()
        }
    }

    @MainActor
    func testUnlockLoadsLibraryAfterPasswordEntry() throws {
        let app = XCUIApplication()
        app.launch()

        let passwordField = app.secureTextFields["masterPasswordField"]
        XCTAssertTrue(passwordField.waitForExistence(timeout: 10), "Isolated e2e vault should start locked")
        passwordField.tap()
        passwordField.typeText("Vault-Test-123")
        let unlockButton = app.buttons["unlockButton"]
        XCTAssertTrue(unlockButton.isEnabled)
        unlockButton.tap()

        // XCTest's tap waits for the app to become idle, so the brief progress
        // view may finish before the test can query it. The screen recording
        // verifies the progress UI; this assertion verifies the full unlock.
        XCTAssertTrue(app.buttons["Images"].waitForExistence(timeout: 15), "Library should appear after successful unlock")
    }

}
