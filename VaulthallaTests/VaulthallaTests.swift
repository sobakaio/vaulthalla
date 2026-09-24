import Testing
import Foundation
import CryptoKit
@testable import Vaulthalla

struct VaulthallaTests {
    @Test @MainActor func webImportServerStartsInDefaultBuild() async {
        let server = LocalWebImportServer()
        server.start(rootKey: SymmetricKey(size: .bits256))
        defer { server.stop() }
        for _ in 0..<100 {
            if case .running = server.state { break }
            if case .failed = server.state { break }
            try? await Task.sleep(for: .milliseconds(50))
        }
        guard case .running = server.state else {
            Issue.record("Web Import listener should start in the default build")
            return
        }
        #expect(server.importURL?.scheme == "http")
        #expect(server.pairingPIN.count == 8)
    }

    @Test @MainActor func webImportResumesWhenSheetStillVisibleAfterSceneInactive() async {
        let model = VaultAppModel()
        model.rootKey = SymmetricKey(size: .bits256)
        model.webImportSheetVisible = true
        model.startWebImport()
        await webImportSettled(model, expect: .running)
        // Simulates the scenePhase == .inactive handler (e.g. a system
        // permission prompt covering the sheet on a fresh install).
        model.webImportServer.stop()
        #expect(model.webImportServer.state == .stopped)
        // Simulates scenePhase == .active with the sheet still on screen.
        model.webImportResumeIfSheetVisible()
        await webImportSettled(model, expect: .running)
        model.webImportServer.stop()
    }

    @Test @MainActor func webImportDoesNotResumeWhenSheetClosed() async {
        let model = VaultAppModel()
        model.rootKey = SymmetricKey(size: .bits256)
        model.webImportSheetVisible = true
        model.startWebImport()
        await webImportSettled(model, expect: .running)
        model.webImportSheetVisible = false
        model.webImportServer.stop()
        model.webImportResumeIfSheetVisible()
        #expect(model.webImportServer.state == .stopped)
    }

    @Test @MainActor func webImportRapidStopStartStaysConsistent() async {
        let model = VaultAppModel()
        model.rootKey = SymmetricKey(size: .bits256)
        // Rapid start/stop/start (SwiftUI onAppear/onDisappear double-fire)
        // must not corrupt the state machine with stale listener callbacks.
        for _ in 0..<3 {
            model.startWebImport()
            await model.stopWebImport()
            model.startWebImport()
            await webImportSettled(model, expect: .running)
        }
        #expect(model.webImportServer.state == .running)
        model.webImportServer.stop()
    }

    @MainActor
    private func webImportSettled(_ model: VaultAppModel, expect state: LocalWebImportServer.State) async {
        for _ in 0..<200 {
            if model.webImportServer.state == state { return }
            if case .failed = model.webImportServer.state { return }
            try? await Task.sleep(for: .milliseconds(50))
        }
    }

    /// Regression: after the scene handler locks on backgrounding (which
    /// revokes block-store access), a convenience unlock must re-arm access
    /// through finishUnlock and load the index — previously PIN failed with
    /// "Vault Integrity Error" and Face ID looped because only store.unlock()
    /// (password path) called activateAccess.
    ///
    /// Runs WITHOUT the global Keychain device secret: the vault is a
    /// header-less block store with a seeded (empty) index, so
    /// requireDeviceBinding returns true without touching Keychain. The unlock
    /// therefore reaches the "audit privacy cleanup" step (no header to verify)
    /// instead of .unlocked. The regression signal is the ABSENCE of the
    /// "Vault Integrity Error" that the access-revocation bug produced.
    @Test(.serialized) @MainActor func convenienceUnlockWorksAfterBackgroundLockRevokesAccess() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        let rootKey = SymmetricKey(size: .bits256)
        let store = VaultStore(fileManager: RedirectedFileManager(replacement: directory))
        // Seed a valid (empty) encrypted index into the store's block store so
        // loadIndex has something authenticated to read. No header, no device
        // secret, no creation journal — the Keychain is never touched.
        let seeder = EncryptedBlockStore(rootDirectory: directory.appendingPathComponent("Vaulthalla", isDirectory: true))
        try await seeder.initialize(using: rootKey, auditPrivateKey: Curve25519.KeyAgreement.PrivateKey().rawRepresentation)

        let model = VaultAppModel()
        model.store = store
        model.rootKey = rootKey
        model.phase = .locked
        model.isApplicationActive = { true }
        model.attemptStore = AttemptStateStore(account: "convenience-lock-test-\(UUID().uuidString)")
        model.faceIDEnabled = true
        model.faceIDUnlocker = ScriptedFaceIDUnlocker(results: [.success(rootKey)])

        // Simulate the background lock: the scene handler revokes store access.
        await store.revokeAccess()
        #expect(model.phase == .locked)

        // Biometric success after the background lock must re-arm access and
        // load the index — not fail with the access-revocation Integrity Error.
        await model.unlockWithFaceID()
        #expect(!model.errorMessage.contains("Integrity"))
    }

    /// Regression (TODO Bug #1): when biometrics match but the biometry-gated
    /// Keychain wrapper can no longer be read (Face ID re-enrolled), the Face ID
    /// unlocker throws FaceIDWrapperUnavailableFailure. The app must stop
    /// looping the user through prompts that can never succeed: disable Face ID
    /// and show the specific "enrollment changed" message — not a generic
    /// "unavailable" that invites endless retries.
    @Test(.serialized) @MainActor func faceIDWrapperUnavailableDisablesFaceIDWithClearMessage() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        let store = VaultStore(fileManager: RedirectedFileManager(replacement: directory))
        let model = VaultAppModel()
        model.store = store
        model.phase = .locked
        model.isApplicationActive = { true }
        model.attemptStore = AttemptStateStore(account: "faceid-wrapper-test-\(UUID().uuidString)")
        model.faceIDEnabled = true
        // Biometrics succeeded, but the Keychain read behind them failed.
        model.faceIDUnlocker = ScriptedFaceIDUnlocker(results: [.failure(FaceIDWrapperUnavailableFailure())])

        await model.unlockWithFaceID()

        #expect(model.faceIDEnabled == false)
        #expect(model.errorMessage.contains("biometric enrollment changed"))
    }

    @Test func passwordKeyIsDeterministicForSameInputs() throws {
        let salt = Data(repeating: 7, count: 32)
        let first = try PasswordKDF.deriveKey(password: "correct horse battery", salt: salt, iterations: 100_000)
        let second = try PasswordKDF.deriveKey(password: "correct horse battery", salt: salt, iterations: 100_000)
        #expect(first.withUnsafeBytes { Data($0) } == second.withUnsafeBytes { Data($0) })
    }

    @Test func wrongPasswordCannotUnwrapRootKey() throws {
        let salt = VaultCrypto.randomData(count: 32)
        let device = VaultCrypto.randomData(count: 32)
        let root = SymmetricKey(size: .bits256)
        let passwordKey = try PasswordKDF.deriveKey(password: "correct password", salt: salt, iterations: 100_000)
        let kek = VaultCrypto.makeKEK(passwordKey: passwordKey, deviceSecret: device)
        let aad = VaultCrypto.headerAAD(segmentCapacity: SegmentCapacity.megabytes100.bytes, salt: salt, iterations: 100_000)
        let wrapped = try VaultCrypto.wrap(root, with: kek, aad: aad)
        let wrongKey = try PasswordKDF.deriveKey(password: "wrong password", salt: salt, iterations: 100_000)
        let wrongKEK = VaultCrypto.makeKEK(passwordKey: wrongKey, deviceSecret: device)
        #expect(throws: (any Error).self) {
            _ = try VaultCrypto.unwrap(wrapped, with: wrongKEK, aad: aad)
        }
    }

    @Test func deviceSecretChangesUnlockKey() throws {
        let password = try PasswordKDF.deriveKey(password: "correct password", salt: Data(repeating: 1, count: 32), iterations: 100_000)
        let first = VaultCrypto.makeKEK(passwordKey: password, deviceSecret: Data(repeating: 2, count: 32))
        let second = VaultCrypto.makeKEK(passwordKey: password, deviceSecret: Data(repeating: 3, count: 32))
        #expect(first.withUnsafeBytes { Data($0) } != second.withUnsafeBytes { Data($0) })
    }

    @Test func authenticatedCiphertextDetectsTampering() throws {
        let key = SymmetricKey(size: .bits256)
        let plaintext = Data("vault".utf8)
        let sealed = try AES.GCM.seal(plaintext, using: key)
        let bytes = Data([sealed.ciphertext.first! ^ 1]) + sealed.ciphertext.dropFirst()
        let tampered = try AES.GCM.SealedBox(nonce: sealed.nonce, ciphertext: bytes, tag: sealed.tag)
        var rejected = false
        do {
            _ = try AES.GCM.open(tampered, using: key)
        } catch {
            rejected = true
        }
        #expect(rejected)
    }

    @Test func headerRejectsUnknownFormat() throws {
        var header = VaultHeader(segmentCapacity: SegmentCapacity.megabytes100.bytes, salt: Data(repeating: 1, count: 32), iterations: 100_000, wrappedRootKey: Data(repeating: 1, count: 60), auditPublicKey: Data(repeating: 1, count: 32))
        header = VaultHeader(magic: Data("BAD".utf8), formatVersion: 99, segmentCapacity: 1, chunkPayloadSize: 1, kdfVersion: 1, salt: Data(), iterations: 0, wrappedRootKey: Data(), auditPublicKey: Data())
        #expect(throws: VaultError.invalidHeader) { try header.validate() }
    }

    @Test func pbkdf2CalibrationStaysWithinBounds() throws {
        let iterations = try PasswordKDF.calibratedIterations()
        #expect(iterations >= PasswordKDF.minimumIterations)
        #expect(iterations < UInt32.max)
    }

    @Test func deriveKeyRejectsInvalidSalt() {
        #expect(throws: VaultError.self) {
            _ = try PasswordKDF.deriveKey(password: "some password", salt: Data(repeating: 0, count: 16), iterations: 1_000)
        }
    }

    @Test func passwordChangeInvalidatesOldCredential() throws {
        let root = SymmetricKey(size: .bits256)
        let device = VaultCrypto.randomData(count: 32)
        let iterations: UInt32 = 100_000

        let salt1 = Data(repeating: 1, count: 32)
        let oldKey = try PasswordKDF.deriveKey(password: "old master password", salt: salt1, iterations: iterations)
        let aad1 = VaultCrypto.headerAAD(segmentCapacity: SegmentCapacity.megabytes100.bytes, salt: salt1, iterations: iterations)
        let oldKEK = VaultCrypto.makeKEK(passwordKey: oldKey, deviceSecret: device)
        let originalHeader = try VaultCrypto.wrap(root, with: oldKEK, aad: aad1)

        let salt2 = Data(repeating: 2, count: 32)
        let newKey = try PasswordKDF.deriveKey(password: "new master password", salt: salt2, iterations: iterations)
        let aad2 = VaultCrypto.headerAAD(segmentCapacity: SegmentCapacity.megabytes100.bytes, salt: salt2, iterations: iterations)
        let newKEK = VaultCrypto.makeKEK(passwordKey: newKey, deviceSecret: device)
        let rewrappedHeader = try VaultCrypto.wrap(root, with: newKEK, aad: aad2)

        #expect(try VaultCrypto.unwrap(originalHeader, with: oldKEK, aad: aad1) == root)
        #expect(try VaultCrypto.unwrap(rewrappedHeader, with: newKEK, aad: aad2) == root)
        #expect(throws: (any Error).self) {
            _ = try VaultCrypto.unwrap(rewrappedHeader, with: oldKEK, aad: aad2)
        }
    }

    @Test func chunkEncryptionIsUniquePerItem() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)

        let sharedPrefix = Data(repeating: 9, count: VaultConstants.chunkPayloadSize)
        let firstURL = directory.appendingPathComponent("one.jpg")
        let secondURL = directory.appendingPathComponent("two.jpg")
        try (sharedPrefix + Data(repeating: 1, count: 100)).write(to: firstURL)
        try (sharedPrefix + Data(repeating: 2, count: 100)).write(to: secondURL)

        let store = EncryptedBlockStore(rootDirectory: directory.appendingPathComponent("vault", isDirectory: true))
        let key = SymmetricKey(size: .bits256)
        let firstRecord = try await store.importFile(at: firstURL, filename: "one.jpg", mimeType: "image/jpeg", rootKey: key, segmentCapacity: SegmentCapacity.megabytes50.bytes)
        let secondRecord = try await store.importFile(at: secondURL, filename: "two.jpg", mimeType: "image/jpeg", rootKey: key, segmentCapacity: SegmentCapacity.megabytes50.bytes)
        #expect(firstRecord != nil && secondRecord != nil)

        // Identical 1 MiB plaintext prefixes must produce different sealed bytes
        // because chunk keys and nonces are derived per item.
        let firstChunk = try await store.readEncryptedChunk(at: firstRecord!.chunks[0])
        let secondChunk = try await store.readEncryptedChunk(at: secondRecord!.chunks[0])
        #expect(firstChunk != secondChunk)
        #expect(try await store.plaintext(for: secondRecord!) == sharedPrefix + Data(repeating: 2, count: 100))
    }
}
