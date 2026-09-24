import Testing
import Foundation
import CryptoKit
@testable import Vaulthalla
import Network

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


/// AUDIT #4 — end-to-end Web Import: real pairing over TCP, real uploads,
/// stop/drain, restart, and an in-flight upload torn down by stop/drain.
///
/// Isolation: the test uses its own redirected file system (a temp
/// directory) and its own Keychain account, so it can run in parallel with
/// every other test — including the other device-secret test that uses the
/// shared App Support directory and the default account.
#if targetEnvironment(simulator)
@MainActor
struct WebImportEndToEndTests {
    private func prepareIsolatedVault() throws -> (store: VaultStore, directory: URL, account: String) {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("vaulthalla-webimport-e2e-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let account = "e2e-web-import-\(UUID().uuidString)"
        let store = VaultStore(fileManager: RedirectedFileManager(replacement: directory), deviceSecretAccount: account)
        return (store, directory, account)
    }

    private func cleanupIsolatedVault(directory: URL, account: String) {
        try? KeychainStore.deleteDeviceSecret(account: account)
        try? FileManager.default.removeItem(at: directory)
    }

    private func waitForServerState(_ server: LocalWebImportServer, _ state: LocalWebImportServer.State) async -> Bool {
        for _ in 0..<200 {
            if server.state == state { return true }
            if case .failed = server.state { return false }
            try? await Task.sleep(for: .milliseconds(50))
        }
        return server.state == state
    }

    private func pairWithServer(_ server: LocalWebImportServer) async throws -> (base: URL, token: String)? {
        guard let base = server.loopbackURL, !server.pairingPIN.isEmpty else { return nil }
        var request = URLRequest(url: base.appendingPathComponent("pair"))
        request.httpMethod = "POST"
        request.httpBody = server.pairingPIN.data(using: .ascii)
        request.timeoutInterval = 10
        let (data, response) = try await URLSession.shared.data(for: request)
        guard (response as? HTTPURLResponse)?.statusCode == 200 else {
            Issue.record("Pairing failed with status \((response as? HTTPURLResponse)?.statusCode ?? -1)")
            return nil
        }
        guard let html = String(data: data, encoding: .utf8),
              let start = html.range(of: "/import/"),
              let end = html.range(of: "/upload", range: start.upperBound..<html.endIndex) else {
            Issue.record("Pairing response is missing the import endpoint")
            return nil
        }
        let token = String(html[start.upperBound..<end.lowerBound])
        guard !token.isEmpty else { return nil }
        return (base, token)
    }

    private func uploadToServer(_ payload: Data, filename: String, base: URL, token: String) async -> Int? {
        var request = URLRequest(
            url: base.appendingPathComponent("import")
                .appendingPathComponent(token)
                .appendingPathComponent("upload"))
        request.httpMethod = "POST"
        request.setValue(filename, forHTTPHeaderField: "x-filename")
        request.setValue("application/octet-stream", forHTTPHeaderField: "x-mime-type")
        request.httpBody = payload
        request.timeoutInterval = 30
        guard let (_, response) = try? await URLSession.shared.data(for: request) else { return nil }
        return (response as? HTTPURLResponse)?.statusCode
    }

    private func sendAll(_ client: NWConnection, _ data: Data) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            var resumed = false
            client.send(content: data, completion: .contentProcessed { error in
                guard !resumed else { return }
                resumed = true
                if let error { continuation.resume(throwing: error) }
                else { continuation.resume() }
            })
        }
    }

    @Test(.serialized)
    func webImportEndToEndPairUploadDrainRestart() async throws {
        let (store, directory, account) = try prepareIsolatedVault()
        defer { cleanupIsolatedVault(directory: directory, account: account) }
        try await store.createVault(password: "e2e-web-import-password", segmentCapacity: .megabytes50)
        let rootKey = try await store.unlock(password: "e2e-web-import-password")

        let server = LocalWebImportServer(store: store)
        server.start(rootKey: rootKey)
        defer { server.stop() }
        guard await waitForServerState(server, .running) else {
            Issue.record("Web Import server did not reach .running")
            return
        }
        guard let (base, token) = try await pairWithServer(server) else { return }

        // Session 1: pair, upload, verify plaintext round-trip.
        let payload1 = Data((0..<8192).map { _ in UInt8.random(in: 0...255) })
        #expect(await uploadToServer(payload1, filename: "alpha.bin", base: base, token: token) == 201)
        var snapshot = await store.indexSnapshot()
        let record1 = try #require(snapshot.records.values.first { $0.filename == "alpha.bin" })
        #expect(try await store.readMedia(record1, using: rootKey) == payload1)

        // Stop + drain, restart, pair again: new token, uploads keep working.
        await server.stopAndDrain()
        #expect(server.state == .stopped)
        server.start(rootKey: rootKey)
        guard await waitForServerState(server, .running),
              let (base2, token2) = try await pairWithServer(server) else {
            Issue.record("Web Import server did not restart after drain")
            return
        }
        #expect(token2 != token)
        let payload2 = Data(repeating: 0xA5, count: 7777)
        #expect(await uploadToServer(payload2, filename: "beta.bin", base: base2, token: token2) == 201)
        snapshot = await store.indexSnapshot()
        let record2 = try #require(snapshot.records.values.first { $0.filename == "beta.bin" })
        #expect(try await store.readMedia(record2, using: rootKey) == payload2)
        #expect(snapshot.records.values.first { $0.filename == "alpha.bin" } != nil)

        // A token from the previous session must be rejected after restart.
        #expect(await uploadToServer(payload2, filename: "stale.bin", base: base2, token: token) == 400)
        #expect(await store.indexSnapshot().records.values.first { $0.filename == "stale.bin" } == nil)

        // Same server, restarted: an upload in flight when stop/drain runs
        // must be discarded — no partial record, and the vault must stay
        // readable with its earlier contents.
        server.stop()
        server.start(rootKey: rootKey)
        guard await waitForServerState(server, .running),
              let (base3, token3) = try await pairWithServer(server) else {
            Issue.record("Web Import server did not restart for the drain scenario")
            return
        }
        let clientPort = base3.port ?? 80
        let client = NWConnection(
            host: NWEndpoint.Host(base3.host!),
            port: NWEndpoint.Port(rawValue: UInt16(clientPort))!,
            using: .tcp)
        client.start(queue: DispatchQueue(label: "vaulthalla.web-import.e2e.client"))
        let header = "POST /import/\(token3)/upload HTTP/1.1\r\nHost: \(base3.host!)\r\nx-filename: partial.bin\r\nx-mime-type: application/octet-stream\r\nContent-Length: 65536\r\nConnection: close\r\n\r\n"
        try await sendAll(client, Data(header.utf8))
        try await sendAll(client, Data(repeating: 0x11, count: 32768))
        var inFlight = false
        for _ in 0..<200 {
            if server.activeFilename == "partial.bin" { inFlight = true; break }
            try? await Task.sleep(for: .milliseconds(50))
        }
        guard inFlight else {
            Issue.record("Upload did not reach the in-flight state; drain assertion skipped")
            client.cancel()
            return
        }
        defer { client.cancel() }
        await server.stopAndDrain()
        #expect(server.state == .stopped)
        _ = try? await sendAll(client, Data(repeating: 0x22, count: 32768))

        // A partial upload must never be committed, and the vault must stay
        // readable with its pre-upload contents.
        let finalSnapshot = await store.indexSnapshot()
        #expect(finalSnapshot.records.values.first { $0.filename == "partial.bin" } == nil)
        #expect(try await store.readMedia(record2, using: rootKey) == payload2)
    }
}
#endif
