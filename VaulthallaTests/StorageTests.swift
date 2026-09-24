import Testing
import Foundation
import UIKit
import AVFoundation
import CryptoKit
import Security
@testable import Vaulthalla

private struct CreationCut: Error {}

struct StorageTests {
    #if targetEnvironment(simulator)
    // Writes the global Keychain device secret, so it must run in the serial
    // domain alongside the other device-secret tests to avoid SecItem races.
    @Test(.serialized) func creationJournalRecoversAfterRestartWithoutReplacingIndex() async throws {
        let manager = FileManager.default
        let appSupport = manager.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
        let root = appSupport.appendingPathComponent("Vaulthalla")
        guard !manager.fileExists(atPath: root.appendingPathComponent("vault.header").path),
              !manager.fileExists(atPath: root.appendingPathComponent("index.v1").path) else {
            Issue.record("Simulator already has a vault; refusing to alter it")
            return
        }
        do {
            _ = try KeychainStore.loadDeviceSecret()
            Issue.record("Simulator already has a device secret; refusing to alter it")
            return
        } catch VaultError.keychainFailure(let status) where status == errSecItemNotFound {}
        defer {
            try? manager.removeItem(at: root)
            try? KeychainStore.deleteDeviceSecret()
        }
        let password = "long-creation-test-password"
        let initial = VaultStore(fileManager: manager)
        try await initial.createVault(password: password, segmentCapacity: .megabytes50, stopAfterStaging: true)
        #expect(!(await initial.hasVault()))
        let deviceBinding = try KeychainStore.loadDeviceSecret()
        let restarted = VaultStore(fileManager: manager)
        let model = await MainActor.run { VaultAppModel() }
        await MainActor.run { model.store = restarted }
        await model.load()
        #expect(try KeychainStore.loadDeviceSecret() == deviceBinding)
        await #expect(throws: VaultError.invalidPasswordOrDevice) {
            try await restarted.resumeCreation(password: "incorrect-password")
        }
        #expect(!(await restarted.hasVault()))
        // An unrelated pre-existing index must never be replaced by recovery.
        let rogue = EncryptedBlockStore(rootDirectory: root)
        try await rogue.initialize(using: SymmetricKey(size: .bits256), auditPrivateKey: Curve25519.KeyAgreement.PrivateKey().rawRepresentation)
        let indexURL = root.appendingPathComponent("index.v1")
        let rogueBytes = try Data(contentsOf: indexURL)
        await #expect(throws: (any Error).self) {
            try await restarted.resumeCreation(password: password)
        }
        #expect(try Data(contentsOf: indexURL) == rogueBytes)
        try manager.removeItem(at: indexURL)
        try await restarted.resumeCreation(password: password)
        #expect(await restarted.hasVault())
        let key = try await restarted.unlock(password: password)
        try await restarted.loadIndex(using: key)
        #expect(!manager.fileExists(atPath: root.appendingPathComponent("vault.creation").path))
        // A committed index without its header is inconsistent: destroy it.
        let headerURL = root.appendingPathComponent("vault.header")
        try manager.removeItem(at: headerURL)
        let orphanModel = await MainActor.run { VaultAppModel() }
        await MainActor.run { orphanModel.store = VaultStore(fileManager: manager) }
        await orphanModel.load()
        #expect(!manager.fileExists(atPath: root.path))
        await #expect(throws: VaultError.keychainFailure(errSecItemNotFound)) {
            try KeychainStore.loadDeviceSecret()
        }

        // A verified missing device key for an existing header also wipes it.
        let missingKeyStore = VaultStore(fileManager: manager)
        try await missingKeyStore.createVault(password: password, segmentCapacity: .megabytes50)
        try KeychainStore.deleteDeviceSecret()
        let missingKeyModel = await MainActor.run { VaultAppModel() }
        await MainActor.run { missingKeyModel.store = missingKeyStore }
        await missingKeyModel.load()
        #expect(!manager.fileExists(atPath: root.path))
        #expect(!UserDefaults.standard.bool(forKey: "vaultDestructionPending"))
        await #expect(throws: VaultError.keychainFailure(errSecItemNotFound)) {
            try KeychainStore.loadDeviceSecret()
        }

        // Wrong password alone must not wipe a sound vault. An authenticated
        // index-tag mismatch after a correct password must wipe it.
        let fresh = VaultStore(fileManager: manager)
        try await fresh.createVault(password: password, segmentCapacity: .megabytes50)
        let integrityModel = await MainActor.run { VaultAppModel() }
        await MainActor.run { integrityModel.store = fresh }
        // The unlock path (finishUnlock) is gated by canFinishUnlock, which
        // requires the app to be active. The test host is not foreground-active,
        // so override it to exercise the real unlock -> tamper -> destroy flow.
        await MainActor.run { integrityModel.isApplicationActive = { true } }
        await integrityModel.load()
        await MainActor.run { integrityModel.pendingPassword = "wrong-password" }
        await integrityModel.unlock()
        #expect(manager.fileExists(atPath: headerURL.path))
        var tampered = try Data(contentsOf: indexURL)
        tampered[tampered.index(before: tampered.endIndex)] ^= 1
        try tampered.write(to: indexURL)
        await MainActor.run { integrityModel.pendingPassword = password }
        await integrityModel.unlock()
        #expect(!manager.fileExists(atPath: root.path))
        #expect(!UserDefaults.standard.bool(forKey: "vaultDestructionPending"))
    }
    #endif

    @Test func encryptedImportRoundTripsExactBytes() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let source = directory.appendingPathComponent("20260916_152657_755005_random_001_production_shot_2_image.jpg")
        let bytes = Data((0..<1_500_000).map { UInt8($0 % 251) })
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        try bytes.write(to: source)

        let store = EncryptedBlockStore(rootDirectory: directory.appendingPathComponent("vault", isDirectory: true))
        let rootKey = SymmetricKey(size: .bits256)
        let record = try await store.importFile(
            at: source,
            filename: source.lastPathComponent,
            mimeType: "image/jpeg",
            rootKey: rootKey,
            segmentCapacity: SegmentCapacity.megabytes50.bytes
        )
        #expect(record?.byteCount == Int64(bytes.count))
        #expect(record?.chunks.count == 2)
        guard let importedRecord = record else {
            Issue.record("Encrypted import did not return a media record.")
            return
        }
        let recovered = try await store.plaintext(for: importedRecord)
        #expect(recovered == bytes)

        let recoveredURL = directory.appendingPathComponent("recovered.jpg")
        try await store.writePlaintext(for: importedRecord, to: recoveredURL)
        #expect(try Data(contentsOf: recoveredURL) == bytes)
        // The writer applies NSFileProtectionComplete before writing. iOS
        // Simulator does not report the protection key in attributesOfItem.
    }

    @Test func streamImportNormalizesProviderChunkSizes() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)

        let bytes = Data((0..<1_500_123).map { UInt8(($0 * 7) % 251) })
        let stream = AsyncThrowingStream<Data, Error> { continuation in
            continuation.yield(Data(bytes.prefix(17_321)))
            continuation.yield(Data(bytes.dropFirst(17_321).prefix(999_999)))
            continuation.yield(Data(bytes.dropFirst(1_017_320)))
            continuation.finish()
        }

        let store = EncryptedBlockStore(rootDirectory: directory.appendingPathComponent("vault", isDirectory: true))
        let rootKey = SymmetricKey(size: .bits256)
        let record = try await store.importStream(
            stream,
            filename: "streamed.jpg",
            mimeType: "image/jpeg",
            rootKey: rootKey,
            segmentCapacity: SegmentCapacity.megabytes50.bytes
        )

        #expect(record?.byteCount == Int64(bytes.count))
        #expect(record?.chunks.count == 2)
        #expect(try await store.plaintext(for: record!) == bytes)
    }

    @Test func failedStreamRollsBackAllocatedChunks() async throws {
        enum StreamFailure: Error {
            case interrupted
        }

        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)

        let stream = AsyncThrowingStream<Data, Error> { continuation in
            continuation.yield(Data(repeating: 7, count: VaultConstants.chunkPayloadSize))
            continuation.finish(throwing: StreamFailure.interrupted)
        }

        let store = EncryptedBlockStore(rootDirectory: directory.appendingPathComponent("vault", isDirectory: true))
        let rootKey = SymmetricKey(size: .bits256)

        do {
            _ = try await store.importStream(
                stream,
                filename: "interrupted.jpg",
                mimeType: "image/jpeg",
                rootKey: rootKey,
                segmentCapacity: SegmentCapacity.megabytes50.bytes
            )
            Issue.record("An interrupted stream must fail.")
        } catch is StreamFailure {
        } catch {
            Issue.record("Unexpected stream error: \(error)")
        }

        let snapshot = await store.snapshot()
        #expect(snapshot.records.isEmpty)
        #expect(snapshot.freeChunks.contains(ChunkAddress(segment: 0, slot: 0)))
        try await store.validateIndex()
    }

    @Test func duplicateReturnsExistingRecord() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let source = directory.appendingPathComponent("one.jpg")
        try Data("same bytes".utf8).write(to: source)

        let store = EncryptedBlockStore(rootDirectory: directory.appendingPathComponent("vault", isDirectory: true))
        let rootKey = SymmetricKey(size: .bits256)
        let first = try await store.importFile(at: source, filename: "one.jpg", mimeType: "image/jpeg", rootKey: rootKey, segmentCapacity: SegmentCapacity.megabytes50.bytes)
        let second = try await store.importFile(at: source, filename: "different-name.jpg", mimeType: "image/jpeg", rootKey: rootKey, segmentCapacity: SegmentCapacity.megabytes50.bytes)
        #expect(first?.id == second?.id)
        #expect((await store.snapshot()).records.count == 1)
    }
private static let videoFixtureBase64 =
        "AAAAIGZ0eXBpc29tAAACAGlzb21pc28yYXZjMW1wNDEAAAPBbW9vdgAAAGxtdmhkAAAAAAAAAAAAAAAAAAAD6AAAA+gAAQAAAQAA"
            + "AAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAA"
            + "Aux0cmFrAAAAXHRraGQAAAADAAAAAAAAAAAAAAABAAAAAAAAA+gAAAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAABAAAA"
            + "AAAAAAAAAAAAAABAAAAAAGAAAABAAAAAAAAkZWR0cwAAABxlbHN0AAAAAAAAAAEAAAPoAAAIAAABAAAAAAJkbWRpYQAAACBtZGhk"
            + "AAAAAAAAAAAAAAAAAAAwAAAAMABVxAAAAAAALWhkbHIAAAAAAAAAAHZpZGUAAAAAAAAAAAAAAABWaWRlb0hhbmRsZXIAAAACD21p"
            + "bmYAAAAUdm1oZAAAAAEAAAAAAAAAAAAAACRkaW5mAAAAHGRyZWYAAAAAAAAAAQAAAAx1cmwgAAAAAQAAAc9zdGJsAAAAv3N0c2QA"
            + "AAAAAAAAAQAAAK9hdmMxAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAGAAQABIAAAASAAAAAAAAAABFExhdmM2My4xLjEwMiBsaWJ4"
            + "MjY0AAAAAAAAAAAAAAAAGP//AAAANWF2Y0MBZAAK/+EAGGdkAAqs2UYmwEQAAAMABAAAAwBgPEiWWAEABmjr48siwP34+AAAAAAQ"
            + "cGFzcAAAAAEAAAABAAAAFGJ0cnQAAAAAAAAb8AAAAAAAAAAYc3R0cwAAAAAAAAABAAAADAAABAAAAAAUc3RzcwAAAAAAAAABAAAA"
            + "AQAAAGhjdHRzAAAAAAAAAAsAAAABAAAIAAAAAAEAABQAAAAAAQAACAAAAAABAAAAAAAAAAEAAAQAAAAAAQAAFAAAAAABAAAIAAAA"
            + "AAEAAAAAAAAAAQAABAAAAAABAAAQAAAAAAIAAAQAAAAAHHN0c2MAAAAAAAAAAQAAAAEAAAAMAAAAAQAAAERzdHN6AAAAAAAAAAAA"
            + "AAAMAAAC4gAAAA8AAAAMAAAADAAAAAwAAAAVAAAADgAAAAwAAAAMAAAAFAAAAA4AAAAMAAAAFHN0Y28AAAAAAAAAAQAAA/EAAABh"
            + "dWR0YQAAAFltZXRhAAAAAAAAACFoZGxyAAAAAAAAAABtZGlyYXBwbAAAAAAAAAAAAAAAACxpbHN0AAAAJKl0b28AAAAcZGF0YQAA"
            + "AAEAAAAATGF2ZjYzLjEuMTAyAAAACGZyZWUAAAOGbWRhdAAAAq4GBf//qtxF6b3m2Ui3lizYINkj7u94MjY0IC0gY29yZSAxNjUg"
            + "cjMyMjIgYjM1NjA1YSAtIEguMjY0L01QRUctNCBBVkMgY29kZWMgLSBDb3B5bGVmdCAyMDAzLTIwMjUgLSBodHRwOi8vd3d3LnZp"
            + "ZGVvbGFuLm9yZy94MjY0Lmh0bWwgLSBvcHRpb25zOiBjYWJhYz0xIHJlZj0zIGRlYmxvY2s9MTowOjAgYW5hbHlzZT0weDM6MHgx"
            + "MTMgbWU9aGV4IHN1Ym1lPTcgcHN5PTEgcHN5X3JkPTEuMDA6MC4wMCBtaXhlZF9yZWY9MSBtZV9yYW5nZT0xNiBjaHJvbWFfbWU9"
            + "MSB0cmVsbGlzPTEgOHg4ZGN0PTEgY3FtPTAgZGVhZHpvbmU9MjEsMTEgZmFzdF9wc2tpcD0xIGNocm9tYV9xcF9vZmZzZXQ9LTIg"
            + "dGhyZWFkcz0yIGxvb2thaGVhZF90aHJlYWRzPTEgc2xpY2VkX3RocmVhZHM9MCBucj0wIGRlY2ltYXRlPTEgaW50ZXJsYWNlZD0w"
            + "IGJsdXJheV9jb21wYXQ9MCBjb25zdHJhaW5lZF9pbnRyYT0wIGJmcmFtZXM9MyBiX3B5cmFtaWQ9MiBiX2FkYXB0PTEgYl9iaWFz"
            + "PTAgZGlyZWN0PTEgd2VpZ2h0Yj0xIG9wZW5fZ29wPTAgd2VpZ2h0cD0yIGtleWludD0yNTAga2V5aW50X21pbj0xMiBzY2VuZWN1"
            + "dD00MCBpbnRyYV9yZWZyZXNoPTAgcmNfbG9va2FoZWFkPTQwIHJjPWNyZiBtYnRyZWU9MSBjcmY9MjMuMCBxY29tcD0wLjYwIHFw"
            + "bWluPTAgcXBtYXg9NjkgcXBzdGVwPTQgaXBfcmF0aW89MS40MCBhcT0xOjEuMDAAgAAAACxliIQAEP/+5sD5llUNV3/9aT0r+M0i"
            + "5SXikwyt23GKfyKU7Q+8+C0DrjXOsQAAAAtBmiRsQQ/+qlUeUAAAAAhBnkJ4hv8C7wAAAAgBnmF0Qz8DVgAAAAgBnmNqQz8DVwAA"
            + "ABFBmmhJqEFomUwIf//+qZZaQQAAAApBnoZFESw3/wLvAAAACAGepXRDPwNXAAAACAGep2pDPwNWAAAAEEGaq0moQWyZTAhn//6e"
            + "EfsAAAAKQZ7JRRUsN/8C7wAAAAgBnupqQz8DVg=="

    private static func makeVideoFixture(at directory: URL) throws -> URL {
        guard let videoBytes = Data(base64Encoded: Self.videoFixtureBase64) else {
            fatalError("The embedded H.264 fixture is invalid.")
        }
        let source = directory.appendingPathComponent("poster-fixture.mp4")
        try videoBytes.write(to: source)
        return source
    }

    /// AUDIT #13: a video poster must be produced by streaming bounded byte
    /// ranges through the in-memory resource loader — no plaintext on disk.
    @Test func streamedVideoFileProducesPosterPreview() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let source = try Self.makeVideoFixture(at: directory)

        let store = EncryptedBlockStore(rootDirectory: directory.appendingPathComponent("vault", isDirectory: true))
        let rootKey = SymmetricKey(size: .bits256)
        guard let record = try await store.importFile(
            at: source,
            filename: source.lastPathComponent,
            mimeType: "video/mp4",
            rootKey: rootKey,
            segmentCapacity: SegmentCapacity.megabytes50.bytes
        ) else {
            Issue.record("Video import did not return a media record.")
            return
        }

        let provider = VaultVideoAssetProvider(
            mimeType: record.mimeType,
            byteCount: record.byteCount
        ) { offset, length in
            try await store.plaintext(for: record, byteRange: offset..<(offset + length))
        }
        let poster = await ThumbnailGenerator.fromVideoAsset(provider: provider, record: record, rootKey: rootKey)
        #expect(poster != nil)
        #expect(UIImage(data: poster ?? Data()) != nil)

        // AUDIT #13: no temporary plaintext file may be created for this vault
        // directory (the loader serves bytes in memory).
        let vaultDir = directory.appendingPathComponent("vault", isDirectory: true)
        let vaultFiles = (try? FileManager.default.contentsOfDirectory(at: vaultDir, includingPropertiesForKeys: nil)) ?? []
        #expect(!vaultFiles.contains {
            $0.lastPathComponent.hasPrefix("vaultplay-") || $0.lastPathComponent.hasPrefix("vaultthumb-")
        })
    }

    /// The resource loader must serve byte ranges that exactly match the
    /// original file, including a clamped tail past EOF and an empty range.
    @Test func inMemoryVideoAssetServesExactByteRanges() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let source = try Self.makeVideoFixture(at: directory)
        let original = try Data(contentsOf: source)

        let store = EncryptedBlockStore(rootDirectory: directory.appendingPathComponent("vault", isDirectory: true))
        let rootKey = SymmetricKey(size: .bits256)
        guard let record = try await store.importFile(
            at: source,
            filename: source.lastPathComponent,
            mimeType: "video/mp4",
            rootKey: rootKey,
            segmentCapacity: SegmentCapacity.megabytes50.bytes
        ) else {
            Issue.record("Video import did not return a media record.")
            return
        }

        // Whole file, one range.
        let whole = try await store.plaintext(for: record, byteRange: 0..<Int64(original.count))
        #expect(whole == original)

        // Two chunks covering the whole file (the fixture straddles the chunk boundary).
        let mid = Int64(original.count / 2)
        let first = try await store.plaintext(for: record, byteRange: 0..<mid)
        let last = try await store.plaintext(for: record, byteRange: mid..<Int64(original.count))
        #expect(first + last == original)

        // A range past EOF is a hard integrity failure at the store level;
        // the asset provider clamps before it ever reaches this API.
        do {
            _ = try await store.plaintext(
                for: record,
                byteRange: (Int64(original.count) - 8)..<Int64(original.count + 4096)
            )
            Issue.record("Out-of-range read must throw.")
        } catch {
            #expect(error is VaultError)
        }

        // An empty range is a legal no-op.
        let empty = try await store.plaintext(for: record, byteRange: mid..<mid)
        #expect(empty.isEmpty)
    }


    // MARK: - AUDIT #8 — interrupted pre-header creation

    private struct IsolatedCreationScope {
        let directory: URL
        let account: String
        /// Unique per scope: a model-level destruction wipes its whole
        /// service, so scopes must never share one.
        let service: String
        func makeStore() -> VaultStore {
            VaultStore(
                fileManager: RedirectedFileManager(replacement: directory),
                deviceSecretAccount: account,
                deviceSecretService: service)
        }
        static func make() throws -> IsolatedCreationScope {
            let directory = FileManager.default.temporaryDirectory
                .appendingPathComponent("vaulthalla-creation-\(UUID().uuidString)", isDirectory: true)
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            return IsolatedCreationScope(
                directory: directory,
                account: "creation-test-\(UUID().uuidString)",
                service: "io.sobaka.vaulthalla-tests-\(UUID().uuidString)")
        }
        func vaultDirectory() -> URL { directory.appendingPathComponent("Vaulthalla", isDirectory: true) }
        func cleanup() {
            try? KeychainStore.deleteDeviceSecret(account: account, service: service)
            try? FileManager.default.removeItem(at: directory)
        }
    }

    private func makeIsolatedAttemptStore() throws -> (store: AttemptStateStore, directory: URL) {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("attempt-state-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        var secret = Data(count: 32)
        _ = secret.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }
        let store = AttemptStateStore(
            account: "attempt-test-\(UUID().uuidString)",
            rootDirectory: directory,
            deviceSecret: { secret },
            service: VaulthallaTestKeychain.testService)
        return (store, directory)
    }

    /// A power cut inside `resumeCreation` (index committed, header not yet
    /// published) must leave a resumable state: no header, journal and index
    /// intact, and a plain retry with the same password completes creation.
    @Test func interruptedPreHeaderCreationRecoversOnRestart() async throws {
        let password = "long-creation-test-password"

        // Window A: crash after the index commit, before the header is staged.
        let scopeA = try IsolatedCreationScope.make()
        defer { scopeA.cleanup() }
        let stagedA = scopeA.makeStore()
        try await stagedA.createVault(password: password, segmentCapacity: .megabytes50, stopAfterStaging: true)
        await stagedA.injectCreationFault { stage in
            if stage == .afterIndexCommit { throw CreationCut() }
        }
        await #expect(throws: CreationCut.self) {
            try await stagedA.resumeCreation(password: password)
        }
        let vaultA = scopeA.vaultDirectory()
        #expect(!FileManager.default.fileExists(atPath: vaultA.appendingPathComponent("vault.header").path))
        #expect(!FileManager.default.fileExists(atPath: vaultA.appendingPathComponent("vault.header.creation").path))
        #expect(FileManager.default.fileExists(atPath: vaultA.appendingPathComponent("index.v1").path))
        #expect(FileManager.default.fileExists(atPath: vaultA.appendingPathComponent("vault.creation").path))
        let resumedA = scopeA.makeStore()
        try await resumedA.resumeCreation(password: password)
        #expect(FileManager.default.fileExists(atPath: vaultA.appendingPathComponent("vault.header").path))
        #expect(!FileManager.default.fileExists(atPath: vaultA.appendingPathComponent("vault.creation").path))
        _ = try await resumedA.unlock(password: password)

        // Window B: crash after the header is staged, before it is moved
        // into place. The staged header must be verified and committed on
        // retry.
        let scopeB = try IsolatedCreationScope.make()
        defer { scopeB.cleanup() }
        let stagedB = scopeB.makeStore()
        try await stagedB.createVault(password: password, segmentCapacity: .megabytes50, stopAfterStaging: true)
        await stagedB.injectCreationFault { stage in
            if stage == .afterHeaderStaged { throw CreationCut() }
        }
        await #expect(throws: CreationCut.self) {
            try await stagedB.resumeCreation(password: password)
        }
        let vaultB = scopeB.vaultDirectory()
        #expect(!FileManager.default.fileExists(atPath: vaultB.appendingPathComponent("vault.header").path))
        #expect(FileManager.default.fileExists(atPath: vaultB.appendingPathComponent("vault.header.creation").path))
        #expect(FileManager.default.fileExists(atPath: vaultB.appendingPathComponent("index.v1").path))
        #expect(FileManager.default.fileExists(atPath: vaultB.appendingPathComponent("vault.creation").path))
        let resumedB = scopeB.makeStore()
        try await resumedB.resumeCreation(password: password)
        #expect(FileManager.default.fileExists(atPath: vaultB.appendingPathComponent("vault.header").path))
        #expect(!FileManager.default.fileExists(atPath: vaultB.appendingPathComponent("vault.header.creation").path))
        #expect(!FileManager.default.fileExists(atPath: vaultB.appendingPathComponent("vault.creation").path))
        _ = try await resumedB.unlock(password: password)
    }

    /// A crash between the device-binding write and the journal write leaves
    /// a device secret with no vault at all. Load must fail closed (destroy
    /// the orphan binding) and a fresh vault must then be creatable.
    @Test @MainActor func orphanDeviceBindingWithoutJournalDestroysAndAllowsNewVault() async throws {
        let scope = try IsolatedCreationScope.make()
        defer { scope.cleanup() }
        var orphan = Data(count: 32)
        _ = orphan.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }
        try KeychainStore.saveDeviceSecret(orphan, account: scope.account, service: scope.service)

        let store = scope.makeStore()
        let model = VaultAppModel()
        model.store = store
        model.deviceSecretAccount = scope.account
        model.deviceSecretService = scope.service
        await model.load()
        #expect(model.destructionMessage == "Vault destroyed because its header was lost.")
        #expect(model.phase == .onboarding)
        await #expect(throws: VaultError.keychainFailure(errSecItemNotFound)) {
            _ = try KeychainStore.loadDeviceSecret(account: scope.account, service: scope.service)
        }
        // Cleanup cleared the orphan binding: creation works again.
        try await store.createVault(password: "long-creation-test-password", segmentCapacity: .megabytes50)
        #expect(await store.hasVault())
    }

    /// A crash after the header commit but before the journal cleanup leaves
    /// a matching journal next to the committed vault: load cleans it up and
    /// the vault stays fully usable.
    @Test @MainActor func committedVaultCleansUpMatchingOrphanJournal() async throws {
        let scope = try IsolatedCreationScope.make()
        defer { scope.cleanup() }
        let store = scope.makeStore()
        let password = "long-creation-test-password"
        try await store.createVault(password: password, segmentCapacity: .megabytes50)
        let vault = scope.vaultDirectory()
        let header = try JSONDecoder().decode(VaultHeader.self, from: try Data(contentsOf: vault.appendingPathComponent("vault.header")))
        let journal = VaultStore.CreationJournal(header: header, sealedSecrets: Data(repeating: 0, count: 28))
        try JSONEncoder().encode(journal).write(to: vault.appendingPathComponent("vault.creation"))

        let (attempts, attemptDir) = try makeIsolatedAttemptStore()
        defer { try? FileManager.default.removeItem(at: attemptDir) }
        let model = VaultAppModel()
        model.store = store
        model.attemptStore = attempts
        model.deviceSecretAccount = scope.account
        model.deviceSecretService = scope.service
        await model.load()
        #expect(model.destructionMessage.isEmpty)
        #expect(model.phase == .locked)
        #expect(!FileManager.default.fileExists(atPath: vault.appendingPathComponent("vault.creation").path))
        _ = try await store.unlock(password: password)
    }

    /// A journal next to a committed vault whose header does NOT match is a
    /// tamper signal: destroy, never ignore.
    @Test @MainActor func committedVaultDestroysOnMismatchedOrphanJournal() async throws {
        let scope = try IsolatedCreationScope.make()
        defer { scope.cleanup() }
        let store = scope.makeStore()
        let vault = scope.vaultDirectory()
        try await store.createVault(password: "long-creation-test-password", segmentCapacity: .megabytes50)
        let header = try JSONDecoder().decode(VaultHeader.self, from: try Data(contentsOf: vault.appendingPathComponent("vault.header")))
        let mismatched = VaultHeader(
            segmentCapacity: header.segmentCapacity,
            salt: Data(repeating: 0xEE, count: 32),
            iterations: header.iterations,
            wrappedRootKey: header.wrappedRootKey,
            auditPublicKey: header.auditPublicKey)
        let journal = VaultStore.CreationJournal(header: mismatched, sealedSecrets: Data(repeating: 0, count: 28))
        try JSONEncoder().encode(journal).write(to: vault.appendingPathComponent("vault.creation"))

        let (attempts, attemptDir) = try makeIsolatedAttemptStore()
        defer { try? FileManager.default.removeItem(at: attemptDir) }
        let model = VaultAppModel()
        model.store = store
        model.attemptStore = attempts
        model.deviceSecretAccount = scope.account
        model.deviceSecretService = scope.service
        await model.load()
        #expect(model.destructionMessage == "Vault destroyed because its creation state was confirmed tampered.")
        #expect(model.phase == .onboarding)
        #expect(!FileManager.default.fileExists(atPath: vault.path))
        await #expect(throws: VaultError.keychainFailure(errSecItemNotFound)) {
            _ = try KeychainStore.loadDeviceSecret(account: scope.account, service: scope.service)
        }
    }
}
