import Testing
import Foundation
import CryptoKit
import Security
@testable import Vaulthalla

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
    @Test func streamedVideoFileProducesPosterPreview() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)

        let encoded = "AAAAIGZ0eXBpc29tAAACAGlzb21pc28yYXZjMW1wNDEAAAPBbW9vdgAAAGxtdmhkAAAAAAAAAAAAAAAAAAAD6AAAA+gAAQAAAQAA"
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
        guard let videoBytes = Data(base64Encoded: encoded) else {
            Issue.record("The embedded H.264 fixture is invalid.")
            return
        }
        let source = directory.appendingPathComponent("poster-fixture.mp4")
        try videoBytes.write(to: source)

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

        let protectedURL = directory.appendingPathComponent("vaultthumb-fixture.mp4")
        try await store.writePlaintext(for: record, to: protectedURL)
        defer { try? FileManager.default.removeItem(at: protectedURL) }
        let poster = await ThumbnailGenerator.fromURL(protectedURL, isVideo: true)
        #expect(poster != nil)
    }

}
