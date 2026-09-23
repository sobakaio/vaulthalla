import Testing
import Foundation
import CryptoKit
@testable import Vaulthalla

struct StorageTests {
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
