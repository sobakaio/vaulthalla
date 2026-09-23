import Testing
import Foundation
import CryptoKit
@testable import Vaulthalla

struct StorageMaintenanceTests {
    @Test func compactionRelocatesChunksAndPreservesPlaintext() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)

        let vaultDirectory = directory.appendingPathComponent("vault", isDirectory: true)
        let key = SymmetricKey(size: .bits256)
        let store = EncryptedBlockStore(rootDirectory: vaultDirectory)
        let capacity = 3_000_000

        let firstURL = directory.appendingPathComponent("first.jpg")
        let secondURL = directory.appendingPathComponent("second.jpg")
        let thirdURL = directory.appendingPathComponent("third.jpg")
        let first = Data(repeating: 1, count: VaultConstants.chunkPayloadSize)
        let second = Data(repeating: 2, count: VaultConstants.chunkPayloadSize)
        let third = Data(repeating: 3, count: VaultConstants.chunkPayloadSize)
        try first.write(to: firstURL)
        try second.write(to: secondURL)
        try third.write(to: thirdURL)

        let firstRecord = try await store.importFile(at: firstURL, filename: "first.jpg", mimeType: "image/jpeg", rootKey: key, segmentCapacity: capacity)
        let secondRecord = try await store.importFile(at: secondURL, filename: "second.jpg", mimeType: "image/jpeg", rootKey: key, segmentCapacity: capacity)
        let thirdRecord = try await store.importFile(at: thirdURL, filename: "third.jpg", mimeType: "image/jpeg", rootKey: key, segmentCapacity: capacity)
        try await store.delete(firstRecord!.id, rootKey: key)
        _ = try await store.compact(using: key, segmentCapacity: capacity)

        let snapshot = await store.snapshot()
        let compactedSecond = snapshot.records[secondRecord!.id]!
        let compactedThird = snapshot.records[thirdRecord!.id]!
        #expect(compactedSecond.chunks.first == ChunkAddress(segment: 0, slot: 0))
        #expect(compactedThird.chunks.first == ChunkAddress(segment: 0, slot: 1))
        #expect(try await store.plaintext(for: compactedSecond) == second)
        #expect(try await store.plaintext(for: compactedThird) == third)
    }

    @Test func deleteMakesChunkReusableAndCompactRemovesEmptySegment() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let source = directory.appendingPathComponent("a.jpg")
        try Data(repeating: 1, count: 100).write(to: source)

        let store = EncryptedBlockStore(rootDirectory: directory.appendingPathComponent("vault", isDirectory: true))
        let key = SymmetricKey(size: .bits256)
        let record = try await store.importFile(at: source, filename: "a.jpg", mimeType: "image/jpeg", rootKey: key, segmentCapacity: SegmentCapacity.megabytes50.bytes)
        try await store.delete(record!.id, rootKey: key)
        #expect((await store.snapshot()).freeChunks.count == 1)
        _ = try await store.compact(using: key)
        #expect((await store.snapshot()).freeChunks.isEmpty)
    }

    @Test func segmentRolloverAllocatesAcrossSegments() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)

        let slotSize = VaultConstants.chunkPayloadSize + 12 + 16
        let segmentCapacity = slotSize * 2  // exactly two slots per segment
        let source = directory.appendingPathComponent("big.jpg")
        let bytes = Data((0..<(VaultConstants.chunkPayloadSize * 2 + 1)).map { UInt8($0 % 251) })
        try bytes.write(to: source)

        let store = EncryptedBlockStore(rootDirectory: directory.appendingPathComponent("vault", isDirectory: true))
        let key = SymmetricKey(size: .bits256)
        let record = try await store.importFile(at: source, filename: "big.jpg", mimeType: "image/jpeg", rootKey: key, segmentCapacity: segmentCapacity)

        #expect(record?.chunks.count == 3)
        let segments = Set(record!.chunks.map(\.segment))
        #expect(segments == Set([0, 1]))
        #expect(record!.chunks.first == ChunkAddress(segment: 0, slot: 0))
        #expect(record!.chunks.last == ChunkAddress(segment: 1, slot: 0))
        #expect(try await store.plaintext(for: record!) == bytes)
    }

    @Test func verifyDetectsCorruptedChunk() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)

        let source = directory.appendingPathComponent("corruptable.jpg")
        let bytes = Data((0..<2_000_000).map { UInt8(($0 &* 31) % 251) })
        try bytes.write(to: source)

        let vaultDirectory = directory.appendingPathComponent("vault", isDirectory: true)
        let key = SymmetricKey(size: .bits256)
        let store = EncryptedBlockStore(rootDirectory: vaultDirectory)
        let record = try await store.importFile(at: source, filename: "corruptable.jpg", mimeType: "image/jpeg", rootKey: key, segmentCapacity: SegmentCapacity.megabytes50.bytes)
        #expect(record != nil)
        try await store.save(using: key)

        // Corrupt one ciphertext byte of the second chunk.
        let slotSize = VaultConstants.chunkPayloadSize + 12 + 16
        let segmentURL = vaultDirectory.appendingPathComponent("segment-0.dat")
        var data = try Data(contentsOf: segmentURL)
        let offset = (1 * slotSize) + 40
        data[offset] ^= 0xFF
        try data.write(to: segmentURL)

        let freshStore = EncryptedBlockStore(rootDirectory: vaultDirectory)
        _ = try await freshStore.load(using: key)
        let result = try await freshStore.verifyAll()
        #expect(result.corrupt == [record!.id])
    }

    @Test func verifyAllHonorsCancellation() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)

        let store = EncryptedBlockStore(rootDirectory: directory.appendingPathComponent("vault", isDirectory: true))
        let key = SymmetricKey(size: .bits256)
        for index in 0..<120 {
            let url = directory.appendingPathComponent("c\(index).jpg")
            try Data(repeating: UInt8(index % 251), count: 30_000).write(to: url)
            let record = try await store.importFile(at: url, filename: url.lastPathComponent, mimeType: "image/jpeg", rootKey: key, segmentCapacity: SegmentCapacity.megabytes50.bytes)
            #expect(record != nil)
        }

        let task = Task { try await store.verifyAll() }
        try await Task.sleep(for: .milliseconds(30))
        task.cancel()
        do {
            _ = try await task.value
            Issue.record("verifyAll should have thrown CancellationError")
        } catch is CancellationError {
            // expected
        } catch {
            Issue.record("unexpected error: \(error)")
        }
    }

    @Test func compactHonorsCancellation() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)

        let vaultDirectory = directory.appendingPathComponent("vault", isDirectory: true)
        let store = EncryptedBlockStore(rootDirectory: vaultDirectory)
        let key = SymmetricKey(size: .bits256)
        let capacity = SegmentCapacity.megabytes50.bytes  // everything fits in segment 0

        var records: [MediaRecord] = []
        for index in 0..<120 {
            let url = directory.appendingPathComponent("k\(index).jpg")
            try Data(repeating: UInt8(index % 251), count: 40_000).write(to: url)
            let record = try await store.importFile(at: url, filename: url.lastPathComponent, mimeType: "image/jpeg", rootKey: key, segmentCapacity: capacity)
            if let record { records.append(record) }
        }

        // Delete every other record so compaction must relocate many chunks into the gaps.
        for (offset, record) in records.enumerated() where offset % 2 == 1 {
            try await store.delete(record.id, rootKey: key)
        }

        func segmentMTimes() -> [Date] {
            ((try? FileManager.default.contentsOfDirectory(at: vaultDirectory, includingPropertiesForKeys: [.contentModificationDateKey])) ?? [])
                .compactMap { (try? $0.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate) }
                .sorted()
        }
        let baselineMTimes = segmentMTimes()
        let task = Task { _ = try await store.compact(using: key, segmentCapacity: capacity) }
        // Cancel only after compact has provably started rewriting segments.
        for _ in 0..<600 {
            try await Task.sleep(for: .milliseconds(5))
            if segmentMTimes() != baselineMTimes { break }
        }
        task.cancel()
        do {
            _ = try await task.value
            Issue.record("compact should have thrown CancellationError")
        } catch is CancellationError {
            // expected
        } catch {
            Issue.record("unexpected error: \(error)")
        }
    }

}
