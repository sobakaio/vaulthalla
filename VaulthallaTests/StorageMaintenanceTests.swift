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
        // Copy-on-write compaction writes a new segment rather than overwriting
        // the old segment before the replacement index is committed.
        #expect(compactedSecond.chunks.first?.segment == compactedThird.chunks.first?.segment)
        #expect(compactedSecond.chunks.first?.segment != secondRecord!.chunks.first?.segment)
        // Record iteration order is not stable; either item may occupy either slot.
        #expect(Set([compactedSecond.chunks.first?.slot, compactedThird.chunks.first?.slot]) == Set([0, 1]))
        #expect(try await store.plaintext(for: compactedSecond) == second)
        #expect(try await store.plaintext(for: compactedThird) == third)
        let reopened = EncryptedBlockStore(rootDirectory: vaultDirectory)
        try await reopened.load(using: key)
        let committed = await reopened.snapshot()
        #expect(try await reopened.plaintext(for: committed.records[secondRecord!.id]!) == second)
        #expect(try await reopened.plaintext(for: committed.records[thirdRecord!.id]!) == third)
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

    @Test(arguments: EncryptedBlockStore.CompactionBoundary.allCases)
    func compactionFaultRestartPreservesCommittedDigest(boundary: EncryptedBlockStore.CompactionBoundary) async throws {
        struct InjectedFault: Error {}
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let vault = directory.appendingPathComponent("vault", isDirectory: true)
        let key = SymmetricKey(size: .bits256)
        let source = directory.appendingPathComponent("source.bin")
        let payload = Data(repeating: 0xA7, count: VaultConstants.chunkPayloadSize + 37)
        try payload.write(to: source)
        let initial = EncryptedBlockStore(rootDirectory: vault)
        let record = try #require(await initial.importFile(at: source, filename: "source.bin", mimeType: "application/octet-stream", rootKey: key, segmentCapacity: 3_000_000))
        let original = try #require((await initial.snapshot()).records[record.id])
        // AUDIT #2: for the `.partialChunk` boundary, physically write only half
        // a chunk to the new segment before the fault fires, to simulate a real
        // power cut mid-append.
        let partialHook: ((ChunkAddress, Data) -> Void)? = boundary == .partialChunk ? { address, data in
            let url = vault.appendingPathComponent("segment-\(address.segment).dat")
            if !FileManager.default.fileExists(atPath: url.path) {
                FileManager.default.createFile(atPath: url.path, contents: nil)
            }
            guard let handle = try? FileHandle(forUpdating: url) else { return }
            defer { try? handle.close() }
            let slot = VaultConstants.chunkPayloadSize + 28
            try? handle.seek(toOffset: UInt64(address.slot) * UInt64(slot))
            try? handle.write(contentsOf: data.prefix(data.count / 2))
        } : nil
        let faulted = EncryptedBlockStore(rootDirectory: vault, compactionFault: { point in
            if point == boundary { throw InjectedFault() }
        }, partialChunkHook: partialHook)
        try await faulted.load(using: key)
        if boundary == .cleanup {
            _ = try await faulted.compact(using: key, segmentCapacity: 3_000_000)
        } else {
            do {
                _ = try await faulted.compact(using: key, segmentCapacity: 3_000_000)
                Issue.record("Expected injected fault at \(boundary)")
            } catch is InjectedFault { // expected before index commit
            }
        }
        let reopened = EncryptedBlockStore(rootDirectory: vault)
        try await reopened.load(using: key)
        let persisted = try #require((await reopened.snapshot()).records[record.id])
        #expect(persisted.sha256 == original.sha256)
        #expect(persisted.byteCount == original.byteCount)
        #expect(try await reopened.plaintext(for: persisted) == payload)
        if boundary == .cleanup {
            #expect(persisted.chunks != original.chunks)
            #expect(FileManager.default.fileExists(atPath: vault.appendingPathComponent("segment-0.dat").path))
        } else {
            #expect(persisted.chunks == original.chunks)
        }
        if boundary == .partialChunk {
            // The simulated partial write must have physically reached the
            // unreferenced new segment; the old index must not point to it.
            let orphan = vault.appendingPathComponent("segment-1.dat")
            #expect(FileManager.default.fileExists(atPath: orphan.path))
            let allChunks = (await reopened.snapshot()).records.values.flatMap { $0.chunks.map(\.segment) }
            #expect(!allChunks.contains(1), "old index must not reference the partial segment")
        }
        if boundary == .afterIndexStaged {
            // The staged replacement index exists but is unpublished; the old
            // index file must be untouched and authoritative.
            #expect(FileManager.default.fileExists(atPath: vault.appendingPathComponent("index.v1.tmp").path))
            #expect(FileManager.default.fileExists(atPath: vault.appendingPathComponent("index.v1").path))
        }
    }

}

private actor SuspendedImportSource {
    private var callCount = 0
    private var entered: CheckedContinuation<Void, Never>?
    private var waiter: CheckedContinuation<Data?, Never>?
    private var released = false
    private let resumeData: Data?

    init(resumeData: Data?) { self.resumeData = resumeData }

    func next() async -> Data? {
        callCount += 1
        if callCount == 1 { return Data(repeating: 0xE3, count: VaultConstants.chunkPayloadSize) }
        entered?.resume()
        entered = nil
        return await withCheckedContinuation { continuation in
            if released { continuation.resume(returning: resumeData) }
            else { waiter = continuation }
        }
    }

    func waitUntilSuspended() async {
        if callCount >= 2 { return }
        await withCheckedContinuation { entered = $0 }
    }

    func release() {
        released = true
        waiter?.resume(returning: resumeData)
        waiter = nil
    }
}

extension StorageMaintenanceTests {
    @Test(arguments: [false, true])
    func revokedSuspendedStreamCannotCommitAfterReactivation(resumeWithChunk: Bool) async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let vault = directory.appendingPathComponent("vault", isDirectory: true)
        let key = SymmetricKey(size: .bits256)
        let store = EncryptedBlockStore(rootDirectory: vault)
        let existingBytes = Data(repeating: 0x47, count: 4093)
        let existingURL = directory.appendingPathComponent("existing.bin")
        try existingBytes.write(to: existingURL)
        let existing = try #require(await store.importFile(at: existingURL, filename: "existing.bin", mimeType: "application/octet-stream", rootKey: key, segmentCapacity: 3_000_000))
        let originalDigest = existing.sha256
        let initialIDs = Set((await store.snapshot()).records.keys)

        let source = SuspendedImportSource(resumeData: resumeWithChunk ? Data(repeating: 0xBC, count: 19) : nil)
        let stream = AsyncThrowingStream<Data, Error>(unfolding: { await source.next() })
        let importTask = Task {
            try await store.importStream(stream, filename: "stale.bin", mimeType: "application/octet-stream", rootKey: key, segmentCapacity: 3_000_000)
        }
        // The second pull proves the first full chunk was processed and the
        // import is suspended inside its async stream, not merely scheduled.
        await source.waitUntilSuspended()
        await store.revokeAccess()
        await store.activateAccess()
        await source.release()
        do {
            _ = try await importTask.value
            Issue.record("Suspended import committed after revoke/reactivate")
        } catch is CancellationError {
            // Access-generation mismatch must survive immediate reactivation.
        } catch {
            Issue.record("Expected CancellationError, got \(error)")
        }

        let live = await store.snapshot()
        #expect(Set(live.records.keys) == initialIDs)
        let liveExisting = try #require(live.records[existing.id])
        #expect(liveExisting.sha256 == originalDigest)
        #expect(try await store.plaintext(for: liveExisting) == existingBytes)

        let reopened = EncryptedBlockStore(rootDirectory: vault)
        try await reopened.load(using: key)
        let persisted = await reopened.snapshot()
        #expect(Set(persisted.records.keys) == initialIDs)
        let persistedExisting = try #require(persisted.records[existing.id])
        #expect(persistedExisting.sha256 == originalDigest)
        #expect(try await reopened.plaintext(for: persistedExisting) == existingBytes)
    }

    /// AUDIT #4: destruction runs while a stream import is suspended mid-flight.
    /// Revocation stays in force through destruction, so the stale task must
    /// abort — and it must not recreate vault storage after the directory is
    /// gone (no header, no index, no segments).
    @Test(arguments: [false, true])
    func destroyedVaultIsNotRecreatedByStaleImport(resumeWithChunk: Bool) async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let vault = directory.appendingPathComponent("vault", isDirectory: true)
        let key = SymmetricKey(size: .bits256)
        let store = EncryptedBlockStore(rootDirectory: vault)
        let existingBytes = Data(repeating: 0x47, count: 4093)
        let existingURL = directory.appendingPathComponent("existing.bin")
        try existingBytes.write(to: existingURL)
        _ = try await store.importFile(at: existingURL, filename: "existing.bin", mimeType: "application/octet-stream", rootKey: key, segmentCapacity: 3_000_000)

        let source = SuspendedImportSource(resumeData: resumeWithChunk ? Data(repeating: 0xBC, count: 19) : nil)
        let stream = AsyncThrowingStream<Data, Error>(unfolding: { await source.next() })
        let importTask = Task {
            try await store.importStream(stream, filename: "stale.bin", mimeType: "application/octet-stream", rootKey: key, segmentCapacity: 3_000_000)
        }
        // First full chunk is on disk; the import is suspended in the stream.
        await source.waitUntilSuspended()
        await store.revokeAccess()
        // Destruction: VaultStore.destroyVault deletes the directory after key
        // destruction; here the Keychain key is out of scope, so directory
        // removal plus revocation is the equivalent final state.
        try FileManager.default.removeItem(at: vault)
        await source.release()
        do {
            _ = try await importTask.value
            Issue.record("Stale import completed after destruction")
        } catch {
            // Expected: revocation aborts the import whatever it was holding.
        }
        #expect(!FileManager.default.fileExists(atPath: vault.path))
    }
}

