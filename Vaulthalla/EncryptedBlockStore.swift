import Foundation
import CryptoKit

actor EncryptedBlockStore {
    let rootDirectory: URL
    private let fileManager: FileManager
    enum CompactionBoundary: CaseIterable {
        case write, sync, replace, cleanup
    }
    private let compactionFault: ((CompactionBoundary) throws -> Void)?
    private(set) var index = VaultIndex()
    private var accessGeneration: UInt64 = 0
    private var accessRevoked = false

    func revokeAccess() {
        accessGeneration &+= 1
        accessRevoked = true
    }

    func activateAccess() {
        accessGeneration &+= 1
        accessRevoked = false
    }

    private var indexURL: URL { rootDirectory.appendingPathComponent("index.v1") }
    private var segmentURLPrefix: String { "segment-" }
    private var slotSize: Int { VaultConstants.chunkPayloadSize + 12 + 16 }

    init(rootDirectory: URL, fileManager: FileManager = .default,
         compactionFault: ((CompactionBoundary) throws -> Void)? = nil) {
        self.rootDirectory = rootDirectory
        self.fileManager = fileManager
        self.compactionFault = compactionFault
    }

    func initialize(using rootKey: SymmetricKey, auditPrivateKey: Data) throws {
        activateAccess()
        guard !fileManager.fileExists(atPath: indexURL.path) else { throw VaultError.vaultAlreadyExists }
        index = VaultIndex()
        index.auditPrivateKey = auditPrivateKey
        index.auditPrivacyVersion = 1
        try fileManager.createDirectory(at: rootDirectory, withIntermediateDirectories: true)
        try save(using: rootKey)
    }

    func load(using rootKey: SymmetricKey) throws {
        guard !accessRevoked else { throw CancellationError() }
        guard let data = fileManager.contents(atPath: indexURL.path) else {
            // A missing committed index is distinct from a temporarily unreadable
            // Data Protection or filesystem item.
            if !fileManager.fileExists(atPath: indexURL.path) {
                throw VaultError.missingCommittedIndex
            }
            throw VaultError.integrityFailure
        }
        guard data.count >= 28 else { throw VaultError.authenticatedIndexMismatch }
        let nonce = try AES.GCM.Nonce(data: data.prefix(12))
        let box = try AES.GCM.SealedBox(nonce: nonce, ciphertext: data.dropFirst(12).dropLast(16), tag: data.suffix(16))
        let plaintext: Data
        do {
            plaintext = try AES.GCM.open(box, using: rootKey, authenticating: Data("Vaulthalla-index-v1".utf8))
        } catch CryptoKitError.authenticationFailure {
            throw VaultError.authenticatedIndexMismatch
        }
        index = try JSONDecoder().decode(VaultIndex.self, from: plaintext)
        do {
            try validateIndex()
        } catch VaultError.integrityFailure {
            throw VaultError.authenticatedIndexMismatch
        }
    }

    func save(using rootKey: SymmetricKey) throws {
        guard !accessRevoked else { throw CancellationError() }
        let plaintext = try JSONEncoder().encode(index)
        let sealed = try AES.GCM.seal(plaintext, using: rootKey, authenticating: Data("Vaulthalla-index-v1".utf8))
        let data = sealed.nonce.withUnsafeBytes { Data($0) } + sealed.ciphertext + sealed.tag
        let temporary = indexURL.appendingPathExtension("tmp")
        try data.write(to: temporary, options: .atomic)
        try protectAndExclude(temporary)
        let temporaryHandle = try FileHandle(forWritingTo: temporary)
        try temporaryHandle.synchronize()
        try temporaryHandle.close()
        if fileManager.fileExists(atPath: indexURL.path) {
            _ = try fileManager.replaceItemAt(indexURL, withItemAt: temporary)
        } else {
            try fileManager.moveItem(at: temporary, to: indexURL)
        }
    }

    func appendEncryptedChunk(_ encryptedChunk: Data, address: ChunkAddress) throws {
        guard !accessRevoked else { throw CancellationError() }
        guard encryptedChunk.count == slotSize else { throw VaultError.storageFailure }
        let url = segmentURL(for: address.segment)
        try fileManager.createDirectory(at: rootDirectory, withIntermediateDirectories: true)
        if !fileManager.fileExists(atPath: url.path) {
            guard fileManager.createFile(atPath: url.path, contents: nil, attributes: [.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication.rawValue]) else { throw VaultError.storageFailure }
            try protectAndExclude(url)
        }
        let handle = try FileHandle(forUpdating: url)
        defer { try? handle.close() }
        try handle.seek(toOffset: UInt64(address.slot * slotSize))
        try handle.write(contentsOf: encryptedChunk)
        try handle.synchronize()
    }

    func readEncryptedChunk(at address: ChunkAddress) throws -> Data {
        guard !accessRevoked else { throw CancellationError() }
        let url = segmentURL(for: address.segment)
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        try handle.seek(toOffset: UInt64(address.slot * slotSize))
        let data = try handle.read(upToCount: slotSize) ?? Data()
        guard data.count == slotSize else { throw VaultError.integrityFailure }
        return data
    }

    func segmentURL(for segment: Int) -> URL {
        rootDirectory.appendingPathComponent("\(segmentURLPrefix)\(segment).dat")
    }

    func importFile(at sourceURL: URL, filename: String, mimeType: String, rootKey: SymmetricKey, segmentCapacity: Int) throws -> MediaRecord? {
        guard !accessRevoked else { throw CancellationError() }
        let handle = try FileHandle(forReadingFrom: sourceURL)
        defer { try? handle.close() }

        let itemID = UUID()
        let mediaKey = VaultCrypto.randomData(count: 32)
        var addresses: [ChunkAddress] = []
        var encryptedChunks: [Data] = []
        var digest = SHA256()
        var totalBytes: Int64 = 0
        var ordinal = 0

        while let sourceChunk = try handle.read(upToCount: VaultConstants.chunkPayloadSize), !sourceChunk.isEmpty {
            digest.update(data: sourceChunk)
            totalBytes += Int64(sourceChunk.count)
            var padded = sourceChunk
            padded.append(Data(repeating: 0, count: VaultConstants.chunkPayloadSize - sourceChunk.count))
            let address = try allocate(segmentCapacity: segmentCapacity)
            let chunkKey = HKDF<SHA256>.deriveKey(
                inputKeyMaterial: SymmetricKey(data: mediaKey),
                salt: Data("Vaulthalla-media-salt-v1".utf8),
                info: Data("item:\(itemID.uuidString)|chunk:\(ordinal)|format:1".utf8),
                outputByteCount: 32
            )
            let nonceKey = HKDF<SHA256>.deriveKey(
                inputKeyMaterial: SymmetricKey(data: mediaKey),
                salt: Data("Vaulthalla-nonce-salt-v1".utf8),
                info: Data("item:\(itemID.uuidString)|chunk:\(ordinal)|format:1".utf8),
                outputByteCount: 12
            )
            let nonce = try AES.GCM.Nonce(data: nonceKey.withUnsafeBytes { Data($0) })
            let sealed = try AES.GCM.seal(padded, using: chunkKey, nonce: nonce, authenticating: Data("Vaulthalla-chunk-v1|\(address.segment)|\(address.slot)".utf8))
            let physical = nonce.withUnsafeBytes { Data($0) } + sealed.ciphertext + sealed.tag
            try appendEncryptedChunk(physical, address: address)
            addresses.append(address)
            encryptedChunks.append(physical)
            ordinal += 1
        }

        let hash = Data(digest.finalize())
        if let duplicate = index.records.values.first(where: { $0.sha256 == hash }) {
            _ = try plaintext(for: duplicate)
            for address in addresses { index.freeChunks.insert(address) }
            return duplicate
        }

        let record = MediaRecord(id: itemID, filename: filename, byteCount: totalBytes, mimeType: mimeType, importedAt: Date(), sha256: hash, mediaKey: mediaKey, chunks: addresses, encryptedThumbnail: nil)
        index.records[record.id] = record
        try validateIndex()
        try save(using: rootKey)
        return record
    }

    func importStream(
        _ stream: AsyncThrowingStream<Data, Error>,
        filename: String,
        mimeType: String,
        rootKey: SymmetricKey,
        segmentCapacity: Int
    ) async throws -> MediaRecord? {
        guard !accessRevoked else { throw CancellationError() }
        let generation = accessGeneration
        let itemID = UUID()
        let mediaKey = VaultCrypto.randomData(count: 32)
        var addresses: [ChunkAddress] = []
        var digest = SHA256()
        var totalBytes: Int64 = 0
        var ordinal = 0
        var pending = Data()

        do {
            for try await sourceChunk in stream {
                guard !accessRevoked, generation == accessGeneration else { throw CancellationError() }
                try Task.checkCancellation()
                pending.append(sourceChunk)
                while pending.count >= VaultConstants.chunkPayloadSize {
                    try Task.checkCancellation()
                    let chunk = Data(pending.prefix(VaultConstants.chunkPayloadSize))
                    pending.removeFirst(VaultConstants.chunkPayloadSize)
                    try appendStreamChunk(
                        chunk,
                        itemID: itemID,
                        mediaKey: mediaKey,
                        ordinal: ordinal,
                        addresses: &addresses,
                        digest: &digest,
                        totalBytes: &totalBytes,
                        rootKey: rootKey,
                        segmentCapacity: segmentCapacity
                    )
                    ordinal += 1
                }
            }

            if !pending.isEmpty {
                try Task.checkCancellation()
                try appendStreamChunk(
                    pending,
                    itemID: itemID,
                    mediaKey: mediaKey,
                    ordinal: ordinal,
                    addresses: &addresses,
                    digest: &digest,
                    totalBytes: &totalBytes,
                    rootKey: rootKey,
                    segmentCapacity: segmentCapacity
                )
            }
        } catch {
            for address in addresses {
                index.freeChunks.insert(address)
            }
            if !accessRevoked, generation == accessGeneration {
                try? validateIndex()
                try? save(using: rootKey)
            }
            throw error
        }

        guard !accessRevoked, generation == accessGeneration else { throw CancellationError() }
        let hash = Data(digest.finalize())
        if let duplicate = index.records.values.first(where: { $0.sha256 == hash }) {
            _ = try plaintext(for: duplicate)
            for address in addresses {
                index.freeChunks.insert(address)
            }
            return duplicate
        }

        let record = MediaRecord(
            id: itemID,
            filename: filename,
            byteCount: totalBytes,
            mimeType: mimeType,
            importedAt: Date(),
            sha256: hash,
            mediaKey: mediaKey,
            chunks: addresses,
            encryptedThumbnail: nil
        )
        index.records[record.id] = record
        try validateIndex()
        try save(using: rootKey)
        return record
    }

    private func appendStreamChunk(
        _ sourceChunk: Data,
        itemID: UUID,
        mediaKey: Data,
        ordinal: Int,
        addresses: inout [ChunkAddress],
        digest: inout SHA256,
        totalBytes: inout Int64,
        rootKey: SymmetricKey,
        segmentCapacity: Int
    ) throws {
        guard !accessRevoked else { throw CancellationError() }
        digest.update(data: sourceChunk)
        totalBytes += Int64(sourceChunk.count)
        var padded = sourceChunk
        padded.append(Data(repeating: 0, count: VaultConstants.chunkPayloadSize - sourceChunk.count))
        let address = try allocate(segmentCapacity: segmentCapacity)
        let info = Data("item:\(itemID.uuidString)|chunk:\(ordinal)|format:1".utf8)
        let chunkKey = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: mediaKey),
            salt: Data("Vaulthalla-media-salt-v1".utf8),
            info: info,
            outputByteCount: 32
        )
        let nonceKey = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: mediaKey),
            salt: Data("Vaulthalla-nonce-salt-v1".utf8),
            info: info,
            outputByteCount: 12
        )
        let nonce = try AES.GCM.Nonce(data: nonceKey.withUnsafeBytes { Data($0) })
        let aad = Data("Vaulthalla-chunk-v1|\(address.segment)|\(address.slot)".utf8)
        let sealed = try AES.GCM.seal(padded, using: chunkKey, nonce: nonce, authenticating: aad)
        let physical = nonce.withUnsafeBytes { Data($0) } + sealed.ciphertext + sealed.tag
        try appendEncryptedChunk(physical, address: address)
        addresses.append(address)
    }

    private func allocate(segmentCapacity: Int) throws -> ChunkAddress {
        if let reusable = index.freeChunks.first {
            index.freeChunks.remove(reusable)
            return reusable
        }
        let slotsPerSegment = max(1, segmentCapacity / slotSize)
        let segment = index.nextSlotBySegment.keys.sorted().last ?? 0
        let slot = index.nextSlotBySegment[segment] ?? 0
        if slot >= slotsPerSegment {
            let nextSegment = segment + 1
            index.nextSlotBySegment[nextSegment] = 1
            return ChunkAddress(segment: nextSegment, slot: 0)
        }
        index.nextSlotBySegment[segment] = slot + 1
        return ChunkAddress(segment: segment, slot: slot)
    }

    /// Writes authenticated plaintext to a complete-protection temporary file
    /// without buffering an entire large media item in memory. The caller must
    /// remove the file as soon as it has finished deriving its preview.
    /// NOTE: the app no longer calls this in normal operation (AUDIT #13 — media
    /// is served in memory); it remains for tests and the import-boundary tooling.
    func writePlaintext(for record: MediaRecord, to url: URL) throws {
        guard !accessRevoked else { throw CancellationError() }
        guard record.byteCount >= 0,
              !fileManager.fileExists(atPath: url.path),
              fileManager.createFile(
                atPath: url.path,
                contents: nil,
                attributes: [.protectionKey: FileProtectionType.complete.rawValue]
              ) else {
            throw VaultError.storageFailure
        }

        var complete = false
        defer {
            if !complete { try? fileManager.removeItem(at: url) }
        }
        // Apply protection explicitly before writing the first plaintext byte.
        try fileManager.setAttributes(
            [.protectionKey: FileProtectionType.complete.rawValue],
            ofItemAtPath: url.path
        )
        let handle = try FileHandle(forWritingTo: url)
        defer { try? handle.close() }

        var digest = SHA256()
        var bytesWritten: Int64 = 0
        for (ordinal, address) in record.chunks.enumerated() {
            try Task.checkCancellation()
            let physical = try readEncryptedChunk(at: address)
            guard physical.count == slotSize else { throw VaultError.integrityFailure }
            let nonce = try AES.GCM.Nonce(data: physical.prefix(12))
            let chunkKey = HKDF<SHA256>.deriveKey(
                inputKeyMaterial: SymmetricKey(data: record.mediaKey),
                salt: Data("Vaulthalla-media-salt-v1".utf8),
                info: Data("item:\(record.id.uuidString)|chunk:\(ordinal)|format:1".utf8),
                outputByteCount: 32
            )
            let box = try AES.GCM.SealedBox(
                nonce: nonce,
                ciphertext: physical.dropFirst(12).dropLast(16),
                tag: physical.suffix(16)
            )
            let clear = try AES.GCM.open(
                box,
                using: chunkKey,
                authenticating: Data("Vaulthalla-chunk-v1|\(address.segment)|\(address.slot)".utf8)
            )
            let remaining = record.byteCount - bytesWritten
            guard remaining > 0 else { throw VaultError.integrityFailure }
            let payload = Data(clear.prefix(Int(min(Int64(clear.count), remaining))))
            digest.update(data: payload)
            try handle.write(contentsOf: payload)
            bytesWritten += Int64(payload.count)
        }

        guard bytesWritten == record.byteCount,
              Data(digest.finalize()) == record.sha256 else {
            throw VaultError.integrityFailure
        }
        try handle.synchronize()
        complete = true
    }

    func plaintext(for record: MediaRecord, byteRange: Range<Int64>) throws -> Data {
        guard byteRange.lowerBound >= 0,
              byteRange.upperBound <= record.byteCount,
              byteRange.lowerBound <= byteRange.upperBound else {
            throw VaultError.integrityFailure
        }
        if byteRange.isEmpty { return Data() }
        let firstChunk = Int(byteRange.lowerBound / Int64(VaultConstants.chunkPayloadSize))
        let lastChunk = Int((byteRange.upperBound - 1) / Int64(VaultConstants.chunkPayloadSize))
        var result = Data()
        for ordinal in firstChunk...lastChunk {
            let address = record.chunks[ordinal]
            let physical = try readEncryptedChunk(at: address)
            let nonce = try AES.GCM.Nonce(data: physical.prefix(12))
            let chunkKey = HKDF<SHA256>.deriveKey(
                inputKeyMaterial: SymmetricKey(data: record.mediaKey),
                salt: Data("Vaulthalla-media-salt-v1".utf8),
                info: Data("item:\(record.id.uuidString)|chunk:\(ordinal)|format:1".utf8),
                outputByteCount: 32
            )
            let box = try AES.GCM.SealedBox(
                nonce: nonce,
                ciphertext: physical.dropFirst(12).dropLast(16),
                tag: physical.suffix(16)
            )
            let clear = try AES.GCM.open(
                box,
                using: chunkKey,
                authenticating: Data("Vaulthalla-chunk-v1|\(address.segment)|\(address.slot)".utf8)
            )
            let chunkStart = Int64(ordinal * VaultConstants.chunkPayloadSize)
            let lower = max(byteRange.lowerBound, chunkStart) - chunkStart
            let upper = min(byteRange.upperBound, chunkStart + Int64(clear.count)) - chunkStart
            result.append(clear[Int(lower)..<Int(upper)])
        }
        return result
    }

    func plaintext(for record: MediaRecord) throws -> Data {
        var plaintext = Data()
        plaintext.reserveCapacity(Int(record.byteCount))
        for (ordinal, address) in record.chunks.enumerated() {
            let physical = try readEncryptedChunk(at: address)
            guard physical.count == slotSize else { throw VaultError.integrityFailure }
            let nonce = try AES.GCM.Nonce(data: physical.prefix(12))
            let ciphertext = physical.dropFirst(12).dropLast(16)
            let tag = physical.suffix(16)
            let chunkKey = HKDF<SHA256>.deriveKey(
                inputKeyMaterial: SymmetricKey(data: record.mediaKey),
                salt: Data("Vaulthalla-media-salt-v1".utf8),
                info: Data("item:\(record.id.uuidString)|chunk:\(ordinal)|format:1".utf8),
                outputByteCount: 32
            )
            let aad = Data("Vaulthalla-chunk-v1|\(address.segment)|\(address.slot)".utf8)
            let box = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: tag)
            plaintext.append(try AES.GCM.open(box, using: chunkKey, authenticating: aad))
        }
        guard plaintext.count >= record.byteCount else { throw VaultError.integrityFailure }
        plaintext.removeSubrange(Int(record.byteCount)..<plaintext.count)
        guard Data(SHA256.hash(data: plaintext)) == record.sha256 else { throw VaultError.integrityFailure }
        return plaintext
    }

    func verifyAll() async throws -> (checked: Int, corrupt: [UUID]) {
        var corrupt: [UUID] = []
        for record in index.records.values {
            try Task.checkCancellation()
            do { _ = try plaintext(for: record) } catch { corrupt.append(record.id) }
        }
        index.integrityState = corrupt.isEmpty ? "Verified" : "Corruption detected"
        index.lastVerifiedAt = Date()
        return (index.records.count, corrupt)
    }

    /// Copy-on-write compaction: old slots remain untouched until the replacement
    /// index is committed. A failed copy leaves unreferenced new segments only.
    func compact(using rootKey: SymmetricKey, segmentCapacity: Int = VaultConstants.defaultSegmentCapacity) async throws -> Int {
        let oldIndex = index
        let oldSegments = try fileManager.contentsOfDirectory(at: rootDirectory, includingPropertiesForKeys: nil)
            .filter { $0.lastPathComponent.hasPrefix(segmentURLPrefix) && $0.pathExtension == "dat" }
        let highest = oldSegments.compactMap { Int($0.deletingPathExtension().lastPathComponent.dropFirst(segmentURLPrefix.count)) }.max() ?? -1
        let slotsPerSegment = max(1, segmentCapacity / slotSize)
        let startSegment = max(highest, oldIndex.nextSlotBySegment.keys.max() ?? -1) + 1
        var replacement = oldIndex
        replacement.freeChunks = []
        replacement.nextSlotBySegment = [:]
        var moved = 0
        do {
            for id in oldIndex.records.keys.sorted(by: { $0.uuidString < $1.uuidString }) {
                guard var record = oldIndex.records[id] else { throw VaultError.integrityFailure }
                for ordinal in record.chunks.indices {
                    try Task.checkCancellation()
                    let source = record.chunks[ordinal]
                    let destination = ChunkAddress(segment: startSegment + moved / slotsPerSegment, slot: moved % slotsPerSegment)
                    let physical = try readEncryptedChunk(at: source)
                    let nonce = try AES.GCM.Nonce(data: physical.prefix(12))
                    let chunkKey = HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: record.mediaKey), salt: Data("Vaulthalla-media-salt-v1".utf8), info: Data("item:\(id.uuidString)|chunk:\(ordinal)|format:1".utf8), outputByteCount: 32)
                    let box = try AES.GCM.SealedBox(nonce: nonce, ciphertext: physical.dropFirst(12).dropLast(16), tag: physical.suffix(16))
                    let clear = try AES.GCM.open(box, using: chunkKey, authenticating: Data("Vaulthalla-chunk-v1|\(source.segment)|\(source.slot)".utf8))
                    let sealed = try AES.GCM.seal(clear, using: chunkKey, nonce: nonce, authenticating: Data("Vaulthalla-chunk-v1|\(destination.segment)|\(destination.slot)".utf8))
                    try compactionFault?(.write)
                    try appendEncryptedChunk(nonce.withUnsafeBytes { Data($0) } + sealed.ciphertext + sealed.tag, address: destination)
                    record.chunks[ordinal] = destination
                    replacement.nextSlotBySegment[destination.segment] = destination.slot + 1
                    moved += 1
                }
                replacement.records[id] = record
            }
            for segment in replacement.nextSlotBySegment.keys {
                try compactionFault?(.sync)
                let handle = try FileHandle(forWritingTo: segmentURL(for: segment))
                try handle.synchronize()
                try handle.close()
            }
            index = replacement
            try validateIndex()
            try compactionFault?(.replace)
            try save(using: rootKey)
        } catch {
            // The index rename may have succeeded before a later error.
            // Reconcile actor state with the durable index before returning.
            if (try? load(using: rootKey)) == nil { index = oldIndex }
            throw error
        }
        // Cleanup is best effort after commit: old slots remain harmless orphans
        // if interrupted, and the next compaction can remove them.
        for url in oldSegments {
            do {
                try compactionFault?(.cleanup)
                try fileManager.removeItem(at: url)
            } catch { /* A committed index must remain usable after cleanup fails. */ }
        }
        return moved + oldSegments.count
    }

    func delete(_ id: UUID, rootKey: SymmetricKey) throws {
        guard let record = index.records.removeValue(forKey: id) else { return }
        record.chunks.forEach { index.freeChunks.insert($0) }
        try save(using: rootKey)
    }

    func snapshot() -> VaultIndex { index }

    // §6 — previews are never persisted in plaintext: each thumbnail is sealed with a
    // per-item key derived from the media key and stored inside the encrypted index.
    func attachThumbnail(_ jpeg: Data, for record: MediaRecord) throws {
        guard var stored = index.records[record.id] else { return }
        let sealed = try AES.GCM.seal(jpeg, using: Self.thumbnailKey(for: record), authenticating: Data("Vaulthalla-thumbnail-v1".utf8))
        stored.encryptedThumbnail = sealed.nonce.withUnsafeBytes { Data($0) } + sealed.ciphertext + sealed.tag
        index.records[record.id] = stored
    }

    func thumbnailData(for record: MediaRecord) throws -> Data? {
        guard let blob = record.encryptedThumbnail, blob.count > 28 else { return nil }
        let nonce = try AES.GCM.Nonce(data: blob.prefix(12))
        let box = try AES.GCM.SealedBox(
            nonce: nonce,
            ciphertext: blob.dropFirst(12).dropLast(16),
            tag: blob.suffix(16)
        )
        return try AES.GCM.open(box, using: Self.thumbnailKey(for: record), authenticating: Data("Vaulthalla-thumbnail-v1".utf8))
    }

    private static func thumbnailKey(for record: MediaRecord) -> SymmetricKey {
        HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: record.mediaKey),
            salt: Data("Vaulthalla-media-salt-v1".utf8),
            info: Data("item:\(record.id.uuidString)|thumbnail:1".utf8),
            outputByteCount: 32
        )
    }

    func replaceAuditPrivateKey(_ privateKey: Data, using rootKey: SymmetricKey) throws {
        index.auditPrivateKey = privateKey
        try save(using: rootKey)
    }

    func markAuditPrivacyMigrated(using rootKey: SymmetricKey) throws {
        index.auditPrivacyVersion = 1
        try save(using: rootKey)
    }

    func validateIndex() throws {
        for record in index.records.values {
            guard !record.chunks.isEmpty || record.byteCount == 0 else { throw VaultError.integrityFailure }
            for address in record.chunks {
                guard address.segment >= 0, address.slot >= 0 else { throw VaultError.integrityFailure }
            }
        }
    }

    func physicalSize() -> Int64 {
        let urls = (try? fileManager.contentsOfDirectory(at: rootDirectory, includingPropertiesForKeys: [.fileSizeKey])) ?? []
        return urls.reduce(0) { $0 + Int64((try? $1.resourceValues(forKeys: [.fileSizeKey]).fileSize) ?? 0) }
    }

    func segmentCount() -> Int {
        let urls = (try? fileManager.contentsOfDirectory(at: rootDirectory, includingPropertiesForKeys: nil)) ?? []
        return urls.filter { $0.lastPathComponent.hasPrefix(segmentURLPrefix) && $0.pathExtension == "dat" }.count
    }

    func protectAndExclude(_ url: URL) throws {
        try fileManager.setAttributes([.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication], ofItemAtPath: url.path)
        try excludeFromBackup(url)
    }

    func excludeFromBackup(_ url: URL) throws {
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        var mutableURL = url
        try mutableURL.setResourceValues(values)
    }
}
