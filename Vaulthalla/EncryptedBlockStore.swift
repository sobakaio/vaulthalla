import Foundation
import CryptoKit

actor EncryptedBlockStore {
    let rootDirectory: URL
    private let fileManager: FileManager
    private(set) var index = VaultIndex()

    private var indexURL: URL { rootDirectory.appendingPathComponent("index.v1") }
    private var segmentURLPrefix: String { "segment-" }
    private var slotSize: Int { VaultConstants.chunkPayloadSize + 12 + 16 }

    init(rootDirectory: URL, fileManager: FileManager = .default) {
        self.rootDirectory = rootDirectory
        self.fileManager = fileManager
    }

    func initialize(using rootKey: SymmetricKey, auditPrivateKey: Data) throws {
        index = VaultIndex()
        index.auditPrivateKey = auditPrivateKey
        try fileManager.createDirectory(at: rootDirectory, withIntermediateDirectories: true)
        try save(using: rootKey)
    }

    func load(using rootKey: SymmetricKey) throws {
        try fileManager.createDirectory(at: rootDirectory, withIntermediateDirectories: true)
        guard let data = fileManager.contents(atPath: indexURL.path) else {
            index = VaultIndex()
            return
        }
        guard data.count >= 28 else { throw VaultError.integrityFailure }
        let nonce = try AES.GCM.Nonce(data: data.prefix(12))
        let box = try AES.GCM.SealedBox(nonce: nonce, ciphertext: data.dropFirst(12).dropLast(16), tag: data.suffix(16))
        let plaintext = try AES.GCM.open(box, using: rootKey, authenticating: Data("Vaulthalla-index-v1".utf8))
        index = try JSONDecoder().decode(VaultIndex.self, from: plaintext)
        try validateIndex()
    }

    func save(using rootKey: SymmetricKey) throws {
        let plaintext = try JSONEncoder().encode(index)
        let sealed = try AES.GCM.seal(plaintext, using: rootKey, authenticating: Data("Vaulthalla-index-v1".utf8))
        let data = sealed.nonce.withUnsafeBytes { Data($0) } + sealed.ciphertext + sealed.tag
        let temporary = indexURL.appendingPathExtension("tmp")
        try data.write(to: temporary, options: .atomic)
        try excludeFromBackup(temporary)
        if fileManager.fileExists(atPath: indexURL.path) {
            _ = try fileManager.replaceItemAt(indexURL, withItemAt: temporary)
        } else {
            try fileManager.moveItem(at: temporary, to: indexURL)
        }
    }

    func appendEncryptedChunk(_ encryptedChunk: Data, address: ChunkAddress) throws {
        guard encryptedChunk.count == slotSize else { throw VaultError.storageFailure }
        let url = segmentURL(for: address.segment)
        try fileManager.createDirectory(at: rootDirectory, withIntermediateDirectories: true)
        if !fileManager.fileExists(atPath: url.path) {
            fileManager.createFile(atPath: url.path, contents: nil)
            try excludeFromBackup(url)
        }
        let handle = try FileHandle(forUpdating: url)
        defer { try? handle.close() }
        try handle.seek(toOffset: UInt64(address.slot * slotSize))
        try handle.write(contentsOf: encryptedChunk)
    }

    func readEncryptedChunk(at address: ChunkAddress) throws -> Data {
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
        let itemID = UUID()
        let mediaKey = VaultCrypto.randomData(count: 32)
        var addresses: [ChunkAddress] = []
        var digest = SHA256()
        var totalBytes: Int64 = 0
        var ordinal = 0
        var pending = Data()

        do {
            for try await sourceChunk in stream {
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
            try? validateIndex()
            try? save(using: rootKey)
            throw error
        }

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
    func writePlaintext(for record: MediaRecord, to url: URL) throws {
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

    func compact(using rootKey: SymmetricKey, segmentCapacity: Int = VaultConstants.defaultSegmentCapacity) async throws -> Int {
        let slotsPerSegment = max(1, segmentCapacity / slotSize)
        var locations: [RelocationRef: ChunkAddress] = [:]
        var referencesByAddress: [ChunkAddress: RelocationRef] = [:]
        var references: [RelocationRef] = []

        for record in index.records.values.sorted(by: { $0.id.uuidString < $1.id.uuidString }) {
            for (ordinal, address) in record.chunks.enumerated() {
                let reference = RelocationRef(recordID: record.id, ordinal: ordinal)
                references.append(reference)
                locations[reference] = address
                referencesByAddress[address] = reference
            }
        }

        references.sort {
            let lhs = locations[$0]!
            let rhs = locations[$1]!
            return lhs.segment == rhs.segment ? lhs.slot < rhs.slot : lhs.segment < rhs.segment
        }

        let segmentURLs = try fileManager.contentsOfDirectory(at: rootDirectory, includingPropertiesForKeys: [.fileSizeKey])
            .filter { $0.lastPathComponent.hasPrefix(segmentURLPrefix) && $0.pathExtension == "dat" }

        var freeAddresses = index.freeChunks
        for url in segmentURLs {
            guard let segment = Int(url.deletingPathExtension().lastPathComponent.replacingOccurrences(of: segmentURLPrefix, with: "")),
                  let fileSize = try? url.resourceValues(forKeys: [.fileSizeKey]).fileSize else { continue }
            let slotCount = fileSize / slotSize
            for slot in 0..<slotCount {
                let address = ChunkAddress(segment: segment, slot: slot)
                if referencesByAddress[address] == nil {
                    freeAddresses.insert(address)
                }
            }
        }

        var moved = 0
        for (targetIndex, reference) in references.enumerated() {
            try Task.checkCancellation()
            let target = ChunkAddress(segment: targetIndex / slotsPerSegment, slot: targetIndex % slotsPerSegment)

            while locations[reference] != target {
                guard let source = locations[reference] else { throw VaultError.integrityFailure }

                if let occupant = referencesByAddress[target], occupant != reference {
                    guard let scratch = freeAddresses.first(where: { $0 != target }) else {
                        throw VaultError.storageFailure
                    }
                    try relocateChunk(occupant, from: target, to: scratch)
                    locations[occupant] = scratch
                    referencesByAddress.removeValue(forKey: target)
                    referencesByAddress[scratch] = occupant
                    freeAddresses.remove(scratch)
                    freeAddresses.insert(target)
                    moved += 1
                }

                try relocateChunk(reference, from: source, to: target)
                locations[reference] = target
                referencesByAddress.removeValue(forKey: source)
                referencesByAddress[target] = reference
                freeAddresses.remove(target)
                freeAddresses.insert(source)
                moved += 1
            }
        }

        index.freeChunks = freeAddresses
        let usedSegments = Set(referencesByAddress.keys.map(\.segment))
        var removed = 0
        for url in segmentURLs {
            guard let segment = Int(url.deletingPathExtension().lastPathComponent.replacingOccurrences(of: segmentURLPrefix, with: "")),
                  !usedSegments.contains(segment) else { continue }
            try fileManager.removeItem(at: url)
            index.nextSlotBySegment.removeValue(forKey: segment)
            index.freeChunks = index.freeChunks.filter { $0.segment != segment }
            removed += 1
        }

        var nextSlots: [Int: Int] = [:]
        for address in referencesByAddress.keys {
            nextSlots[address.segment] = max(nextSlots[address.segment] ?? 0, address.slot + 1)
        }
        index.nextSlotBySegment = nextSlots
        try validateIndex()
        try save(using: rootKey)
        return moved + removed
    }

    private struct RelocationRef: Hashable {
        let recordID: UUID
        let ordinal: Int
    }

    private func relocateChunk(_ reference: RelocationRef, from source: ChunkAddress, to destination: ChunkAddress) throws {
        guard source != destination,
              let record = index.records[reference.recordID],
              reference.ordinal < record.chunks.count else { return }

        let physical = try readEncryptedChunk(at: source)
        let nonce = try AES.GCM.Nonce(data: physical.prefix(12))
        let chunkKey = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: record.mediaKey),
            salt: Data("Vaulthalla-media-salt-v1".utf8),
            info: Data("item:\(record.id.uuidString)|chunk:\(reference.ordinal)|format:1".utf8),
            outputByteCount: 32
        )
        let recordedAddress = record.chunks[reference.ordinal]
        guard recordedAddress == source else { throw VaultError.integrityFailure }
        let oldAAD = Data("Vaulthalla-chunk-v1|\(recordedAddress.segment)|\(recordedAddress.slot)".utf8)
        let box = try AES.GCM.SealedBox(
            nonce: nonce,
            ciphertext: physical.dropFirst(12).dropLast(16),
            tag: physical.suffix(16)
        )
        let clear = try AES.GCM.open(box, using: chunkKey, authenticating: oldAAD)
        let newAAD = Data("Vaulthalla-chunk-v1|\(destination.segment)|\(destination.slot)".utf8)
        let sealed = try AES.GCM.seal(clear, using: chunkKey, nonce: nonce, authenticating: newAAD)
        let rewritten = nonce.withUnsafeBytes { Data($0) } + sealed.ciphertext + sealed.tag
        try appendEncryptedChunk(rewritten, address: destination)

        var updated = record
        updated.chunks[reference.ordinal] = destination
        index.records[reference.recordID] = updated
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

    func excludeFromBackup(_ url: URL) throws {
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        var mutableURL = url
        try mutableURL.setResourceValues(values)
    }
}
