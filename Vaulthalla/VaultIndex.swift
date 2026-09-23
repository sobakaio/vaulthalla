import Foundation

struct ChunkAddress: Codable, Hashable {
    let segment: Int
    let slot: Int
}

struct MediaRecord: Codable, Identifiable, Hashable {
    let id: UUID
    let filename: String
    let byteCount: Int64
    let mimeType: String
    let importedAt: Date
    let sha256: Data
    let mediaKey: Data
    var chunks: [ChunkAddress]
    var encryptedThumbnail: Data?
    var isCorrupt: Bool = false
}

struct VaultIndex: Codable {
    var records: [UUID: MediaRecord] = [:]
    var auditPrivateKey: Data?
    /// Nil in legacy indexes that may have stored failed unlock input.
    var auditPrivacyVersion: Int? = nil
    var freeChunks: Set<ChunkAddress> = []
    var nextSlotBySegment: [Int: Int] = [:]
    var lastVerifiedAt: Date?
    var integrityState: String = "Not verified"

    var imageCount: Int {
        records.values.filter { $0.mimeType.hasPrefix("image/") }.count
    }

    var videoCount: Int {
        records.values.filter { $0.mimeType.hasPrefix("video/") }.count
    }
}
