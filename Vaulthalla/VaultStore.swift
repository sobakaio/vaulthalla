import Foundation
import CryptoKit

actor VaultStore {
    static let shared = VaultStore()
    private let fileManager: FileManager
    private let rootDirectory: URL
    private let headerURL: URL
    private let blockStore: EncryptedBlockStore
    private let auditRotationURL: URL

    private struct AuditRotation: Codable {
        let privateKey: Data
        let publicKey: Data
    }

    init(fileManager: FileManager = .default) {
        self.fileManager = fileManager
        let appSupport = fileManager.urls(for: .applicationSupportDirectory, in: .userDomainMask).first ?? fileManager.temporaryDirectory
        self.rootDirectory = appSupport.appendingPathComponent("Vaulthalla", isDirectory: true)
        self.headerURL = rootDirectory.appendingPathComponent("vault.header")
        self.auditRotationURL = rootDirectory.appendingPathComponent("audit.rotation")
        self.blockStore = EncryptedBlockStore(rootDirectory: rootDirectory)
        try? fileManager.createDirectory(at: rootDirectory, withIntermediateDirectories: true)
        let importDirectory = fileManager.urls(for: .documentDirectory, in: .userDomainMask).first?.appendingPathComponent("Import", isDirectory: true)
        if let importDirectory {
            try? fileManager.createDirectory(at: importDirectory, withIntermediateDirectories: true)
            var values = URLResourceValues()
            values.isExcludedFromBackup = true
            var mutableImportDirectory = importDirectory
            try? mutableImportDirectory.setResourceValues(values)
        }
    }

    func hasVault() -> Bool {
        fileManager.fileExists(atPath: headerURL.path)
    }

    func createVault(password: String, segmentCapacity: SegmentCapacity) async throws {
        guard password.count >= VaultConstants.minimumPasswordLength && password.count <= VaultConstants.maximumPasswordLength else {
            throw VaultError.invalidPassword
        }
        guard !hasVault() else { throw VaultError.vaultAlreadyExists }

        try fileManager.createDirectory(at: rootDirectory, withIntermediateDirectories: true)
        var rootValues = URLResourceValues()
        rootValues.isExcludedFromBackup = true
        var mutableRootDirectory = rootDirectory
        try? mutableRootDirectory.setResourceValues(rootValues)
        let salt = VaultCrypto.randomData(count: 32)
        let deviceSecret = VaultCrypto.randomData(count: 32)
        let rootKey = SymmetricKey(size: .bits256)
        let auditPrivate = Curve25519.KeyAgreement.PrivateKey()
        let iterations = try PasswordKDF.calibratedIterations()
        let passwordKey = try PasswordKDF.deriveKey(password: password, salt: salt, iterations: iterations)
        let kek = VaultCrypto.makeKEK(passwordKey: passwordKey, deviceSecret: deviceSecret)
        let aad = VaultCrypto.headerAAD(segmentCapacity: segmentCapacity.bytes, salt: salt, iterations: iterations)
        let wrappedRootKey = try VaultCrypto.wrap(rootKey, with: kek, aad: aad)
        let header = VaultHeader(segmentCapacity: segmentCapacity.bytes, salt: salt, iterations: iterations, wrappedRootKey: wrappedRootKey, auditPublicKey: auditPrivate.publicKey.rawRepresentation)
        let encoded = try JSONEncoder().encode(header)
        let temporaryURL = rootDirectory.appendingPathComponent("vault.header.tmp")
        try encoded.write(to: temporaryURL, options: .atomic)
        try KeychainStore.saveDeviceSecret(deviceSecret)
        try fileManager.setAttributes([.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication], ofItemAtPath: temporaryURL.path)
        if fileManager.fileExists(atPath: headerURL.path) {
            _ = try fileManager.replaceItemAt(headerURL, withItemAt: temporaryURL)
        } else {
            try fileManager.moveItem(at: temporaryURL, to: headerURL)
        }
        try await blockStore.initialize(using: rootKey, auditPrivateKey: auditPrivate.rawRepresentation)
    }

    func unlock(password: String) throws -> SymmetricKey {
        guard hasVault() else { throw VaultError.noVault }
        let header = try loadHeader()
        let deviceSecret = try KeychainStore.loadDeviceSecret()
        let passwordKey = try PasswordKDF.deriveKey(password: password, salt: header.salt, iterations: header.iterations)
        let kek = VaultCrypto.makeKEK(passwordKey: passwordKey, deviceSecret: deviceSecret)
        do {
            return try VaultCrypto.unwrap(header.wrappedRootKey, with: kek, aad: VaultCrypto.headerAAD(segmentCapacity: header.segmentCapacity, salt: header.salt, iterations: header.iterations))
        } catch {
            throw VaultError.invalidPasswordOrDevice
        }
    }

    func changePassword(_ password: String, using rootKey: SymmetricKey) throws {
        guard password.count >= VaultConstants.minimumPasswordLength,
              password.count <= VaultConstants.maximumPasswordLength else {
            throw VaultError.invalidPassword
        }
        let header = try loadHeader()
        let deviceSecret = try KeychainStore.loadDeviceSecret()
        let salt = VaultCrypto.randomData(count: 32)
        let iterations = try PasswordKDF.calibratedIterations()
        let passwordKey = try PasswordKDF.deriveKey(password: password, salt: salt, iterations: iterations)
        let kek = VaultCrypto.makeKEK(passwordKey: passwordKey, deviceSecret: deviceSecret)
        let aad = VaultCrypto.headerAAD(segmentCapacity: header.segmentCapacity, salt: salt, iterations: iterations)
        let wrappedRootKey = try VaultCrypto.wrap(rootKey, with: kek, aad: aad)
        let updatedHeader = VaultHeader(
            segmentCapacity: header.segmentCapacity,
            salt: salt,
            iterations: iterations,
            wrappedRootKey: wrappedRootKey,
            auditPublicKey: header.auditPublicKey
        )
        let temporaryURL = headerURL.appendingPathExtension("tmp")
        let encoded = try JSONEncoder().encode(updatedHeader)
        try encoded.write(to: temporaryURL, options: .atomic)
        try fileManager.setAttributes([.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication], ofItemAtPath: temporaryURL.path)
        if fileManager.fileExists(atPath: headerURL.path) {
            _ = try fileManager.replaceItemAt(headerURL, withItemAt: temporaryURL)
        } else {
            try fileManager.moveItem(at: temporaryURL, to: headerURL)
        }
    }

    struct StorageStatistics: Equatable {
        let physicalBytes: Int64
        let usedBytes: Int64
        let reusableChunks: Int
        let segmentCount: Int
        let segmentCapacity: Int64
    }

    func storageStatistics(using rootKey: SymmetricKey) async throws -> StorageStatistics {
        let header = try loadHeader()
        try await blockStore.load(using: rootKey)
        let index = await blockStore.snapshot()
        let segmentCount = await blockStore.segmentCount()
        return StorageStatistics(
            physicalBytes: await blockStore.physicalSize(),
            usedBytes: index.records.values.reduce(0) { $0 + $1.byteCount },
            reusableChunks: index.freeChunks.count,
            segmentCount: segmentCount,
            segmentCapacity: Int64(header.segmentCapacity)
        )
    }

    func destroyVault() {
        // Key destruction is deliberately first; filesystem cleanup cannot restore access.
        KeychainStore.deleteDeviceSecret()
        try? fileManager.removeItem(at: rootDirectory)
    }

    func importFile(at url: URL, rootKey: SymmetricKey) async throws -> MediaRecord? {
        let header = try loadHeader()
        let didStart = url.startAccessingSecurityScopedResource()
        defer { if didStart { url.stopAccessingSecurityScopedResource() } }
        let type = url.pathExtension.lowercased()
        let mime = type == "jpg" || type == "jpeg" ? "image/jpeg" : type == "png" ? "image/png" : type == "gif" ? "image/gif" : type == "mp4" ? "video/mp4" : type == "mov" ? "video/quicktime" : type == "m4v" ? "video/x-m4v" : "application/octet-stream"
        try await blockStore.load(using: rootKey)
        return try await blockStore.importFile(at: url, filename: url.lastPathComponent, mimeType: mime, rootKey: rootKey, segmentCapacity: header.segmentCapacity)
    }

    func importStream(
        _ stream: AsyncThrowingStream<Data, Error>,
        filename: String,
        mimeType: String,
        rootKey: SymmetricKey
    ) async throws -> MediaRecord? {
        let header = try loadHeader()
        try await blockStore.load(using: rootKey)
        return try await blockStore.importStream(
            stream,
            filename: filename,
            mimeType: mimeType,
            rootKey: rootKey,
            segmentCapacity: header.segmentCapacity
        )
    }

    func loadIndex(using rootKey: SymmetricKey) async throws {
        try await blockStore.load(using: rootKey)
    }

    func indexSnapshot() async -> VaultIndex {
        await blockStore.snapshot()
    }

    func appendAudit(_ event: AuditEvent) async {
        guard !fileManager.fileExists(atPath: auditRotationURL.path) else { return }
        guard let header = try? loadHeader(),
              let audit = try? AuditLogStore(rootDirectory: rootDirectory, publicKeyData: header.auditPublicKey) else { return }
        let maximumEntries = UserDefaults.standard.integer(forKey: "auditHistoryLimit")
        try? audit.append(event, maximumEntries: maximumEntries > 0 ? maximumEntries : nil)
    }

    func setAuditHistoryLimit(_ limit: Int) throws {
        guard limit == 0 || [50, 100, 500].contains(limit) else { throw VaultError.storageFailure }
        guard !fileManager.fileExists(atPath: auditRotationURL.path) else { throw VaultError.storageFailure }
        let header = try loadHeader()
        let audit = try AuditLogStore(rootDirectory: rootDirectory, publicKeyData: header.auditPublicKey)
        try audit.trim(maximumEntries: limit > 0 ? limit : nil)
    }

    func readAudit(using rootKey: SymmetricKey) async throws -> [AuditEvent] {
        try await completeAuditRotation(using: rootKey)
        try await blockStore.load(using: rootKey)
        let index = await blockStore.snapshot()
        guard let privateKey = index.auditPrivateKey else { throw VaultError.integrityFailure }
        let header = try loadHeader()
        let audit = try AuditLogStore(rootDirectory: rootDirectory, publicKeyData: header.auditPublicKey)
        return try audit.decrypt(using: privateKey)
    }

    func eraseAudit(using rootKey: SymmetricKey) async throws {
        try await completeAuditRotation(using: rootKey)
        try await blockStore.load(using: rootKey)
        let header = try loadHeader()
        let audit = try AuditLogStore(rootDirectory: rootDirectory, publicKeyData: header.auditPublicKey)

        let newPrivateKey = Curve25519.KeyAgreement.PrivateKey()
        let rotation = AuditRotation(
            privateKey: newPrivateKey.rawRepresentation,
            publicKey: newPrivateKey.publicKey.rawRepresentation
        )
        let plaintext = try JSONEncoder().encode(rotation)
        let sealed = try AES.GCM.seal(plaintext, using: rootKey, authenticating: Data("Vaulthalla-audit-rotation-v1".utf8))
        let journal = sealed.nonce.withUnsafeBytes { Data($0) } + sealed.ciphertext + sealed.tag
        try journal.write(to: auditRotationURL, options: .atomic)
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        var mutableURL = auditRotationURL
        try? mutableURL.setResourceValues(values)

        // The journal is durable before the old log is removed. If the process is
        // interrupted from this point onward, recovery can safely finish rotation.
        try audit.erase()
        try writeHeader(withAuditPublicKey: rotation.publicKey, basedOn: header)
        try await blockStore.replaceAuditPrivateKey(rotation.privateKey, using: rootKey)
        try? fileManager.removeItem(at: auditRotationURL)
    }

    private func completeAuditRotation(using rootKey: SymmetricKey) async throws {
        guard let journalData = fileManager.contents(atPath: auditRotationURL.path) else { return }
        guard journalData.count >= 28 else { throw VaultError.integrityFailure }
        let nonce = try AES.GCM.Nonce(data: journalData.prefix(12))
        let box = try AES.GCM.SealedBox(
            nonce: nonce,
            ciphertext: journalData.dropFirst(12).dropLast(16),
            tag: journalData.suffix(16)
        )
        let rotation = try JSONDecoder().decode(
            AuditRotation.self,
            from: try AES.GCM.open(box, using: rootKey, authenticating: Data("Vaulthalla-audit-rotation-v1".utf8))
        )
        let header = try loadHeader()
        try await blockStore.load(using: rootKey)
        let oldAudit = try AuditLogStore(rootDirectory: rootDirectory, publicKeyData: header.auditPublicKey)
        try oldAudit.erase()
        if header.auditPublicKey != rotation.publicKey {
            try writeHeader(withAuditPublicKey: rotation.publicKey, basedOn: header)
        }
        try await blockStore.replaceAuditPrivateKey(rotation.privateKey, using: rootKey)
        try? fileManager.removeItem(at: auditRotationURL)
    }

    private func writeHeader(withAuditPublicKey publicKey: Data, basedOn header: VaultHeader) throws {
        let updated = VaultHeader(
            segmentCapacity: header.segmentCapacity,
            salt: header.salt,
            iterations: header.iterations,
            wrappedRootKey: header.wrappedRootKey,
            auditPublicKey: publicKey
        )
        let temporaryURL = headerURL.appendingPathExtension("tmp")
        try JSONEncoder().encode(updated).write(to: temporaryURL, options: .atomic)
        try fileManager.setAttributes([.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication], ofItemAtPath: temporaryURL.path)
        _ = try fileManager.replaceItemAt(headerURL, withItemAt: temporaryURL)
    }

    /// Creates a short-lived, protected file for AVFoundation poster extraction.
    /// The block store authenticates each chunk and the complete media digest.
    func writeMediaToProtectedTemporaryFile(
        _ record: MediaRecord,
        using rootKey: SymmetricKey,
        prefix: String = "vaultthumb-"
    ) async throws -> URL {
        try await blockStore.load(using: rootKey)
        let fileExtension = (record.filename as NSString).pathExtension
        let suffix = fileExtension.isEmpty ? "" : ".\(fileExtension)"
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("\(prefix)\(UUID().uuidString)\(suffix)")
        try await blockStore.writePlaintext(for: record, to: url)
        return url
    }

    func readMedia(_ record: MediaRecord, using rootKey: SymmetricKey) async throws -> Data {
        try await blockStore.load(using: rootKey)
        return try await blockStore.plaintext(for: record)
    }

    func attachThumbnail(_ jpeg: Data, to record: MediaRecord, using rootKey: SymmetricKey) async throws {
        try await blockStore.load(using: rootKey)
        try await blockStore.attachThumbnail(jpeg, for: record)
        try await blockStore.save(using: rootKey)
    }

    func thumbnail(for record: MediaRecord, using rootKey: SymmetricKey) async throws -> Data? {
        try await blockStore.load(using: rootKey)
        return try await blockStore.thumbnailData(for: record)
    }

    func readMedia(_ record: MediaRecord, range: Range<Int64>, using rootKey: SymmetricKey) async throws -> Data {
        try await blockStore.load(using: rootKey)
        return try await blockStore.plaintext(for: record, byteRange: range)
    }

    func deleteMedia(_ id: UUID, using rootKey: SymmetricKey) async throws {
        try await blockStore.load(using: rootKey)
        try await blockStore.delete(id, rootKey: rootKey)
    }

    func compact(using rootKey: SymmetricKey) async throws -> Int {
        let header = try loadHeader()
        try await blockStore.load(using: rootKey)
        return try await blockStore.compact(using: rootKey, segmentCapacity: header.segmentCapacity)
    }

    func verify(using rootKey: SymmetricKey) async throws -> (checked: Int, corrupt: [UUID]) {
        try await blockStore.load(using: rootKey)
        let result = try await blockStore.verifyAll()
        try await blockStore.save(using: rootKey)
        return result
    }

    func loadHeader() throws -> VaultHeader {
        guard let data = fileManager.contents(atPath: headerURL.path) else { throw VaultError.noVault }
        let header = try JSONDecoder().decode(VaultHeader.self, from: data)
        try header.validate()
        return header
    }
}
