import Foundation
import CryptoKit
import Security

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

    func hasPendingCreation() -> Bool {
        fileManager.fileExists(atPath: creationURL.path)
    }

    func hasCommittedIndex() -> Bool {
        fileManager.fileExists(atPath: rootDirectory.appendingPathComponent("index.v1").path)
    }

    private struct CreationJournal: Codable {
        let header: VaultHeader
        let sealedSecrets: Data
    }

    private var creationURL: URL { rootDirectory.appendingPathComponent("vault.creation") }
    private var indexURL: URL { rootDirectory.appendingPathComponent("index.v1") }

    func createVault(password: String, segmentCapacity: SegmentCapacity, stopAfterStaging: Bool = false) async throws {
        guard password.count >= VaultConstants.minimumPasswordLength && password.count <= VaultConstants.maximumPasswordLength else {
            throw VaultError.invalidPassword
        }
        // Onboarding calls this same entry point after restart. A staged vault
        // resumes with its original capacity; it never starts a second creation.
        if !hasVault(), fileManager.fileExists(atPath: creationURL.path) {
            try await resumeCreation(password: password)
            return
        }
        guard !hasVault(),
              !fileManager.fileExists(atPath: indexURL.path),
              !fileManager.fileExists(atPath: rootDirectory.appendingPathComponent("index.v1.tmp").path) else {
            throw VaultError.vaultAlreadyExists
        }
        // Never replace a pre-existing device binding, even if the header was lost.
        do {
            _ = try KeychainStore.loadDeviceSecret()
            throw VaultError.vaultAlreadyExists
        } catch VaultError.keychainFailure(let status) where status == errSecItemNotFound {
            // Fresh installation.
        }

        try fileManager.createDirectory(at: rootDirectory, withIntermediateDirectories: true)
        var rootValues = URLResourceValues()
        rootValues.isExcludedFromBackup = true
        var mutableRootDirectory = rootDirectory
        try mutableRootDirectory.setResourceValues(rootValues)
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
        // The device secret never appears in a file, even encrypted under the password.
        // If power fails before the journal is durable, creation fails closed with an
        // orphan Keychain binding rather than replacing it on the next attempt.
        try KeychainStore.saveDeviceSecret(deviceSecret)
        let sealed = try AES.GCM.seal(auditPrivate.rawRepresentation, using: rootKey, authenticating: Data("Vaulthalla-creation-v1".utf8))
        let journal = CreationJournal(header: header, sealedSecrets: sealed.nonce.withUnsafeBytes { Data($0) } + sealed.ciphertext + sealed.tag)
        try writeProtectedNewFile(try JSONEncoder().encode(journal), at: creationURL)
        if stopAfterStaging { return }
        try await resumeCreation(password: password)
    }

    /// Resume only with the password that authenticated the staged creation.
    /// No existing index or Keychain binding is replaced without verification.
    func resumeCreation(password: String) async throws {
        guard !hasVault(), let data = fileManager.contents(atPath: creationURL.path) else {
            throw VaultError.noVault
        }
        let journal = try JSONDecoder().decode(CreationJournal.self, from: data)
        try journal.header.validate()
        let passwordKey = try PasswordKDF.deriveKey(password: password, salt: journal.header.salt, iterations: journal.header.iterations)
        guard journal.sealedSecrets.count >= 28 else { throw VaultError.integrityFailure }
        let box = try AES.GCM.SealedBox(
            nonce: AES.GCM.Nonce(data: journal.sealedSecrets.prefix(12)),
            ciphertext: journal.sealedSecrets.dropFirst(12).dropLast(16),
            tag: journal.sealedSecrets.suffix(16)
        )
        let deviceSecret = try KeychainStore.loadDeviceSecret()
        let kek = VaultCrypto.makeKEK(passwordKey: passwordKey, deviceSecret: deviceSecret)
        let rootKey: SymmetricKey
        do {
            rootKey = try VaultCrypto.unwrap(journal.header.wrappedRootKey, with: kek,
                aad: VaultCrypto.headerAAD(segmentCapacity: journal.header.segmentCapacity, salt: journal.header.salt, iterations: journal.header.iterations))
        } catch { throw VaultError.invalidPasswordOrDevice }
        let auditPrivateKey: Data
        do {
            auditPrivateKey = try AES.GCM.open(box, using: rootKey, authenticating: Data("Vaulthalla-creation-v1".utf8))
        } catch { throw VaultError.integrityFailure }
        guard let auditKey = try? Curve25519.KeyAgreement.PrivateKey(rawRepresentation: auditPrivateKey),
              auditKey.publicKey.rawRepresentation == journal.header.auditPublicKey else {
            throw VaultError.integrityFailure
        }
        if fileManager.fileExists(atPath: indexURL.path) {
            try await blockStore.load(using: rootKey)
            let index = await blockStore.snapshot()
            guard index.auditPrivateKey == auditPrivateKey,
                  index.records.isEmpty, index.freeChunks.isEmpty else { throw VaultError.integrityFailure }
        } else {
            guard !fileManager.fileExists(atPath: rootDirectory.appendingPathComponent("index.v1.tmp").path) else {
                throw VaultError.storageFailure
            }
            try await blockStore.initialize(using: rootKey, auditPrivateKey: auditPrivateKey)
        }
        // Move the authenticated, protected header into place last.
        let headerStage = rootDirectory.appendingPathComponent("vault.header.creation")
        if !fileManager.fileExists(atPath: headerStage.path) {
            try writeProtectedNewFile(try JSONEncoder().encode(journal.header), at: headerStage)
        } else {
            guard (try? Data(contentsOf: headerStage)) == (try JSONEncoder().encode(journal.header)) else {
                throw VaultError.integrityFailure
            }
        }
        try fileManager.moveItem(at: headerStage, to: headerURL)
        try? fileManager.removeItem(at: creationURL)
    }

    private func writeProtectedNewFile(_ data: Data, at url: URL) throws {
        guard !fileManager.fileExists(atPath: url.path),
              fileManager.createFile(atPath: url.path, contents: nil,
            attributes: [.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication]) else {
            throw VaultError.storageFailure
        }
        var protectedURL = url
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try protectedURL.setResourceValues(values)
        let attributes = try fileManager.attributesOfItem(atPath: url.path)
        #if targetEnvironment(simulator)
        // Simulator filesystems do not report NSFileProtectionKey reliably.
        // Keep the protection attribute on create, but verify it on hardware.
        #else
        guard attributes[.protectionKey] as? FileProtectionType == .completeUntilFirstUserAuthentication else {
            throw VaultError.storageFailure
        }
        #endif
        guard try url.resourceValues(forKeys: [.isExcludedFromBackupKey]).isExcludedFromBackup == true else {
            throw VaultError.storageFailure
        }
        let handle = try FileHandle(forWritingTo: url)
        do {
            try handle.write(contentsOf: data)
            try handle.synchronize()
            try handle.close()
        } catch {
            try? handle.close()
            throw error
        }
    }

    func revokeAccess() async {
        await blockStore.revokeAccess()
    }

    func unlock(password: String) async throws -> SymmetricKey {
        guard hasVault() else { throw VaultError.noVault }
        let header = try loadHeader()
        let deviceSecret = try KeychainStore.loadDeviceSecret()
        let passwordKey = try PasswordKDF.deriveKey(password: password, salt: header.salt, iterations: header.iterations)
        let kek = VaultCrypto.makeKEK(passwordKey: passwordKey, deviceSecret: deviceSecret)
        do {
            let key = try VaultCrypto.unwrap(header.wrappedRootKey, with: kek, aad: VaultCrypto.headerAAD(segmentCapacity: header.segmentCapacity, salt: header.salt, iterations: header.iterations))
            await blockStore.activateAccess()
            return key
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
        try replaceHeader(updatedHeader)
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

    func destroyVault() async throws {
        await blockStore.revokeAccess()
        // Key destruction is deliberately first; filesystem cleanup cannot restore access.
        try KeychainStore.deleteDeviceSecret()
        if fileManager.fileExists(atPath: rootDirectory.path) {
            try fileManager.removeItem(at: rootDirectory)
        }
        guard !fileManager.fileExists(atPath: rootDirectory.path) else { throw VaultError.storageFailure }
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
        guard UserDefaults.standard.bool(forKey: "auditLoggingEnabled"),
              !fileManager.fileExists(atPath: auditRotationURL.path) else { return }
        guard let header = try? loadHeader(),
              let audit = try? AuditLogStore(rootDirectory: rootDirectory, publicKeyData: header.auditPublicKey) else { return }
        let maximumEntries = UserDefaults.standard.integer(forKey: "auditHistoryLimit")
        // Never persist user-entered unlock input, even if a future caller
        // accidentally supplies it. Legacy entries are handled separately.
        try? audit.append(event.metadataOnly, maximumEntries: maximumEntries > 0 ? maximumEntries : nil)
    }

    func setAuditHistoryLimit(_ limit: Int) throws {
        guard UserDefaults.standard.bool(forKey: "auditLoggingEnabled") else { return }
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

    /// One-time crypto-shred of legacy audit history that could contain a
    /// near-correct password or PIN. All old events are intentionally lost.
    func purgeLegacyAuditSecrets(using rootKey: SymmetricKey) async throws {
        try await completeAuditRotation(using: rootKey)
        try await blockStore.load(using: rootKey)
        if (await blockStore.snapshot()).auditPrivacyVersion != 1 {
            try await eraseAudit(using: rootKey)
            // Commit the marker only after the old audit key and log are rotated.
            // If interrupted, the next unlock repeats the safe purge.
            try await blockStore.markAuditPrivacyMigrated(using: rootKey)
        }
        // Turning logging off also removes history from newer versions. A
        // failed/interrupted erasure is retried on the next authenticated unlock.
        if !UserDefaults.standard.bool(forKey: "auditLoggingEnabled"),
           fileManager.fileExists(atPath: rootDirectory.appendingPathComponent("audit.log").path) {
            try await eraseAudit(using: rootKey)
        }
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
        let stagingURL = rootDirectory.appendingPathComponent("audit.rotation.\(UUID().uuidString).tmp")
        guard fileManager.createFile(
            atPath: stagingURL.path,
            contents: nil,
            attributes: [.protectionKey: FileProtectionType.complete]
        ) else { throw VaultError.storageFailure }
        defer { try? fileManager.removeItem(at: stagingURL) }
        var protectedURL = stagingURL
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try protectedURL.setResourceValues(values)
        let attributes = try fileManager.attributesOfItem(atPath: stagingURL.path)
        #if !targetEnvironment(simulator)
        guard attributes[.protectionKey] as? FileProtectionType == .complete else {
            throw VaultError.storageFailure
        }
        #endif
        guard try stagingURL.resourceValues(forKeys: [.isExcludedFromBackupKey]).isExcludedFromBackup == true else {
            throw VaultError.storageFailure
        }
        let handle = try FileHandle(forWritingTo: stagingURL)
        do {
            try handle.write(contentsOf: journal)
            try handle.synchronize()
            try handle.close()
        } catch {
            try? handle.close()
            throw error
        }
        try fileManager.moveItem(at: stagingURL, to: auditRotationURL)

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
        try replaceHeader(updated)
    }

    private func replaceHeader(_ header: VaultHeader) throws {
        let temporaryURL = rootDirectory.appendingPathComponent("vault.header.\(UUID().uuidString).tmp")
        guard fileManager.createFile(
            atPath: temporaryURL.path,
            contents: nil,
            attributes: [.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication]
        ) else { throw VaultError.storageFailure }
        defer { try? fileManager.removeItem(at: temporaryURL) }
        var protectedURL = temporaryURL
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try protectedURL.setResourceValues(values)
        let attributes = try fileManager.attributesOfItem(atPath: temporaryURL.path)
        #if !targetEnvironment(simulator)
        guard attributes[.protectionKey] as? FileProtectionType == .completeUntilFirstUserAuthentication else {
            throw VaultError.storageFailure
        }
        #endif
        guard try temporaryURL.resourceValues(forKeys: [.isExcludedFromBackupKey]).isExcludedFromBackup == true else {
            throw VaultError.storageFailure
        }
        let handle = try FileHandle(forWritingTo: temporaryURL)
        do {
            try handle.write(contentsOf: JSONEncoder().encode(header))
            try handle.synchronize()
            try handle.close()
        } catch {
            try? handle.close()
            throw error
        }
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
