import Foundation
import CryptoKit

enum AuditMethod: String, Codable {
    case password
    case pin
    case faceID
    case lifecycle
}

struct AuditEvent: Codable, Equatable {
    let timestamp: Date
    let method: AuditMethod
    let result: String
    let enteredSecret: String?

    var metadataOnly: AuditEvent {
        AuditEvent(timestamp: timestamp, method: method, result: result, enteredSecret: nil)
    }
}

struct LockedAuditEntry: Codable {
    let ephemeralPublicKey: Data
    let sealedRecord: Data
}

struct AuditLogStore {
    let rootDirectory: URL
    let publicKey: Curve25519.KeyAgreement.PublicKey
    /// Injectable so tests can simulate physical write failures (AUDIT #12).
    var fileManager: FileManager = .default

    private var logURL: URL {
        rootDirectory.appendingPathComponent("audit.log")
    }

    init(rootDirectory: URL, publicKeyData: Data) throws {
        self.rootDirectory = rootDirectory
        self.publicKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: publicKeyData)
    }

    func append(_ event: AuditEvent, maximumEntries: Int? = nil) throws {
        let ephemeral = Curve25519.KeyAgreement.PrivateKey()
        let shared = try ephemeral.sharedSecretFromKeyAgreement(with: publicKey)
        let key = shared.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: Data("Vaulthalla-audit-salt-v1".utf8),
            sharedInfo: Data("Vaulthalla-audit-entry-v1".utf8),
            outputByteCount: 32
        )
        // Audit metadata must never retain unlock input, even for direct callers.
        let plaintext = try JSONEncoder().encode(event.metadataOnly)
        let sealed = try AES.GCM.seal(plaintext, using: key)
        let ciphertext = sealed.nonce.withUnsafeBytes { Data($0) } + sealed.ciphertext + sealed.tag
        var entries = try loadEntries()
        entries.append(LockedAuditEntry(ephemeralPublicKey: ephemeral.publicKey.rawRepresentation, sealedRecord: ciphertext))
        entries = limited(entries, maximumEntries: maximumEntries)
        try writeEntries(entries)
    }

    func trim(maximumEntries: Int?) throws {
        try writeEntries(limited(try loadEntries(), maximumEntries: maximumEntries))
    }

    private func limited(_ entries: [LockedAuditEntry], maximumEntries: Int?) -> [LockedAuditEntry] {
        guard let maximumEntries, maximumEntries > 0, entries.count > maximumEntries else { return entries }
        return Array(entries.suffix(maximumEntries))
    }

    private func writeEntries(_ entries: [LockedAuditEntry]) throws {
        try fileManager.createDirectory(at: rootDirectory, withIntermediateDirectories: true)
        let data = try JSONEncoder().encode(entries)
        let temporary = logURL.appendingPathExtension("tmp")
        try data.write(to: temporary, options: .atomic)
        try fileManager.setAttributes([.protectionKey: FileProtectionType.complete], ofItemAtPath: temporary.path)
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        var mutableURL = temporary
        try mutableURL.setResourceValues(values)
        // AUDIT #10: verify the protection/backup policy actually took effect
        // before the log is published; never write an unverified audit file.
        let attrs = try fileManager.attributesOfItem(atPath: temporary.path)
        #if !targetEnvironment(simulator)
        guard attrs[.protectionKey] as? FileProtectionType == .complete else { throw VaultError.storageFailure }
        #endif
        guard (try? temporary.resourceValues(forKeys: [.isExcludedFromBackupKey]))?.isExcludedFromBackup == true else {
            throw VaultError.storageFailure
        }
        if fileManager.fileExists(atPath: logURL.path) {
            _ = try fileManager.replaceItemAt(logURL, withItemAt: temporary)
        } else {
            try fileManager.moveItem(at: temporary, to: logURL)
        }
    }

    func decrypt(using privateKeyData: Data) throws -> [AuditEvent] {
        let privateKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKeyData)
        return try loadEntries().map { entry in
            let ephemeral = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: entry.ephemeralPublicKey)
            let shared = try privateKey.sharedSecretFromKeyAgreement(with: ephemeral)
            let key = shared.hkdfDerivedSymmetricKey(
                using: SHA256.self,
                salt: Data("Vaulthalla-audit-salt-v1".utf8),
                sharedInfo: Data("Vaulthalla-audit-entry-v1".utf8),
                outputByteCount: 32
            )
            let sealed = entry.sealedRecord
            guard sealed.count >= 28 else { throw VaultError.integrityFailure }
            let nonce = try AES.GCM.Nonce(data: sealed.prefix(12))
            let box = try AES.GCM.SealedBox(
                nonce: nonce,
                ciphertext: sealed.dropFirst(12).dropLast(16),
                tag: sealed.suffix(16)
            )
            return try JSONDecoder().decode(AuditEvent.self, from: AES.GCM.open(box, using: key))
        }
    }

    func erase() throws {
        if fileManager.fileExists(atPath: logURL.path) {
            try fileManager.removeItem(at: logURL)
        }
        guard !fileManager.fileExists(atPath: logURL.path) else {
            throw VaultError.storageFailure
        }
    }

    private func loadEntries() throws -> [LockedAuditEntry] {
        guard let data = fileManager.contents(atPath: logURL.path) else { return [] }
        return try JSONDecoder().decode([LockedAuditEntry].self, from: data)
    }
}
