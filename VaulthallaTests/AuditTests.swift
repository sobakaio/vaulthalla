import Testing
import Foundation
import CryptoKit
@testable import Vaulthalla

struct AuditTests {
    @Test func auditMetadataNeverIncludesFailedUnlockInput() throws {
        let event = AuditEvent(timestamp: Date(timeIntervalSince1970: 1),
                               method: .password, result: "failure", enteredSecret: "near-correct-secret")
        let sanitized = event.metadataOnly
        #expect(sanitized.enteredSecret == nil)
        #expect(sanitized.method == .password)
        #expect(sanitized.result == "failure")
        #expect(try JSONEncoder().encode(sanitized).range(of: Data("near-correct-secret".utf8)) == nil)
    }

    @Test @MainActor func lockClearsDecryptedAuditEntries() {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let model = VaultAppModel()
        model.store = VaultStore(fileManager: RedirectedFileManager(replacement: directory))
        model.phase = .unlocked
        model.auditEvents = [AuditEvent(timestamp: Date(), method: .password,
                                        result: "failure", enteredSecret: "legacy-guess")]
        model.lock()
        #expect(model.phase == .locked)
        #expect(model.auditEvents.isEmpty)
    }

    @Test func lockedAuditEntryDecryptsOnlyWithPrivateKey() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let privateKey = Curve25519.KeyAgreement.PrivateKey()
        let store = try AuditLogStore(rootDirectory: directory, publicKeyData: privateKey.publicKey.rawRepresentation)
        let secret = "failed-master-secret"
        try store.append(AuditEvent(timestamp: Date(timeIntervalSince1970: 1), method: .password, result: "failure", enteredSecret: secret))

        let raw = try Data(contentsOf: directory.appendingPathComponent("audit.log"))
        #expect(raw.range(of: Data(secret.utf8)) == nil)
        #expect(try store.decrypt(using: privateKey.rawRepresentation).first?.enteredSecret == nil)
    }

    @Test func disabledAuditLoggingDoesNotCreateFile() async throws {
        let previous = UserDefaults.standard.object(forKey: "auditLoggingEnabled")
        UserDefaults.standard.set(false, forKey: "auditLoggingEnabled")
        defer {
            if let previous { UserDefaults.standard.set(previous, forKey: "auditLoggingEnabled") }
            else { UserDefaults.standard.removeObject(forKey: "auditLoggingEnabled") }
        }
        let base = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: base) }
        let root = base.appendingPathComponent("Vaulthalla", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let privateKey = Curve25519.KeyAgreement.PrivateKey()
        let header = VaultHeader(segmentCapacity: SegmentCapacity.megabytes50.bytes,
                                 salt: Data(repeating: 1, count: 32), iterations: 100_000,
                                 wrappedRootKey: Data(repeating: 2, count: 60),
                                 auditPublicKey: privateKey.publicKey.rawRepresentation)
        try JSONEncoder().encode(header).write(to: root.appendingPathComponent("vault.header"))
        let store = VaultStore(fileManager: RedirectedFileManager(replacement: base))
        await store.appendAudit(AuditEvent(timestamp: Date(), method: .password,
                                           result: "failure", enteredSecret: "must-not-store"))
        let logURL = root.appendingPathComponent("audit.log")
        #expect(!FileManager.default.fileExists(atPath: logURL.path))
        let key = SymmetricKey(size: .bits256)
        let blocks = EncryptedBlockStore(rootDirectory: root)
        try await blocks.initialize(using: key, auditPrivateKey: privateKey.rawRepresentation)
        UserDefaults.standard.set(true, forKey: "auditLoggingEnabled")
        await store.appendAudit(AuditEvent(timestamp: Date(), method: .pin,
                                           result: "failure", enteredSecret: "1234"))
        #expect(FileManager.default.fileExists(atPath: logURL.path))
        let audit = try AuditLogStore(rootDirectory: root, publicKeyData: privateKey.publicKey.rawRepresentation)
        #expect(try audit.decrypt(using: privateKey.rawRepresentation).first?.enteredSecret == nil)
        UserDefaults.standard.set(false, forKey: "auditLoggingEnabled")
        try await store.purgeLegacyAuditSecrets(using: key)
        #expect(!FileManager.default.fileExists(atPath: logURL.path))
        #expect((try await store.loadHeader()).auditPublicKey != privateKey.publicKey.rawRepresentation)
    }

    @Test func legacyAuditSecretsRotateKeyAndClearHistory() async throws {
        let base = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: base) }
        let root = base.appendingPathComponent("Vaulthalla", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let key = SymmetricKey(size: .bits256)
        let oldPrivate = Curve25519.KeyAgreement.PrivateKey()
        var index = VaultIndex()
        index.auditPrivateKey = oldPrivate.rawRepresentation
        index.auditPrivacyVersion = nil // legacy authenticated index
        let sealedIndex = try AES.GCM.seal(JSONEncoder().encode(index), using: key,
                                           authenticating: Data("Vaulthalla-index-v1".utf8))
        try (sealedIndex.nonce.withUnsafeBytes { Data($0) } + sealedIndex.ciphertext + sealedIndex.tag)
            .write(to: root.appendingPathComponent("index.v1"))
        let header = VaultHeader(segmentCapacity: SegmentCapacity.megabytes50.bytes,
                                 salt: Data(repeating: 1, count: 32), iterations: 100_000,
                                 wrappedRootKey: Data(repeating: 2, count: 60),
                                 auditPublicKey: oldPrivate.publicKey.rawRepresentation)
        try JSONEncoder().encode(header).write(to: root.appendingPathComponent("vault.header"))
        let legacy = AuditEvent(timestamp: Date(), method: .password,
                                result: "failure", enteredSecret: "near-correct-secret")
        let ephemeral = Curve25519.KeyAgreement.PrivateKey()
        let shared = try ephemeral.sharedSecretFromKeyAgreement(with: oldPrivate.publicKey)
        let auditKey = shared.hkdfDerivedSymmetricKey(using: SHA256.self,
            salt: Data("Vaulthalla-audit-salt-v1".utf8),
            sharedInfo: Data("Vaulthalla-audit-entry-v1".utf8), outputByteCount: 32)
        let sealed = try AES.GCM.seal(JSONEncoder().encode(legacy), using: auditKey)
        let entry = LockedAuditEntry(ephemeralPublicKey: ephemeral.publicKey.rawRepresentation,
            sealedRecord: sealed.nonce.withUnsafeBytes { Data($0) } + sealed.ciphertext + sealed.tag)
        try JSONEncoder().encode([entry]).write(to: root.appendingPathComponent("audit.log"))

        let store = VaultStore(fileManager: RedirectedFileManager(replacement: base))
        try await store.purgeLegacyAuditSecrets(using: key)
        #expect(!FileManager.default.fileExists(atPath: root.appendingPathComponent("audit.log").path))
        let updated = try await store.indexSnapshot()
        #expect(updated.auditPrivacyVersion == 1)
        #expect(updated.auditPrivateKey != oldPrivate.rawRepresentation)
        let newHeader = try await store.loadHeader()
        #expect(newHeader.auditPublicKey != oldPrivate.publicKey.rawRepresentation)
        try await store.purgeLegacyAuditSecrets(using: key)
        #expect((try await store.loadHeader()).auditPublicKey == newHeader.auditPublicKey)
    }

    @Test func wrongAuditPrivateKeyCannotDecrypt() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let privateKey = Curve25519.KeyAgreement.PrivateKey()
        let otherKey = Curve25519.KeyAgreement.PrivateKey()
        let store = try AuditLogStore(rootDirectory: directory, publicKeyData: privateKey.publicKey.rawRepresentation)
        try store.append(AuditEvent(timestamp: Date(), method: .pin, result: "failure", enteredSecret: "1234"))
        #expect(throws: (any Error).self) {
            _ = try store.decrypt(using: otherKey.rawRepresentation)
        }
    }

    @Test func auditHistoryLimitKeepsNewestEntries() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let privateKey = Curve25519.KeyAgreement.PrivateKey()
        let store = try AuditLogStore(rootDirectory: directory, publicKeyData: privateKey.publicKey.rawRepresentation)

        for index in 0..<3 {
            try store.append(
                AuditEvent(timestamp: Date(timeIntervalSince1970: TimeInterval(index)), method: .lifecycle, result: "\(index)", enteredSecret: nil),
                maximumEntries: 2
            )
        }

        let events = try store.decrypt(using: privateKey.rawRepresentation)
        #expect(events.map(\.result) == ["1", "2"])
    }

    @Test func trimmingAuditHistoryRewritesOnlyNewestEntries() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let privateKey = Curve25519.KeyAgreement.PrivateKey()
        let store = try AuditLogStore(rootDirectory: directory, publicKeyData: privateKey.publicKey.rawRepresentation)

        for index in 0..<3 {
            try store.append(AuditEvent(timestamp: Date(timeIntervalSince1970: TimeInterval(index)), method: .lifecycle, result: "\(index)", enteredSecret: nil))
        }

        try store.trim(maximumEntries: 2)
        #expect(try store.decrypt(using: privateKey.rawRepresentation).map(\.result) == ["1", "2"])
    }
}
