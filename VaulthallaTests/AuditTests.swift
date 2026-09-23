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
