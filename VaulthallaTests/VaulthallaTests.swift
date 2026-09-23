import Testing
import Foundation
import CryptoKit
@testable import Vaulthalla

struct VaulthallaTests {
    #if !VAULTHALLA_UNSAFE_HTTP_IMPORT
    @Test @MainActor func defaultBuildRefusesPlaintextWebImport() {
        let server = LocalWebImportServer()
        server.start(rootKey: SymmetricKey(size: .bits256))
        guard case .failed = server.state else {
            Issue.record("Plaintext Web Import listener must be disabled by default")
            server.stop()
            return
        }
        #expect(server.importURL == nil)
        #expect(server.pairingPIN.isEmpty)
        server.stop()
    }
    #endif

    @Test func passwordKeyIsDeterministicForSameInputs() throws {
        let salt = Data(repeating: 7, count: 32)
        let first = try PasswordKDF.deriveKey(password: "correct horse battery", salt: salt, iterations: 100_000)
        let second = try PasswordKDF.deriveKey(password: "correct horse battery", salt: salt, iterations: 100_000)
        #expect(first.withUnsafeBytes { Data($0) } == second.withUnsafeBytes { Data($0) })
    }

    @Test func wrongPasswordCannotUnwrapRootKey() throws {
        let salt = VaultCrypto.randomData(count: 32)
        let device = VaultCrypto.randomData(count: 32)
        let root = SymmetricKey(size: .bits256)
        let passwordKey = try PasswordKDF.deriveKey(password: "correct password", salt: salt, iterations: 100_000)
        let kek = VaultCrypto.makeKEK(passwordKey: passwordKey, deviceSecret: device)
        let aad = VaultCrypto.headerAAD(segmentCapacity: SegmentCapacity.megabytes100.bytes, salt: salt, iterations: 100_000)
        let wrapped = try VaultCrypto.wrap(root, with: kek, aad: aad)
        let wrongKey = try PasswordKDF.deriveKey(password: "wrong password", salt: salt, iterations: 100_000)
        let wrongKEK = VaultCrypto.makeKEK(passwordKey: wrongKey, deviceSecret: device)
        #expect(throws: (any Error).self) {
            _ = try VaultCrypto.unwrap(wrapped, with: wrongKEK, aad: aad)
        }
    }

    @Test func deviceSecretChangesUnlockKey() throws {
        let password = try PasswordKDF.deriveKey(password: "correct password", salt: Data(repeating: 1, count: 32), iterations: 100_000)
        let first = VaultCrypto.makeKEK(passwordKey: password, deviceSecret: Data(repeating: 2, count: 32))
        let second = VaultCrypto.makeKEK(passwordKey: password, deviceSecret: Data(repeating: 3, count: 32))
        #expect(first.withUnsafeBytes { Data($0) } != second.withUnsafeBytes { Data($0) })
    }

    @Test func authenticatedCiphertextDetectsTampering() throws {
        let key = SymmetricKey(size: .bits256)
        let plaintext = Data("vault".utf8)
        let sealed = try AES.GCM.seal(plaintext, using: key)
        let bytes = Data([sealed.ciphertext.first! ^ 1]) + sealed.ciphertext.dropFirst()
        let tampered = try AES.GCM.SealedBox(nonce: sealed.nonce, ciphertext: bytes, tag: sealed.tag)
        var rejected = false
        do {
            _ = try AES.GCM.open(tampered, using: key)
        } catch {
            rejected = true
        }
        #expect(rejected)
    }

    @Test func headerRejectsUnknownFormat() throws {
        var header = VaultHeader(segmentCapacity: SegmentCapacity.megabytes100.bytes, salt: Data(repeating: 1, count: 32), iterations: 100_000, wrappedRootKey: Data(repeating: 1, count: 60), auditPublicKey: Data(repeating: 1, count: 32))
        header = VaultHeader(magic: Data("BAD".utf8), formatVersion: 99, segmentCapacity: 1, chunkPayloadSize: 1, kdfVersion: 1, salt: Data(), iterations: 0, wrappedRootKey: Data(), auditPublicKey: Data())
        #expect(throws: VaultError.invalidHeader) { try header.validate() }
    }

    @Test func pbkdf2CalibrationStaysWithinBounds() throws {
        let iterations = try PasswordKDF.calibratedIterations()
        #expect(iterations >= PasswordKDF.minimumIterations)
        #expect(iterations < UInt32.max)
    }

    @Test func deriveKeyRejectsInvalidSalt() {
        #expect(throws: VaultError.self) {
            _ = try PasswordKDF.deriveKey(password: "some password", salt: Data(repeating: 0, count: 16), iterations: 1_000)
        }
    }

    @Test func passwordChangeInvalidatesOldCredential() throws {
        let root = SymmetricKey(size: .bits256)
        let device = VaultCrypto.randomData(count: 32)
        let iterations: UInt32 = 100_000

        let salt1 = Data(repeating: 1, count: 32)
        let oldKey = try PasswordKDF.deriveKey(password: "old master password", salt: salt1, iterations: iterations)
        let aad1 = VaultCrypto.headerAAD(segmentCapacity: SegmentCapacity.megabytes100.bytes, salt: salt1, iterations: iterations)
        let oldKEK = VaultCrypto.makeKEK(passwordKey: oldKey, deviceSecret: device)
        let originalHeader = try VaultCrypto.wrap(root, with: oldKEK, aad: aad1)

        let salt2 = Data(repeating: 2, count: 32)
        let newKey = try PasswordKDF.deriveKey(password: "new master password", salt: salt2, iterations: iterations)
        let aad2 = VaultCrypto.headerAAD(segmentCapacity: SegmentCapacity.megabytes100.bytes, salt: salt2, iterations: iterations)
        let newKEK = VaultCrypto.makeKEK(passwordKey: newKey, deviceSecret: device)
        let rewrappedHeader = try VaultCrypto.wrap(root, with: newKEK, aad: aad2)

        #expect(try VaultCrypto.unwrap(originalHeader, with: oldKEK, aad: aad1) == root)
        #expect(try VaultCrypto.unwrap(rewrappedHeader, with: newKEK, aad: aad2) == root)
        #expect(throws: (any Error).self) {
            _ = try VaultCrypto.unwrap(rewrappedHeader, with: oldKEK, aad: aad2)
        }
    }

    @Test func chunkEncryptionIsUniquePerItem() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)

        let sharedPrefix = Data(repeating: 9, count: VaultConstants.chunkPayloadSize)
        let firstURL = directory.appendingPathComponent("one.jpg")
        let secondURL = directory.appendingPathComponent("two.jpg")
        try (sharedPrefix + Data(repeating: 1, count: 100)).write(to: firstURL)
        try (sharedPrefix + Data(repeating: 2, count: 100)).write(to: secondURL)

        let store = EncryptedBlockStore(rootDirectory: directory.appendingPathComponent("vault", isDirectory: true))
        let key = SymmetricKey(size: .bits256)
        let firstRecord = try await store.importFile(at: firstURL, filename: "one.jpg", mimeType: "image/jpeg", rootKey: key, segmentCapacity: SegmentCapacity.megabytes50.bytes)
        let secondRecord = try await store.importFile(at: secondURL, filename: "two.jpg", mimeType: "image/jpeg", rootKey: key, segmentCapacity: SegmentCapacity.megabytes50.bytes)
        #expect(firstRecord != nil && secondRecord != nil)

        // Identical 1 MiB plaintext prefixes must produce different sealed bytes
        // because chunk keys and nonces are derived per item.
        let firstChunk = try await store.readEncryptedChunk(at: firstRecord!.chunks[0])
        let secondChunk = try await store.readEncryptedChunk(at: secondRecord!.chunks[0])
        #expect(firstChunk != secondChunk)
        #expect(try await store.plaintext(for: secondRecord!) == sharedPrefix + Data(repeating: 2, count: 100))
    }
}
