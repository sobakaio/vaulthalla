import Foundation
import CryptoKit
import Security
import CommonCrypto

enum VaultError: LocalizedError, Equatable {
    case invalidPassword
    case invalidConfirmation
    case noVault
    case vaultAlreadyExists
    case invalidHeader
    case invalidPasswordOrDevice
    case integrityFailure
    case keychainFailure(OSStatus)
    case storageFailure
    case unsupportedFormat
    case debuggerDetected

    var errorDescription: String? {
        switch self {
        case .invalidPassword: return "Password must contain 8–128 characters."
        case .invalidConfirmation: return "Passwords do not match."
        case .noVault: return "No vault exists on this device."
        case .vaultAlreadyExists: return "A vault already exists."
        case .invalidHeader: return "Vault header is invalid."
        case .invalidPasswordOrDevice: return "Incorrect password or unavailable device binding."
        case .integrityFailure: return "Vault integrity could not be verified."
        case .keychainFailure: return "Secure key storage is unavailable."
        case .storageFailure: return "Vault storage is unavailable."
        case .unsupportedFormat: return "This vault format is not supported."
        case .debuggerDetected: return "Unlock is unavailable while debugging is attached."
        }
    }
}

enum VaultConstants {
    static let formatVersion: UInt16 = 1
    static let chunkPayloadSize = 1_048_576
    static let defaultSegmentCapacity = 100 * 1_048_576
    static let minimumPasswordLength = 8
    static let maximumPasswordLength = 128
    static let kdfVersion: UInt16 = 1
    static let magic = Data("VAULTHALLA\0".utf8)
}

enum SegmentCapacity: Int, CaseIterable, Identifiable {
    case megabytes50 = 50
    case megabytes100 = 100
    case megabytes250 = 250
    case megabytes500 = 500
    case gigabyte1 = 1000

    var id: Int { rawValue }
    var bytes: Int { rawValue * 1_000_000 }
    var title: String {
        rawValue == 1000 ? "1 GB" : "\(rawValue) MB"
    }
}

struct VaultHeader: Codable, Equatable {
    let magic: Data
    let formatVersion: UInt16
    let segmentCapacity: Int
    let chunkPayloadSize: Int
    let kdfVersion: UInt16
    let salt: Data
    let iterations: UInt32
    let wrappedRootKey: Data
    let auditPublicKey: Data

    init(segmentCapacity: Int, salt: Data, iterations: UInt32, wrappedRootKey: Data, auditPublicKey: Data) {
        self.magic = VaultConstants.magic
        self.formatVersion = VaultConstants.formatVersion
        self.segmentCapacity = segmentCapacity
        self.chunkPayloadSize = VaultConstants.chunkPayloadSize
        self.kdfVersion = VaultConstants.kdfVersion
        self.salt = salt
        self.iterations = iterations
        self.wrappedRootKey = wrappedRootKey
        self.auditPublicKey = auditPublicKey
    }

    init(magic: Data, formatVersion: UInt16, segmentCapacity: Int, chunkPayloadSize: Int, kdfVersion: UInt16, salt: Data, iterations: UInt32, wrappedRootKey: Data, auditPublicKey: Data) {
        self.magic = magic
        self.formatVersion = formatVersion
        self.segmentCapacity = segmentCapacity
        self.chunkPayloadSize = chunkPayloadSize
        self.kdfVersion = kdfVersion
        self.salt = salt
        self.iterations = iterations
        self.wrappedRootKey = wrappedRootKey
        self.auditPublicKey = auditPublicKey
    }

    func validate() throws {
        guard magic == VaultConstants.magic,
              formatVersion == VaultConstants.formatVersion,
              chunkPayloadSize == VaultConstants.chunkPayloadSize,
              SegmentCapacity.allCases.contains(where: { $0.bytes == segmentCapacity }),
              kdfVersion == VaultConstants.kdfVersion,
              salt.count == 32,
              iterations > 0,
              !wrappedRootKey.isEmpty,
              !auditPublicKey.isEmpty else {
            throw VaultError.invalidHeader
        }
    }
}

struct PasswordKDF {
    static let targetMilliseconds = 600
    static let minimumIterations: UInt32 = 100_000

    static func deriveKey(password: String, salt: Data, iterations: UInt32) throws -> SymmetricKey {
        let normalized = password.precomposedStringWithCanonicalMapping
        guard let passwordData = normalized.data(using: .utf8), salt.count == 32 else {
            throw VaultError.invalidPassword
        }
        var output = Data(repeating: 0, count: 32)
        let outputLength = output.count
        let result = output.withUnsafeMutableBytes { outputBuffer in
            passwordData.withUnsafeBytes { passwordBuffer in
                salt.withUnsafeBytes { saltBuffer in
                    CCKeyDerivationPBKDF(
                        CCPBKDFAlgorithm(kCCPBKDF2),
                        passwordBuffer.bindMemory(to: Int8.self).baseAddress,
                        passwordData.count,
                        saltBuffer.bindMemory(to: UInt8.self).baseAddress,
                        salt.count,
                        CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                        iterations,
                        outputBuffer.bindMemory(to: UInt8.self).baseAddress,
                        outputLength
                    )
                }
            }
        }
        guard result == kCCSuccess else { throw VaultError.integrityFailure }
        return SymmetricKey(data: output)
    }

    static func calibratedIterations() throws -> UInt32 {
        let salt = Data(repeating: 0x5A, count: 32)
        let sampleIterations: UInt32 = 10_000
        let start = ContinuousClock.now
        _ = try deriveKey(password: "calibration", salt: salt, iterations: sampleIterations)
        let elapsed = max(1.0, Double(start.duration(to: .now).components.attoseconds) / 1_000_000_000_000_000_000.0 + Double(start.duration(to: .now).components.seconds))
        let estimate = UInt64(Double(sampleIterations) * Double(targetMilliseconds) / (elapsed * 1000.0))
        return UInt32(min(max(estimate, UInt64(minimumIterations)), UInt64.max - 1))
    }
}

enum KeychainStore {
    private static let service = "io.sobaka.vaulthalla"
    private static let account = "device-secret-v1"

    static func saveDeviceSecret(_ data: Data) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecAttrSynchronizable as String: false
        ]
        SecItemDelete(query as CFDictionary)
        guard SecItemAdd(query as CFDictionary, nil) == errSecSuccess else {
            throw VaultError.keychainFailure(errSecIO)
        }
    }

    static func loadDeviceSecret() throws -> Data {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let data = result as? Data else {
            throw VaultError.keychainFailure(status)
        }
        return data
    }

    static func deleteDeviceSecret() {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        SecItemDelete(query as CFDictionary)
    }

    /// Fresh-install hygiene: removes every Vaulthalla keychain item (device secret,
    /// attempt counters, PIN/Face ID wrappers) so a reinstalled app starts clean.
    static func deleteAllVaulthallaItems() {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service
        ]
        SecItemDelete(query as CFDictionary)
    }
}

enum VaultCrypto {
    static func randomData(count: Int) -> Data {
        var data = Data(repeating: 0, count: count)
        data.withUnsafeMutableBytes { buffer in
            _ = SecRandomCopyBytes(kSecRandomDefault, count, buffer.baseAddress!)
        }
        return data
    }

    static func makeKEK(passwordKey: SymmetricKey, deviceSecret: Data) -> SymmetricKey {
        let ikm = passwordKey.withUnsafeBytes { Data($0) } + deviceSecret
        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: ikm),
            salt: Data("Vaulthalla-KDF-v1".utf8),
            info: Data("Vault-Key-Encryption-Key".utf8),
            outputByteCount: 32
        )
    }

    static func wrap(_ rootKey: SymmetricKey, with kek: SymmetricKey, aad: Data) throws -> Data {
        let nonce = AES.GCM.Nonce()
        let sealed = try AES.GCM.seal(rootKey.withUnsafeBytes { Data($0) }, using: kek, nonce: nonce, authenticating: aad)
        return nonce.withUnsafeBytes { Data($0) } + sealed.ciphertext + sealed.tag
    }

    static func unwrap(_ wrapped: Data, with kek: SymmetricKey, aad: Data) throws -> SymmetricKey {
        guard wrapped.count >= 12 + 16 else { throw VaultError.invalidPasswordOrDevice }
        let nonce = try AES.GCM.Nonce(data: wrapped.prefix(12))
        let ciphertext = wrapped.dropFirst(12).dropLast(16)
        let tag = wrapped.suffix(16)
        let box = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: tag)
        let clear = try AES.GCM.open(box, using: kek, authenticating: aad)
        return SymmetricKey(data: clear)
    }

    static func headerAAD(segmentCapacity: Int, salt: Data, iterations: UInt32) -> Data {
        Data("VAULTHALLA-WRAPPER-v1".utf8) + withBytes(segmentCapacity) + salt + withBytes(Int(iterations))
    }

    private static func withBytes(_ value: Int) -> Data {
        var big = UInt64(value).bigEndian
        return Data(bytes: &big, count: MemoryLayout<UInt64>.size)
    }
}
