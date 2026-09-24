import Foundation
import CryptoKit
import LocalAuthentication
import Security

enum UnlockMethod: String, Codable, CaseIterable {
    case password
    case pin
    case faceID
}

struct AttemptState: Codable, Equatable {
    var passwordFailures = 0
    var pinFailures = 0
    var faceIDFailures = 0
    var destructivePasswordFailures = 0
    var autoDestroyEnabled = false
    var autoDestroyThreshold = 5
    var pinThreshold = 5
    var faceIDThreshold = 3
    /// Monotonic save counter. Lets the authenticated shadow copy tell a
    /// crash window apart from a rolled-back or deleted Keychain item.
    var version = 0

    init() {}

    // Items written by older app versions predate `version`; decode them as
    // version 0 instead of failing the whole load.
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        passwordFailures = try c.decodeIfPresent(Int.self, forKey: .passwordFailures) ?? 0
        pinFailures = try c.decodeIfPresent(Int.self, forKey: .pinFailures) ?? 0
        faceIDFailures = try c.decodeIfPresent(Int.self, forKey: .faceIDFailures) ?? 0
        destructivePasswordFailures = try c.decodeIfPresent(Int.self, forKey: .destructivePasswordFailures) ?? 0
        autoDestroyEnabled = try c.decodeIfPresent(Bool.self, forKey: .autoDestroyEnabled) ?? false
        autoDestroyThreshold = try c.decodeIfPresent(Int.self, forKey: .autoDestroyThreshold) ?? 5
        pinThreshold = try c.decodeIfPresent(Int.self, forKey: .pinThreshold) ?? 5
        faceIDThreshold = try c.decodeIfPresent(Int.self, forKey: .faceIDThreshold) ?? 3
        version = try c.decodeIfPresent(Int.self, forKey: .version) ?? 0
    }
}

enum AttemptPolicy {
    static func delay(for failureCount: Int) -> TimeInterval {
        switch failureCount {
        case ...0: return 0
        case 1: return 1
        case 2: return 2
        case 3: return 5
        case 4: return 10
        default: return min(60, pow(2, Double(min(failureCount - 4, 5))) * 10)
        }
    }

    static func shouldDestroy(state: AttemptState) -> Bool {
        state.autoDestroyEnabled &&
        state.destructivePasswordFailures >= state.autoDestroyThreshold
    }

    static func convenienceLockedOut(state: AttemptState) -> Bool {
        state.pinFailures >= state.pinThreshold || state.faceIDFailures >= state.faceIDThreshold
    }
}

actor AttemptStateStore {
    static let shared = AttemptStateStore()
    private let service = "io.sobaka.vaulthalla"
    private let account: String
    private let fileManager: FileManager
    private let rootDirectory: URL
    private let deviceSecretProvider: @Sendable () throws -> Data

    init(account: String = "attempt-state-v1",
         fileManager: FileManager = .default,
         rootDirectory: URL? = nil,
         deviceSecret: (@Sendable () throws -> Data)? = nil) {
        self.account = account
        self.fileManager = fileManager
        let appSupport = fileManager.urls(for: .applicationSupportDirectory, in: .userDomainMask).first ?? fileManager.temporaryDirectory
        self.rootDirectory = rootDirectory ?? appSupport.appendingPathComponent("Vaulthalla", isDirectory: true)
        self.deviceSecretProvider = deviceSecret ?? { try KeychainStore.loadDeviceSecret() }
    }

    enum PersistenceError: Error, Equatable { case keychain(OSStatus), invalidData, readbackMismatch, sealStorage, tampered, destructionRequired, convenienceLockedOut }

    private var query: [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: service,
         kSecAttrAccount as String: account]
    }

    func loadChecked() throws -> AttemptState {
        let state = try readKeychain()
        try verifyShadow(against: state)
        return state
    }

    private func readKeychain() throws -> AttemptState {
        var request = query
        request[kSecReturnData as String] = true
        request[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(request as CFDictionary, &result)
        if status == errSecItemNotFound { return AttemptState() }
        guard status == errSecSuccess else { throw PersistenceError.keychain(status) }
        guard let data = result as? Data,
              let state = try? JSONDecoder().decode(AttemptState.self, from: data) else {
            throw PersistenceError.invalidData
        }
        return state
    }

    /// Persists `state` and returns the actually stored copy, whose
    /// `version` has been bumped. Callers compare against this value, not
    /// the pre-save input.
    @discardableResult
    func saveChecked(_ state: AttemptState) throws -> AttemptState {
        var updated = state
        updated.version = max(state.version, try readKeychain().version) + 1
        let data = try JSONEncoder().encode(updated)
        let attributes: [String: Any] = [kSecValueData as String: data]
        let status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        if status == errSecItemNotFound {
            var add = query
            add[kSecValueData as String] = data
            add[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            add[kSecAttrSynchronizable as String] = false
            let added = SecItemAdd(add as CFDictionary, nil)
            guard added == errSecSuccess else { throw PersistenceError.keychain(added) }
        } else if status != errSecSuccess {
            throw PersistenceError.keychain(status)
        }
        guard try readKeychain() == updated else { throw PersistenceError.readbackMismatch }
        // AUDIT #6: re-establish the authenticated shadow after the Keychain
        // write is durable. Keychain-first ordering makes a crash between the
        // two writes a recoverable lag (self-heal on next load), never a
        // tamper verdict.
        if let secret = try? deviceSecretProvider() {
            try writeShadow(updated, secret: secret)
        }
        return updated
    }

    func recordFailureChecked(method: UnlockMethod) throws -> AttemptState {
        var state = try loadChecked()
        switch method {
        case .password:
            state.passwordFailures += 1
            if state.autoDestroyEnabled { state.destructivePasswordFailures += 1 }
        case .pin: state.pinFailures += 1
        case .faceID: state.faceIDFailures += 1
        }
        return try saveChecked(state)
    }

    func recordSuccessChecked(method: UnlockMethod) throws -> AttemptState {
        var state = try loadChecked()
        guard !AttemptPolicy.shouldDestroy(state: state) else { throw PersistenceError.destructionRequired }
        if method != .password, AttemptPolicy.convenienceLockedOut(state: state) {
            throw PersistenceError.convenienceLockedOut
        }
        switch method {
        case .password:
            state.passwordFailures = 0
            state.destructivePasswordFailures = 0
            state.pinFailures = 0
            state.faceIDFailures = 0
        case .pin: state.pinFailures = 0
        case .faceID: state.faceIDFailures = 0
        }
        return try saveChecked(state)
    }

    func configureChecked(_ update: (inout AttemptState) -> Void) throws -> AttemptState {
        var state = try loadChecked()
        update(&state)
        return try saveChecked(state)
    }

    // MARK: - AUDIT #6 — authenticated shadow copy (rollback / deletion detection)
    //
    // The Keychain counter alone cannot distinguish "external deletion or
    // rollback" from "fresh install" — both read back as a clean state. The
    // shadow is an AES-GCM copy of the state sealed under the device secret:
    // a fresh install has neither, a rolled-back or deleted Keychain item is
    // always behind its shadow, and a crash between the two writes only ever
    // leaves the shadow behind (a recoverable lag, self-healed below).
    // Vault destruction removes both sides: `store.destroyVault` deletes the
    // directory and `KeychainStore.deleteAllVaulthallaItems` the Keychain
    // entries, each checked with a readback.

    private var shadowURL: URL { rootDirectory.appendingPathComponent("attempt-state.seal") }

    private func verifyShadow(against state: AttemptState) throws {
        let url = shadowURL
        guard fileManager.fileExists(atPath: url.path),
              let sealed = try? fileManager.contents(atPath: url.path) else { return }
        // Without the device secret there is nothing to authenticate against;
        // the missing-secret policy (vault present ⇒ destroy) is enforced at
        // the device-binding gate, not here.
        guard let secret = try? deviceSecretProvider() else { return }
        let shadow: AttemptState
        do {
            shadow = try Self.unseal(sealed, with: secret)
        } catch {
            throw PersistenceError.tampered
        }
        if shadow.version > state.version || (shadow.version == state.version && shadow != state) {
            throw PersistenceError.tampered
        }
        // Shadow behind the Keychain state: crash between the Keychain write
        // and the shadow write. Accept the state, re-establish the shadow.
        if shadow.version < state.version {
            try? writeShadow(state, secret: secret)
        }
    }

    private func writeShadow(_ state: AttemptState, secret: Data) throws {
        let sealed = try Self.seal(state, with: secret)
        try fileManager.createDirectory(at: rootDirectory, withIntermediateDirectories: true)
        let url = shadowURL
        let temp = url.appendingPathExtension("tmp")
        do {
            try sealed.write(to: temp, options: .atomic)
            try fileManager.setAttributes([.protectionKey: FileProtectionType.complete], ofItemAtPath: temp.path)
            var values = URLResourceValues()
            values.isExcludedFromBackup = true
            var mutableTemp = temp
            try mutableTemp.setResourceValues(values)
            if fileManager.fileExists(atPath: url.path) {
                _ = try fileManager.replaceItemAt(url, withItemAt: temp)
            } else {
                try fileManager.moveItem(at: temp, to: url)
            }
            let back = try Data(contentsOf: url)
            guard try Self.unseal(back, with: secret) == state else { throw PersistenceError.sealStorage }
        } catch {
            try? fileManager.removeItem(at: temp)
            throw PersistenceError.sealStorage
        }
    }

    static func seal(_ state: AttemptState, with secret: Data) throws -> Data {
        let key = SymmetricKey(data: secret)
        let aad = Data("Vaulthalla-attempt-seal-v1".utf8)
        let nonce = AES.GCM.Nonce()
        let plaintext = try JSONEncoder().encode(state)
        let sealed = try AES.GCM.seal(plaintext, using: key, nonce: nonce, authenticating: aad)
        return nonce.withUnsafeBytes { Data($0) } + sealed.ciphertext + sealed.tag
    }

    static func unseal(_ sealed: Data, with secret: Data) throws -> AttemptState {
        guard sealed.count >= 12 + 16 else { throw PersistenceError.tampered }
        let key = SymmetricKey(data: secret)
        let aad = Data("Vaulthalla-attempt-seal-v1".utf8)
        let nonce = try AES.GCM.Nonce(data: sealed.prefix(12))
        let box = try AES.GCM.SealedBox(nonce: nonce,
                                        ciphertext: sealed.dropFirst(12).dropLast(16),
                                        tag: sealed.suffix(16))
        let plaintext = try AES.GCM.open(box, using: key, authenticating: aad)
        return try JSONDecoder().decode(AttemptState.self, from: plaintext)
    }
}

enum AntiDebug {
    /// True when a debugger is attached to this process.
    /// Never reports in DEBUG builds (the dev debugger is expected).
    static func isDebuggerAttached() -> Bool {
        #if DEBUG
        return false
        #else
        var mib = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        var info = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.size
        guard sysctl(&mib, 4, &info, &size, nil, 0) == 0 else { return false }
        // P_TRACED (0x1) from <mach/proc.h>
        return (info.kp_proc.p_flag & 0x1) != 0
        #endif
    }
}

enum BiometricFailure: Error, Equatable {
    case code(LAError.Code)
}

/// §42 — abstraction over the biometric-gated unlock so the Face ID state machine
/// (success, failure counting, lockout) is testable without biometric hardware.
protocol FaceIDUnlocking: Sendable {
    /// Throws `FaceIDAuthenticationFailure` when the biometrics do not match,
    /// `FaceIDWrapperUnavailableFailure` when biometrics succeeded but the
    /// Keychain item they guard can no longer be read, and
    /// `FaceIDUnavailableFailure` for everything else (no sensor, cancelled,
    /// not configured).
    func unlock() async throws -> SymmetricKey
}

struct FaceIDAuthenticationFailure: Error {}
struct FaceIDUnavailableFailure: Error {}
/// The biometric prompt succeeded, but the biometry-gated Keychain item could
/// not be read afterwards. With `.biometryCurrentSet` access control this is
/// definitive: the stored enrollment no longer matches the current one (e.g.
/// Face ID was re-registered), so the wrapper can never unlock again.
struct FaceIDWrapperUnavailableFailure: Error {}

struct LiveFaceIDUnlocker: FaceIDUnlocking {
    func unlock() async throws -> SymmetricKey {
        switch await BiometricAuthenticator.authenticate(reason: "Unlock your Vaulthalla vault.") {
        case .success(let context):
            do {
                return try ConvenienceUnlockStore.unlockWithFaceID(using: context)
            } catch {
                // Biometrics just succeeded, so the failure is the Keychain
                // item itself — not the user. The wrapper is permanently
                // unusable with the current enrollment.
                throw FaceIDWrapperUnavailableFailure()
            }
        case .failure(.code(.authenticationFailed)):
            throw FaceIDAuthenticationFailure()
        case .failure:
            throw FaceIDUnavailableFailure()
        }
    }
}

enum BiometricAuthenticator {
    static func authenticate(reason: String) async -> Result<LAContext, BiometricFailure> {
        let context = LAContext()
        context.localizedCancelTitle = "Use Password"
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
            return .failure(.code(error.flatMap { LAError.Code(rawValue: $0.code) } ?? .biometryNotAvailable))
        }
        do {
            let success = try await context.evaluatePolicy(
                .deviceOwnerAuthenticationWithBiometrics,
                localizedReason: reason
            )
            return success ? .success(context) : .failure(.code(.authenticationFailed))
        } catch let error as LAError {
            return .failure(.code(error.code))
        } catch {
            return .failure(.code(.systemCancel))
        }
    }
}
