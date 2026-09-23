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
}

actor AttemptStateStore {
    static let shared = AttemptStateStore()
    private let service = "io.sobaka.vaulthalla"
    private let account = "attempt-state-v1"

    func load() -> AttemptState {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let data = result as? Data,
              let state = try? JSONDecoder().decode(AttemptState.self, from: data) else {
            return AttemptState()
        }
        return state
    }

    func save(_ state: AttemptState) {
        guard let data = try? JSONEncoder().encode(state) else { return }
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        SecItemDelete(query as CFDictionary)
        let add: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecAttrSynchronizable as String: false
        ]
        SecItemAdd(add as CFDictionary, nil)
    }

    func recordFailure(method: UnlockMethod) -> AttemptState {
        var state = load()
        switch method {
        case .password:
            state.passwordFailures += 1
            if state.autoDestroyEnabled {
                state.destructivePasswordFailures += 1
            }
        case .pin:
            state.pinFailures += 1
        case .faceID:
            state.faceIDFailures += 1
        }
        save(state)
        return state
    }

    func recordSuccess(method: UnlockMethod) -> AttemptState {
        var state = load()
        switch method {
        case .password:
            state.passwordFailures = 0
            state.destructivePasswordFailures = 0
            state.pinFailures = 0
            state.faceIDFailures = 0
        case .pin:
            state.pinFailures = 0
        case .faceID:
            state.faceIDFailures = 0
        }
        save(state)
        return state
    }

    func configure(_ update: (inout AttemptState) -> Void) -> AttemptState {
        var state = load()
        update(&state)
        save(state)
        return state
    }

    func erase() {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        SecItemDelete(query as CFDictionary)
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
    /// Throws `FaceIDAuthenticationFailure` when the biometrics do not match and
    /// `FaceIDUnavailableFailure` for everything else (no sensor, cancelled, not configured).
    func unlock() async throws -> SymmetricKey
}

struct FaceIDAuthenticationFailure: Error {}
struct FaceIDUnavailableFailure: Error {}

struct LiveFaceIDUnlocker: FaceIDUnlocking {
    func unlock() async throws -> SymmetricKey {
        switch await BiometricAuthenticator.authenticate(reason: "Unlock your Vaulthalla vault.") {
        case .success(let context):
            do {
                return try ConvenienceUnlockStore.unlockWithFaceID(using: context)
            } catch {
                throw FaceIDUnavailableFailure()
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
