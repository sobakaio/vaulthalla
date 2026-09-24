import SwiftUI
import Observation
import CryptoKit
import UniformTypeIdentifiers
import PhotosUI
import Photos
import UIKit
import LocalAuthentication
import AVKit
import OSLog
import Security
import UserNotifications

struct ContentView: View {
    @State private var model = VaultAppModel()
    @Environment(\.scenePhase) private var scenePhase
    @State private var privacyCover = false
    @AppStorage("screenshotProtection") private var screenshotProtection = true

    var body: some View {
        Group {
            switch model.phase {
            case .loading:
                VaultLoadingView()
            case .onboarding:
                OnboardingView(model: model)
            case .locked:
                LockView(model: model)
            case .unlocked:
                MainVaultView(model: model)
            }
        }
        .task { await model.load() }
        .onChange(of: scenePhase) { _, phase in
            if phase == .inactive {
                privacyCover = true
                Task { await model.stopWebImport() }
            } else if phase == .background {
                model.lock()
            } else if phase == .active {
                privacyCover = false
                // A system permission prompt (or backgrounding) briefly
                // transitions the scene to .inactive, which stopped the
                // import server. If the import sheet is still on screen,
                // resume the session instead of leaving it permanently off.
                model.webImportResumeIfSheetVisible()
            }
        }
        .onReceive(NotificationCenter.default.publisher(for: UIApplication.userDidTakeScreenshotNotification)) { _ in
            guard screenshotProtection else { return }
            privacyCover = true
            model.lock(reason: "capture")
        }
        .onReceive(NotificationCenter.default.publisher(for: UIScreen.capturedDidChangeNotification)) { _ in
            guard screenshotProtection else { return }
            if UIScreen.main.isCaptured {
                privacyCover = true
                model.lock(reason: "capture")
            }
        }
        .overlay {
            if privacyCover && screenshotProtection {
                Color.black.ignoresSafeArea()
                    .accessibilityLabel("Privacy cover")
            } else if model.isBusy && !model.importProgress.isRunning && model.phase != .locked {
                VStack {
                    Spacer()
                    HStack(spacing: 14) {
                        ProgressView()
                            .controlSize(.regular)

                        Text("Working…")
                            .font(.body.weight(.semibold))
                            .lineLimit(1)

                        Spacer(minLength: 8)

                        Button("Cancel") {
                            model.cancelCurrentOperation()
                        }
                        .buttonStyle(.bordered)
                        .tint(VaultUI.accent)
                    }
                    .padding(.horizontal, 16)
                    .padding(.vertical, 13)
                    .frame(maxWidth: .infinity)
                    .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 18, style: .continuous))
                    .overlay {
                        RoundedRectangle(cornerRadius: 18, style: .continuous)
                            .stroke(.quaternary, lineWidth: 1)
                    }
                    .shadow(color: .black.opacity(0.12), radius: 16, y: 6)
                    .padding(.horizontal, 16)
                    .padding(.bottom, 8)
                }
            }
        }
    }
}

@Observable
@MainActor
final class VaultAppModel {
    enum Phase: Equatable {
        case loading
        case onboarding
        case locked
        case unlocked
    }

    var phase: Phase = .loading
    var errorMessage = ""
    /// Shown as a confirmation dialog on the onboarding screen after the vault
    /// was auto-destroyed — never as an inline error label.
    var destructionMessage = ""
    var isBusy = false
    var pendingPassword = ""
    var pendingPIN = ""
    var confirmPassword = ""
    var selectedSegment: SegmentCapacity = .megabytes100
    var rootKey: SymmetricKey?
    var records: [MediaRecord] = []
    var importMessage = "" {
        didSet {
            // Toasts self-dismiss so cancelled/failed operations leave no artefacts on screen.
            guard importMessage != oldValue, !importMessage.isEmpty else { return }
            clearImportMessageAfterDelay()
        }
    }
    var integrityState = "Not verified"
    var lastVerifiedAt: Date?
    var pinEnabled = false
    var faceIDEnabled = false
    var autoDestroyEnabled = false
    var autoDestroyThreshold = 5
    var unlockStatistics = AttemptState()
    var auditEvents: [AuditEvent] = []
    var pinFailureThreshold = 5
    var faceIDFailureThreshold = 3
    var storageStatistics: VaultStore.StorageStatistics?

    private static let logger = Logger(subsystem: "io.sobaka.vaulthalla", category: "vault-lifecycle")
    /// Injectable for tests (§42); production always uses the shared stores.
    var store: VaultStore = .shared
    var attemptStore: AttemptStateStore = .shared
    var faceIDUnlocker: any FaceIDUnlocking = LiveFaceIDUnlocker()
    let webImportServer = LocalWebImportServer()
    /// True while the Web Import sheet is on screen (set by WebImportView's
    /// onAppear/onDisappear). Used to resume the server when the scene
    /// becomes active again after a transient .inactive (e.g. a system
    /// permission prompt covering the sheet).
    var webImportSheetVisible = false
    private var loaded = false
    private var sessionGeneration: UInt64 = 0
    private var destructionInProgress = false
    var isApplicationActive: () -> Bool = { UIApplication.shared.applicationState == .active }

    /// A missing device binding for an existing vault is not a bad password.
    /// Other Keychain errors may be temporary, so they block access without wiping.
    private func requireDeviceBinding() async -> Bool {
        // Test models and a normal first launch can have no committed vault.
        // Never erase global Keychain state from an unrelated empty store.
        let hasHeader = await store.hasVault()
        let hasJournal = await store.hasPendingCreation()
        if !hasHeader && !hasJournal { return true }
        do {
            _ = try KeychainStore.loadDeviceSecret()
            return true
        } catch VaultError.keychainFailure(let status) where status == errSecItemNotFound {
            // Recheck before irreversible cleanup in case a transient Keychain
            // visibility change produced an apparent missing item.
            do {
                _ = try KeychainStore.loadDeviceSecret()
                return true
            } catch VaultError.keychainFailure(let retry) where retry == errSecItemNotFound {
                await completeAutoDestroy()
                destructionMessage = "Vault destroyed because its device key was lost."
                return false
            } catch {
                errorMessage = "Device key unavailable. Unlock blocked."
                return false
            }
        } catch {
            errorMessage = "Device key unavailable. Unlock blocked."
            return false
        }
    }

    private func canFinishUnlock(_ generation: UInt64) -> Bool {
        sessionGeneration == generation && phase == .locked &&
        isApplicationActive() && !Task.isCancelled && !destructionInProgress
    }
    private var generatedPreviewIDs = Set<UUID>()

    /// §20 — free space on the volume holding the vault, in bytes.
    private func availableDiskSpace() -> Int64 {
        let path = (try? FileManager.default.url(for: .documentDirectory, in: .userDomainMask,
                                                 appropriateFor: nil, create: false).path) ?? NSHomeDirectory()
        let attrs = try? FileManager.default.attributesOfFileSystem(forPath: path)
        return (attrs?[.systemFreeSize] as? NSNumber)?.int64Value ?? 0
    }

    /// §5 — enforce the strongest practical file protection on staged (plaintext) files.
    /// Files staged in the USB inbox (Documents root) get complete protection:
    /// they are plaintext waiting to be encrypted into the vault.
    private func protectStagingDirectory() {
        guard let documents = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first else { return }
        let ok: Set<String> = ["jpg", "jpeg", "png", "gif", "heic", "heif", "mp4", "mov", "m4v"]
        let urls = (try? FileManager.default.contentsOfDirectory(at: documents, includingPropertiesForKeys: nil)) ?? []
        for url in urls where ok.contains(url.pathExtension.lowercased()) {
            try? FileManager.default.setAttributes(
                [FileAttributeKey.protectionKey: FileProtectionType.complete.rawValue],
                ofItemAtPath: url.path
            )
        }
    }

    /// §16 — number of staged media files waiting in the USB Inbox (Documents root).
    var usbInboxWaitingCount = 0

    // MARK: - Import completion notification

    /// iOS cannot bring a backgrounded app to the foreground. The closest
    /// redirect available: a local notification whose tap opens the app.
    /// Posted only when the user is not looking at the app.
    func postImportCompletionNotification(imported: Int, failed: Int) {
        guard imported > 0 || failed > 0 else { return }
        guard UIApplication.shared.applicationState != .active else { return }
        let center = UNUserNotificationCenter.current()
        center.getNotificationSettings { settings in
            guard settings.authorizationStatus == .authorized else { return }
            let body = failed > 0
                ? "\(imported) file(s) imported, \(failed) failed."
                : "\(imported) file(s) imported to the vault."
            let content = UNMutableNotificationContent()
            content.title = "Vaulthalla import finished"
            content.body = body
            content.sound = .default
            let request = UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: nil)
            center.add(request)
        }
    }

    /// Ask once when the user actually uses an import feature.
    func requestNotificationAuthorization() {
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .badge]) { _, _ in }
    }

    // MARK: - Pending photo imports (survive app suspension)

    private static var pendingImportURL: URL {
        let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first ?? FileManager.default.temporaryDirectory
        return appSupport.appendingPathComponent("Vaulthalla").appendingPathComponent("pending-import.json")
    }

    private struct PendingImport: Codable {
        var identifiers: [String]
        var deleteOriginals: Bool
    }

    @discardableResult
    private func savePendingPhotoImport(_ identifiers: [String], deleteOriginals: Bool) -> Bool {
        guard let rootKey else { return false }
        let url = Self.pendingImportURL
        do {
            try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
            let plaintext = try JSONEncoder().encode(PendingImport(identifiers: identifiers, deleteOriginals: deleteOriginals))
            let sealed = try AES.GCM.seal(plaintext, using: rootKey, authenticating: Data("Vaulthalla-pending-import-v1".utf8))
            let data = sealed.nonce.withUnsafeBytes { Data($0) } + sealed.ciphertext + sealed.tag
            try data.write(to: url, options: .atomic)
            try FileManager.default.setAttributes([.protectionKey: FileProtectionType.complete], ofItemAtPath: url.path)
            var protectedURL = url
            var values = URLResourceValues()
            values.isExcludedFromBackup = true
            try protectedURL.setResourceValues(values)
            return true
        } catch {
            return false
        }
    }

    private func clearPendingPhotoImport() {
        try? FileManager.default.removeItem(at: Self.pendingImportURL)
    }

    private func loadPendingPhotoImport() -> PendingImport? {
        guard let rootKey, let data = try? Data(contentsOf: Self.pendingImportURL) else { return nil }
        if let legacy = try? JSONDecoder().decode(PendingImport.self, from: data) {
            // Migrate a pending import written by an older release before using it.
            guard savePendingPhotoImport(legacy.identifiers, deleteOriginals: legacy.deleteOriginals) else { return nil }
            return legacy
        }
        guard data.count >= 28,
              let nonce = try? AES.GCM.Nonce(data: data.prefix(12)),
              let box = try? AES.GCM.SealedBox(nonce: nonce, ciphertext: data.dropFirst(12).dropLast(16), tag: data.suffix(16)),
              let plaintext = try? AES.GCM.open(box, using: rootKey, authenticating: Data("Vaulthalla-pending-import-v1".utf8)) else { return nil }
        return try? JSONDecoder().decode(PendingImport.self, from: plaintext)
    }

    /// Re-imports photo items whose import was interrupted (app suspended or
    /// killed mid-import). Called after a successful unlock: no silent losses.
    func resumePendingPhotoImport() async {
        guard let pending = loadPendingPhotoImport(), !pending.identifiers.isEmpty, let rootKey else { return }
        let options = PHFetchOptions()
        options.predicate = NSPredicate(format: "localIdentifier IN %@", pending.identifiers)
        let result = PHAsset.fetchAssets(with: options)
        guard result.count > 0 else { return }
        isBusy = true
        defer { isBusy = false }
        importProgress = ImportProgress()
        importProgress.isRunning = true
        importProgress.total = result.count
        defer { importProgress.isRunning = false }
        var identifiers = pending.identifiers
        var imported = 0
        var failed = 0
        let coordinator = PhotosImportCoordinator()
        var index = 0
        for item in 0..<result.count {
            let asset = result[item]
            let id = asset.localIdentifier
            importProgress.currentFilename = "Pending item \(index + 1)"
            if let record = try? await coordinator.importPHAsset(asset, into: store, rootKey: rootKey) {
                if !records.contains(where: { $0.id == record.id }) {
                    imported += 1
                }
                identifiers.removeAll { $0 == id }
            } else {
                failed += 1
            }
            index += 1
            importProgress.completed = index
            if identifiers.isEmpty {
                clearPendingPhotoImport()
            } else {
                savePendingPhotoImport(identifiers, deleteOriginals: pending.deleteOriginals)
            }
        }
        await refreshIndex()
        importMessage = failed > 0
            ? "Resumed pending import: \(imported) imported, \(failed) failed."
            : "Resumed pending import: \(imported) imported."
        postImportCompletionNotification(imported: imported, failed: failed)
    }
    /// §13 — selected tab survives lock/unlock (lives in the model, not a torn-down view).
    var selectedTab = 0
    private func refreshUSBInboxCount() {
        usbInboxWaitingCount = usbInboxURLs().count
    }

    func load() async {
        guard !loaded else { return }
        loaded = true
        let hasVault = await store.hasVault()
        if UserDefaults.standard.bool(forKey: "vaultDestructionPending") {
            phase = .locked
            await completeAutoDestroy()
            return
        }
        phase = hasVault ? .locked : .onboarding
        if hasVault {
            guard await requireDeviceBinding() else { return }
        } else {
            let pendingCreation = await store.hasPendingCreation()
            if await store.hasCommittedIndex() {
                phase = .locked
                await completeAutoDestroy()
                destructionMessage = "Vault destroyed because its header and index did not match."
                return
            }
            if pendingCreation {
                // A staged creation is consistent only while its device key exists.
                guard await requireDeviceBinding() else { return }
            } else {
                do {
                    _ = try KeychainStore.loadDeviceSecret()
                    phase = .locked
                    await completeAutoDestroy()
                    destructionMessage = "Vault destroyed because its header was lost."
                    return
                } catch VaultError.keychainFailure(let status) where status == errSecItemNotFound {
                    // No committed vault or device binding: ordinary first launch.
                } catch {
                    phase = .locked
                    errorMessage = "Device key unavailable. Vault setup blocked."
                    return
                }
            }
        }
        if hasVault, let state = try? await attemptStore.loadChecked(), AttemptPolicy.shouldDestroy(state: state) {
            await completeAutoDestroy()
            return
        }
        if hasVault {
            guard (try? await attemptStore.loadChecked()) != nil else { errorMessage = "Security state unavailable. Unlock blocked."; return }
        }
        pinEnabled = ConvenienceUnlockStore.hasPIN()
        faceIDEnabled = ConvenienceUnlockStore.hasFaceID()
        await loadSecuritySettings()
        if hasVault {
            protectStagingDirectory()
            migrateLegacyInboxFolder()
            refreshUSBInboxCount()
        }
    }

    func createVault() async {
        errorMessage = ""
        destructionMessage = ""
        guard pendingPassword.count >= VaultConstants.minimumPasswordLength,
              pendingPassword.count <= VaultConstants.maximumPasswordLength else {
            errorMessage = VaultError.invalidPassword.localizedDescription
            return
        }
        guard pendingPassword == confirmPassword else {
            errorMessage = VaultError.invalidConfirmation.localizedDescription
            return
        }
        isBusy = true
        defer { isBusy = false }
        Self.logger.info("Vault creation started")
        do {
            try await store.createVault(password: pendingPassword, segmentCapacity: selectedSegment)
            let unlockedKey = try await store.unlock(password: pendingPassword)
            pendingPassword = ""
            confirmPassword = ""
            await finishUnlock(using: unlockedKey)
            Self.logger.info("Vault creation completed")
        } catch {
            Self.logger.error("Vault creation failed")
            errorMessage = error.localizedDescription
        }
    }

    func unlock() async {
        guard !isBusy else { return }
        errorMessage = ""
        guard !AntiDebug.isDebuggerAttached() else {
            errorMessage = "Security violation: a debugger is attached. Unlock is disabled."
            return
        }
        isBusy = true
        defer { isBusy = false }
        let generation = sessionGeneration
        guard await requireDeviceBinding() else { return }
        guard let currentState = try? await attemptStore.loadChecked() else { errorMessage = "Security state unavailable. Unlock blocked."; return }
        if AttemptPolicy.shouldDestroy(state: currentState) {
            await completeAutoDestroy()
            return
        }
        let delay = AttemptPolicy.delay(for: currentState.passwordFailures)
        if delay > 0 {
            try? await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000))
        }
        do {
            let unlockedKey = try await store.unlock(password: pendingPassword)
            guard canFinishUnlock(generation) else { return }
            guard let verifiedState = try? await attemptStore.loadChecked() else {
                errorMessage = "Security state unavailable. Unlock blocked."
                return
            }
            if AttemptPolicy.convenienceLockedOut(state: verifiedState) {
                do {
                    try ConvenienceUnlockStore.removeAllChecked()
                    pinEnabled = false
                    faceIDEnabled = false
                } catch {
                    pendingPassword = ""
                    errorMessage = "Convenience credentials could not be removed. Password unlock blocked; retry."
                    return
                }
            }
            guard let persisted = try? await attemptStore.recordSuccessChecked(method: .password) else { errorMessage = "Security state unavailable. Unlock blocked."; return }
            unlockStatistics = persisted
            await store.appendAudit(AuditEvent(timestamp: Date(), method: .password, result: "success", enteredSecret: nil))
            pendingPassword = ""
            guard canFinishUnlock(generation) else { return }
            await finishUnlock(using: unlockedKey)
        } catch {
            guard canFinishUnlock(generation) else { return }
            if case VaultError.keychainFailure(errSecItemNotFound) = error {
                _ = await requireDeviceBinding()
                return
            }
            if (error as? VaultError) == .invalidHeader {
                await completeAutoDestroy()
                if phase == .onboarding {
                    destructionMessage = "Vault destroyed after confirmed header corruption."
                }
                return
            }
            guard (error as? VaultError) == .invalidPasswordOrDevice else {
                errorMessage = "Unlock unavailable. Security state preserved."
                return
            }
            guard let state = try? await attemptStore.recordFailureChecked(method: .password) else { errorMessage = "Security state unavailable. Unlock blocked."; return }
            unlockStatistics = state
            pendingPassword = ""
            if AttemptPolicy.shouldDestroy(state: state) {
                await completeAutoDestroy()
                destructionMessage = "Vault destroyed after \(state.autoDestroyThreshold) failed unlock attempts."
            } else {
                await store.appendAudit(AuditEvent(timestamp: Date(), method: .password, result: "failure", enteredSecret: nil))
                errorMessage = "Incorrect password or unavailable device binding."
            }
        }
    }

    func cancelCurrentOperation() {
        BackgroundOperationCoordinator.shared.cancelCurrentOperation()
    }

    // §17 — live import progress: overall percent, current item, byte counters and Pause.
    struct ImportProgress: Equatable {
        var total = 0
        var completed = 0
        var totalBytes: Int64 = 0
        var processedBytes: Int64 = 0
        var currentFilename = ""
        var isRunning = false
        var isPaused = false

        var percent: Double? {
            total > 0 ? Double(completed) / Double(total) : nil
        }
    }

    var importProgress = ImportProgress()

    private var importMessageTask: Task<Void, Never>?

    /// Dismisses the import toast after a short delay; a newer message restarts the timer.
    private func clearImportMessageAfterDelay(seconds: Double = 5) {
        importMessageTask?.cancel()
        let current = importMessage
        importMessageTask = Task {
            try? await Task.sleep(for: .seconds(seconds))
            guard !Task.isCancelled, importMessage == current else { return }
            importMessage = ""
        }
    }

    func pauseImport() {
        importProgress.isPaused = true
    }

    func resumeImport() {
        importProgress.isPaused = false
    }

    /// Cooperative pause: blocks until the user resumes (or the operation is cancelled).
    private func waitForImportPause() async throws {
        while importProgress.isPaused {
            try await Task.sleep(for: .milliseconds(100))
            try Task.checkCancellation()
        }
    }

    private func fileSize(of url: URL) -> Int64 {
        guard let values = try? url.resourceValues(forKeys: [.fileSizeKey]) else { return 0 }
        return Int64(values.fileSize ?? 0)
    }

    private func totalFileSize(of urls: [URL]) -> Int64 {
        urls.reduce(Int64(0)) { $0 + fileSize(of: $1) }
    }

    func startWebImport() {
        guard let rootKey else {
            errorMessage = "Unlock the vault before starting Web Import."
            return
        }
        // Live grid refresh: as each file lands in the vault the index is
        // reloaded, so the library updates while the import session is open.
        webImportServer.onImportCompleted = { [weak self] in
            Task { @MainActor [weak self] in
                await self?.refreshIndex()
                // The user is usually in Safari/home while uploading: a
                // notification is the only way iOS lets us "redirect" them
                // back to the app.
                self?.postImportCompletionNotification(imported: self?.webImportServer.uploadedCount ?? 0, failed: 0)
            }
        }
        // Keep the app (and its local server) alive while the session runs
        // in the background — uploads keep arriving when the user is in Safari.
        // (Notification permission is requested at app launch, not here: a
        // prompt covering this sheet would transition the scene to
        // .inactive and stop the server right after its first start.)
        WebImportBackgroundSession.shared.begin()
        webImportServer.start(rootKey: rootKey)
    }

    /// Stops the session and, if anything was imported, reloads the index so
    /// newly uploaded files appear in the grid immediately — no unlock cycle.
    func stopWebImport() async {
        let imported = webImportServer.uploadedCount
        webImportServer.stop()
        webImportServer.onImportCompleted = nil
        WebImportBackgroundSession.shared.end()
        guard imported > 0 else { return }
        webImportServer.uploadedCount = 0
        await refreshIndex()
        await loadStorageStatistics()
    }

    /// Resumes Web Import when the scene becomes active again while the
    /// import sheet is still on screen. A system permission prompt (or
    /// backgrounding) briefly transitions the scene to .inactive, which
    /// stops the server; without this resume the first start on a fresh
    /// install would be left permanently "off" until a manual restart.
    func webImportResumeIfSheetVisible() {
        guard webImportSheetVisible,
              case .stopped = webImportServer.state else { return }
        startWebImport()
    }

    @discardableResult
    func refreshIndex() async -> Bool {
        guard let rootKey else { return false }
        do {
            try await store.loadIndex(using: rootKey)
            let index = await store.indexSnapshot()
            records = index.records.values.sorted { $0.filename < $1.filename }
            integrityState = index.integrityState
            lastVerifiedAt = index.lastVerifiedAt
            return true
        } catch VaultError.authenticatedIndexMismatch, VaultError.missingCommittedIndex {
            if await store.hasVault() {
                await completeAutoDestroy()
                destructionMessage = "Vault destroyed after authenticated data or key mismatch."
            } else {
                errorMessage = "Vault Integrity Error"
            }
            return false
        } catch {
            errorMessage = "Vault Integrity Error"
            return false
        }
    }

    /// Keep the lock screen visible until the encrypted index is authenticated and ready.
    private func finishUnlock(using key: SymmetricKey) async {
        guard await requireDeviceBinding() else { return }
        // Every successful unlock (password, PIN, Face ID) must re-arm store
        // access: lock() revokes it on backgrounding, and the convenience
        // paths do not re-arm it the way store.unlock() does. Without this,
        // the first index load after a background lock fails and PIN/Face ID
        // look broken ("Vault Integrity Error" / endless Face ID loop).
        await store.activateAccess()
        let generation = sessionGeneration
        let initialPhase = phase
        rootKey = key
        guard await refreshIndex() else {
            if phase != .onboarding {
                rootKey = nil
                records = []
                phase = .locked
            }
            return
        }
        do {
            try await store.purgeLegacyAuditSecrets(using: key)
        } catch VaultError.authenticatedIndexMismatch, VaultError.integrityFailure, VaultError.invalidHeader {
            guard sessionGeneration == generation else { return }
            await completeAutoDestroy()
            if phase == .onboarding {
                destructionMessage = "Vault destroyed after confirmed, unrecoverable audit integrity failure."
            }
            return
        } catch {
            if sessionGeneration == generation {
                rootKey = nil
                records = []
                phase = .locked
                errorMessage = "Audit privacy cleanup failed. Unlock blocked."
            }
            return
        }
        guard !destructionInProgress, rootKey != nil, sessionGeneration == generation,
              phase == initialPhase, isApplicationActive() else {
            if sessionGeneration == generation {
                rootKey = nil
                records = []
            }
            return
        }
        phase = .unlocked
        // Let the library become visible before resuming any long-running import.
        Task { await resumePendingPhotoImport() }
    }

    func scheduleImportFiles(_ urls: [URL], deleteOriginals: Bool) {
        BackgroundOperationCoordinator.shared.submit(
            title: "Importing media",
            subtitle: "Encrypting selected files"
        ) { [weak self] in
            guard let self else { return false }
            await self.performImportFiles(urls, deleteOriginals: deleteOriginals)
            return true
        }
    }

    private func performImportFiles(_ urls: [URL], deleteOriginals: Bool) async {
        guard let rootKey else { return }
        requestNotificationAuthorization()
        isBusy = true
        defer { isBusy = false }
        var imported = 0
        var duplicates = 0
        var failed = 0
        var cancelled = false
        var notEnoughStorage = 0
        var deletedOriginals = 0
        var deleteFailures = 0

        importProgress = ImportProgress()
        importProgress.isRunning = true
        importProgress.total = urls.count
        importProgress.totalBytes = totalFileSize(of: urls)
        defer { importProgress.isRunning = false }

        for url in urls {
            let progressIndex = importProgress.completed
            do {
                try Task.checkCancellation()
                try await waitForImportPause()
                importProgress.currentFilename = url.lastPathComponent
                let size = fileSize(of: url)
                if size > availableDiskSpace() {
                    notEnoughStorage += 1
                } else if let record = try await importWithPreview(url, rootKey: rootKey) {
                    if records.contains(where: { $0.id == record.id }) {
                        duplicates += 1
                    } else {
                        imported += 1
                    }
                    if deleteOriginals {
                        do {
                            try FileManager.default.removeItem(at: url)
                            deletedOriginals += 1
                        } catch {
                            deleteFailures += 1
                        }
                    }
                } else {
                    failed += 1
                }
                importProgress.processedBytes += size
                importProgress.completed = progressIndex + 1
            } catch is CancellationError {
                cancelled = true
                break
            } catch {
                failed += 1
                importProgress.completed = progressIndex + 1
            }
        }

        await refreshIndex()
        refreshUSBInboxCount()
        if cancelled {
            importMessage = "Import cancelled."
        } else {
            var message = "Imported \(imported), duplicates skipped \(duplicates), failed \(failed)."
            if notEnoughStorage > 0 {
                message += " \(notEnoughStorage) skipped: not enough storage."
            }
            if deleteOriginals && deleteFailures > 0 {
                message += " \(deleteFailures) original(s) could not be deleted."
            }
            importMessage = message
        }
    }

    func scheduleImportPhotos(_ items: [PhotosPickerItem], deleteOriginals: Bool) {
        BackgroundOperationCoordinator.shared.submit(
            title: "Importing Photos",
            subtitle: "Streaming encrypted media"
        ) { [weak self] in
            guard let self else { return false }
            await self.performImportPhotos(items, deleteOriginals: deleteOriginals)
            return true
        }
    }

    private func performImportPhotos(_ items: [PhotosPickerItem], deleteOriginals: Bool) async {
        guard let rootKey else { return }
        isBusy = true
        defer { isBusy = false }

        var imported = 0
        var duplicates = 0
        var failed = 0
        var cancelled = false
        var deletedOriginals = 0
        var originalsKept = false
        var importedIdentifiers: [String] = []
        var duplicateIdentifiers: [String] = []
        let coordinator = PhotosImportCoordinator()

        // §20 — conservative guard: photos stream from the library, so we can't know exact
        // sizes up front; refuse to start if the volume is nearly full.
        guard availableDiskSpace() > 256 * 1024 * 1024 else {
            importMessage = "Not enough storage to import photos. Free up space and try again."
            return
        }

        requestNotificationAuthorization()
        // Answer the system permission prompt (first use) before any fetch; racing it fails every item.
        let authStatus = await PhotosImportCoordinator.awaitAuthorization()
        guard authStatus == .authorized || authStatus == .limited else {
            importMessage = "Photo library access is required for Photos import. Enable it in Settings."
            return
        }

        importProgress = ImportProgress()
        importProgress.isRunning = true
        importProgress.total = items.count
        defer { importProgress.isRunning = false }

        // Persist the pending list so an import interrupted by app suspension
        // or a kill resumes automatically after the next unlock.
        var pendingIdentifiers = items.compactMap { $0.itemIdentifier }
        guard savePendingPhotoImport(pendingIdentifiers, deleteOriginals: deleteOriginals) else {
            importMessage = "Could not securely save the pending import. No photos were imported or deleted."
            return
        }

        for (index, item) in items.enumerated() {
            do {
                try Task.checkCancellation()
                try await waitForImportPause()
                importProgress.currentFilename = "Item \(index + 1)"
                if let record = try await coordinator.importAsset(item, into: store, rootKey: rootKey) {
                    if records.contains(where: { $0.id == record.id }) {
                        duplicates += 1
                        if deleteOriginals, let identifier = item.itemIdentifier {
                            duplicateIdentifiers.append(identifier)
                        }
                    } else {
                        imported += 1
                        if deleteOriginals, let identifier = item.itemIdentifier {
                            importedIdentifiers.append(identifier)
                        }
                        if record.encryptedThumbnail == nil {
                            if let jpeg = await PhotosImportCoordinator.thumbnail(for: item) {
                                try? await store.attachThumbnail(jpeg, to: record, using: rootKey)
                            }
                        }
                    }
                    importProgress.processedBytes += record.byteCount
                    if let identifier = item.itemIdentifier {
                        pendingIdentifiers.removeAll { $0 == identifier }
                    }
                    savePendingPhotoImport(pendingIdentifiers, deleteOriginals: deleteOriginals)
                } else {
                    failed += 1
                }
                importProgress.completed = index + 1
            } catch is CancellationError {
                cancelled = true
                break
            } catch {
                failed += 1
                importProgress.completed = index + 1
            }
        }

        var toDelete = importedIdentifiers
        if deleteOriginals, !duplicateIdentifiers.isEmpty {
            // Spec: before deleting duplicate sources, confirm the existing vault copy is still valid.
            do {
                let result = try await store.verify(using: rootKey)
                if result.corrupt.isEmpty {
                    toDelete.append(contentsOf: duplicateIdentifiers)
                } else {
                    originalsKept = true
                }
            } catch {
                originalsKept = true
            }
        }

        if !toDelete.isEmpty {
            deletedOriginals = await deleteLibraryAssets(withLocalIdentifiers: toDelete)
            if deletedOriginals < toDelete.count {
                originalsKept = true
            }
        }

        await refreshIndex()
        if cancelled {
            importMessage = "Import cancelled."
        } else {
            if pendingIdentifiers.isEmpty { clearPendingPhotoImport() }
            var message = "Photos: imported \(imported), duplicates skipped \(duplicates), failed \(failed)."
            if deleteOriginals {
                message += " \(deletedOriginals) original(s) deleted."
            } else {
                message += " Originals were kept."
            }
            if originalsKept {
                message += " Some originals were kept."
            }
            importMessage = message
        }
        postImportCompletionNotification(imported: imported, failed: failed)
    }

    private func deleteLibraryAssets(withLocalIdentifiers identifiers: [String]) async -> Int {
        let result = PHAsset.fetchAssets(withLocalIdentifiers: identifiers, options: nil)
        let count = result.count
        guard count > 0 else { return 0 }
        let assets = (0..<result.count).map { result[$0] }
        let succeeded: Bool = await withCheckedContinuation { continuation in
            PHPhotoLibrary.shared().performChanges({
                PHAssetChangeRequest.deleteAssets(assets as NSArray)
            }, completionHandler: { _, error in
                continuation.resume(returning: error == nil)
            })
        }
        return succeeded ? count : 0
    }

    func scheduleImportUSBInbox(deleteOriginals: Bool) {
        BackgroundOperationCoordinator.shared.submit(
            title: "Importing USB Inbox",
            subtitle: "Encrypting staged media"
        ) { [weak self] in
            guard let self else { return false }
            await self.performImportUSBInbox(deleteOriginals: deleteOriginals)
            return true
        }
    }

    private func performImportUSBInbox(deleteOriginals: Bool) async {
        guard let rootKey else { return }
        let fileManager = FileManager.default
        guard let documents = fileManager.urls(for: .documentDirectory, in: .userDomainMask).first else {
            importMessage = "USB Inbox is unavailable."
            return
        }
        // The USB inbox is the Documents root itself — that is where Finder
        // drops land when files are thrown onto the app icon. No subfolder.
        migrateLegacyInboxFolder()
        let urls = usbInboxURLs()

        isBusy = true
        defer { isBusy = false }
        var imported = 0
        var duplicates = 0
        var failed = 0
        var cancelled = false

        var notEnoughStorage = 0
        var deletedOriginals = 0
        var deleteFailures = 0

        importProgress = ImportProgress()
        importProgress.isRunning = true
        importProgress.total = urls.count
        importProgress.totalBytes = totalFileSize(of: urls)
        defer { importProgress.isRunning = false }

        for url in urls {
            let progressIndex = importProgress.completed
            do {
                try Task.checkCancellation()
                try await waitForImportPause()
                importProgress.currentFilename = url.lastPathComponent
                let size = fileSize(of: url)
                if size > availableDiskSpace() {
                    notEnoughStorage += 1
                } else if let record = try await importWithPreview(url, rootKey: rootKey) {
                    if records.contains(where: { $0.id == record.id }) {
                        duplicates += 1
                    } else {
                        imported += 1
                    }
                    if deleteOriginals {
                        do {
                            try fileManager.removeItem(at: url)
                            deletedOriginals += 1
                        } catch {
                            deleteFailures += 1
                        }
                    }
                } else {
                    failed += 1
                }
                importProgress.processedBytes += size
                importProgress.completed = progressIndex + 1
            } catch is CancellationError {
                cancelled = true
                break
            } catch {
                failed += 1
                importProgress.completed = progressIndex + 1
            }
        }

        await refreshIndex()
        refreshUSBInboxCount()
        if cancelled {
            importMessage = "Import cancelled."
        } else {
            var message = "USB Inbox: imported \(imported), duplicates skipped \(duplicates), failed \(failed)."
            if notEnoughStorage > 0 {
                message += " \(notEnoughStorage) skipped: not enough storage."
            }
            if deleteOriginals && deleteFailures > 0 {
                message += " \(deleteFailures) original(s) could not be deleted."
            }
            importMessage = message
        }
    }

    func read(_ record: MediaRecord) async -> Data? {
        guard let rootKey else { return nil }
        return try? await store.readMedia(record, using: rootKey)
    }

    /// §6 — returns encrypted previews, repairing legacy and streamed imports on demand.
    func preview(for record: MediaRecord) async -> Data? {
        guard let rootKey else { return nil }
        let isVideo = record.mimeType.hasPrefix("video/")
        let isImage = record.mimeType.hasPrefix("image/")
        guard isVideo || isImage else { return nil }

        if let thumb = try? await store.thumbnail(for: record, using: rootKey) {
            // Legacy image thumbnails were generated at 640 px and looked soft
            // on high-density displays. Never treat video poster data as a full image.
            if isImage, let img = UIImage(data: thumb), max(img.size.width, img.size.height) < 800,
               let full = try? await store.readMedia(record, using: rootKey),
               let upgraded = await ThumbnailGenerator.fromImageData(full) {
                try? await store.attachThumbnail(upgraded, to: record, using: rootKey)
                return upgraded
            }
            return thumb
        }

        let jpeg: Data?
        if isVideo {
            // Decrypt to a protected temporary file a chunk at a time. This avoids
            // holding a whole movie in memory just to render its poster.
            guard let url = try? await store.writeMediaToProtectedTemporaryFile(record, using: rootKey) else { return nil }
            defer { try? FileManager.default.removeItem(at: url) }
            jpeg = await ThumbnailGenerator.fromURL(url, isVideo: true)
        } else if let full = try? await store.readMedia(record, using: rootKey) {
            jpeg = await ThumbnailGenerator.fromImageData(full)
        } else {
            jpeg = nil
        }

        guard let jpeg else { return nil }
        do {
            try await store.attachThumbnail(jpeg, to: record, using: rootKey)
            generatedPreviewIDs.insert(record.id)
        } catch {
            // Keep this in memory for the current view, but leave the repair
            // action available in Settings if encrypted persistence failed.
        }
        return jpeg
    }

    var missingPreviewCount: Int {
        records.filter {
            $0.encryptedThumbnail == nil
                && !generatedPreviewIDs.contains($0.id)
                && ($0.mimeType.hasPrefix("image/") || $0.mimeType.hasPrefix("video/"))
        }.count
    }

    /// §6 — backfill missing encrypted image and video poster previews.
    func generateMissingPreviews() {
        BackgroundOperationCoordinator.shared.submit(
            title: "Generating previews",
            subtitle: "Encrypted thumbnails"
        ) { [weak self] in
            guard let self else { return false }
            await self.performGeneratePreviews()
            return true
        }
    }

    private func performGeneratePreviews() async {
        guard rootKey != nil else { return }
        isBusy = true
        defer { isBusy = false }
        var generated = 0
        let candidates = records.filter {
            $0.encryptedThumbnail == nil && ($0.mimeType.hasPrefix("image/") || $0.mimeType.hasPrefix("video/"))
        }
        for record in candidates {
            do {
                try Task.checkCancellation()
                if await preview(for: record) != nil { generated += 1 }
            } catch is CancellationError {
                break
            } catch {
                continue
            }
        }
        await refreshIndex()
        importMessage = generated > 0 ? "Generated \(generated) preview(s)." : ""
    }

    /// §6 — imports a file and, while security-scoped access is still open, attaches an
    /// encrypted preview. The original file is untouched.
    private func importWithPreview(_ url: URL, rootKey: SymmetricKey) async throws -> MediaRecord? {
        let didStart = url.startAccessingSecurityScopedResource()
        defer { if didStart { url.stopAccessingSecurityScopedResource() } }
        let isVideo = ["mp4", "mov", "m4v"].contains(url.pathExtension.lowercased())
        let jpegTask = Task.detached { await ThumbnailGenerator.fromURL(url, isVideo: isVideo) }
        guard let record = try await store.importFile(at: url, rootKey: rootKey) else {
            return nil
        }
        if let jpeg = await jpegTask.value {
            try? await store.attachThumbnail(jpeg, to: record, using: rootKey)
        }
        return record
    }

    func delete(_ ids: Set<UUID>) async {
        guard let rootKey else { return }
        isBusy = true
        defer { isBusy = false }
        for id in ids {
            try? await store.deleteMedia(id, using: rootKey)
        }
        await refreshIndex()
    }

    func scheduleCompact() {
        BackgroundOperationCoordinator.shared.submit(
            title: "Compacting vault",
            subtitle: "Reclaiming encrypted storage"
        ) { [weak self] in
            guard let self else { return false }
            await self.performCompact()
            return self.errorMessage == "Compaction completed."
        }
    }

    private func performCompact() async {
        guard let rootKey else { return }
        isBusy = true
        defer { isBusy = false }
        do {
            _ = try await store.compact(using: rootKey)
            await refreshIndex()
            errorMessage = "Compaction completed."
        } catch {
            errorMessage = "Vault Integrity Error"
        }
    }

    func scheduleVerify() {
        BackgroundOperationCoordinator.shared.submit(
            title: "Verifying vault",
            subtitle: "Checking encrypted media integrity"
        ) { [weak self] in
            guard let self else { return false }
            await self.performVerify()
            return self.errorMessage == "Vault verification completed."
        }
    }

    private func performVerify() async {
        guard let rootKey else { return }
        isBusy = true
        defer { isBusy = false }
        do {
            let result = try await store.verify(using: rootKey)
            await refreshIndex()
            errorMessage = result.corrupt.isEmpty
                ? "Vault verification completed."
                : "Corruption detected in \(result.corrupt.count) item(s)."
        } catch {
            errorMessage = "Vault Integrity Error"
        }
    }

    func unlockWithPIN() async {
        guard !isBusy else { return }
        errorMessage = ""
        guard !AntiDebug.isDebuggerAttached() else {
            errorMessage = "Security violation: a debugger is attached. Unlock is disabled."
            return
        }
        guard pinEnabled else { return }
        isBusy = true
        defer { isBusy = false }
        let generation = sessionGeneration
        guard await requireDeviceBinding() else { return }
        guard let state = try? await attemptStore.loadChecked() else { errorMessage = "Security state unavailable. Unlock blocked."; return }
        if AttemptPolicy.shouldDestroy(state: state) { await completeAutoDestroy(); return }
        guard !AttemptPolicy.convenienceLockedOut(state: state) else {
            pinEnabled = false
            pendingPIN = ""
            errorMessage = "Convenience unlock locked out after too many failed attempts."
            return
        }
        let delay = AttemptPolicy.delay(for: state.pinFailures)
        if delay > 0 { try? await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000)) }
        do {
            let unlockedKey = try ConvenienceUnlockStore.unlockWithPIN(pendingPIN)
            guard canFinishUnlock(generation) else { return }
            guard let persisted = try? await attemptStore.recordSuccessChecked(method: .pin) else { errorMessage = "Security state unavailable. Unlock blocked."; return }
            unlockStatistics = persisted
            await store.appendAudit(AuditEvent(timestamp: Date(), method: .pin, result: "success", enteredSecret: nil))
            pendingPIN = ""
            guard canFinishUnlock(generation) else { return }
            await finishUnlock(using: unlockedKey)
        } catch {
            guard canFinishUnlock(generation) else { return }
            guard let next = try? await attemptStore.recordFailureChecked(method: .pin) else { errorMessage = "Security state unavailable. Unlock blocked."; return }
            unlockStatistics = next
            await store.appendAudit(AuditEvent(timestamp: Date(), method: .pin, result: "failure", enteredSecret: nil))
            pendingPIN = ""
            if next.pinFailures >= next.pinThreshold {
                let removed = (try? ConvenienceUnlockStore.removeAllChecked()) != nil
                pinEnabled = false
                faceIDEnabled = false
                errorMessage = removed
                    ? "Convenience unlock locked out after too many failed attempts."
                    : "Convenience unlock locked out; Keychain removal could not be verified. Use password to retry."
                await store.appendAudit(AuditEvent(timestamp: Date(), method: .lifecycle, result: "pin-lockout", enteredSecret: nil))
            } else {
                errorMessage = "Incorrect PIN."
            }
        }
    }

    func unlockWithFaceID() async {
        guard !isBusy else { return }
        errorMessage = ""
        guard !AntiDebug.isDebuggerAttached() else {
            errorMessage = "Security violation: a debugger is attached. Unlock is disabled."
            return
        }
        guard faceIDEnabled else { return }
        let generation = sessionGeneration
        guard await requireDeviceBinding() else { return }
        guard let persistedState = try? await attemptStore.loadChecked() else { errorMessage = "Security state unavailable. Unlock blocked."; return }
        if AttemptPolicy.shouldDestroy(state: persistedState) { await completeAutoDestroy(); return }
        guard !AttemptPolicy.convenienceLockedOut(state: persistedState) else {
            faceIDEnabled = false
            errorMessage = "Convenience unlock locked out after too many failed attempts."
            return
        }
        isBusy = true
        defer { isBusy = false }
        do {
            let unlockedKey = try await faceIDUnlocker.unlock()
            guard canFinishUnlock(generation) else { return }
            guard let persisted = try? await attemptStore.recordSuccessChecked(method: .faceID) else { errorMessage = "Security state unavailable. Unlock blocked."; return }
            unlockStatistics = persisted
            await store.appendAudit(AuditEvent(timestamp: Date(), method: .faceID, result: "success", enteredSecret: nil))
            guard canFinishUnlock(generation) else { return }
            await finishUnlock(using: unlockedKey)
        } catch is FaceIDAuthenticationFailure {
            guard canFinishUnlock(generation) else { return }
            guard let next = try? await attemptStore.recordFailureChecked(method: .faceID) else { errorMessage = "Security state unavailable. Unlock blocked."; return }
            unlockStatistics = next
            await store.appendAudit(AuditEvent(timestamp: Date(), method: .faceID, result: "failure", enteredSecret: nil))
            if next.faceIDFailures >= next.faceIDThreshold {
                let removed = (try? ConvenienceUnlockStore.removeAllChecked()) != nil
                faceIDEnabled = false
                pinEnabled = false
                errorMessage = removed
                    ? "Convenience unlock locked out after too many failed attempts."
                    : "Convenience unlock locked out; Keychain removal could not be verified. Use password to retry."
                await store.appendAudit(AuditEvent(timestamp: Date(), method: .lifecycle, result: "faceid-lockout", enteredSecret: nil))
            } else {
                errorMessage = "Face ID authentication failed."
            }
        } catch is FaceIDWrapperUnavailableFailure {
            // Biometrics matched but the stored wrapper no longer does: the
            // enrollment changed, so this wrapper is dead. Disable it instead
            // of looping the user through prompts that can never succeed.
            guard canFinishUnlock(generation) else { return }
            faceIDEnabled = false
            await store.appendAudit(AuditEvent(timestamp: Date(), method: .faceID, result: "wrapper-unavailable", enteredSecret: nil))
            errorMessage = "Face ID unlock is no longer available — your biometric enrollment changed. Unlock with your password and re-enable Face ID in settings."
        } catch is FaceIDUnavailableFailure {
            guard canFinishUnlock(generation) else { return }
            errorMessage = "Face ID is unavailable right now. Try again, or unlock with your password."
        } catch {
            guard canFinishUnlock(generation) else { return }
            errorMessage = "Face ID unlock failed. Try again, or unlock with your password."
        }
    }

    func loadSecuritySettings() async {
        guard let state = try? await attemptStore.loadChecked() else { errorMessage = "Security state unavailable. Unlock blocked."; return }
        unlockStatistics = state
        autoDestroyEnabled = state.autoDestroyEnabled
        autoDestroyThreshold = state.autoDestroyThreshold
        pinFailureThreshold = state.pinThreshold
        faceIDFailureThreshold = state.faceIDThreshold
        if AttemptPolicy.convenienceLockedOut(state: state) {
            pinEnabled = false
            faceIDEnabled = false
        }
    }

    func loadAuditEvents() async {
        guard let rootKey, phase == .unlocked else { return }
        let generation = sessionGeneration
        do {
            let events = try await store.readAudit(using: rootKey)
            // A lock may occur while decryption is suspended. Never repopulate
            // the model after that transition, and never retain legacy inputs.
            guard sessionGeneration == generation, phase == .unlocked, self.rootKey != nil else { return }
            auditEvents = events.reversed().map(\.metadataOnly)
        } catch VaultError.authenticatedIndexMismatch, VaultError.integrityFailure {
            guard sessionGeneration == generation, phase == .unlocked else { return }
            await completeAutoDestroy()
            if phase == .onboarding {
                destructionMessage = "Vault destroyed after confirmed, unrecoverable audit integrity failure."
            }
        } catch {
            guard sessionGeneration == generation, phase == .unlocked else { return }
            errorMessage = "Security Activity is unavailable."
        }
    }

    func eraseAuditEvents() async {
        guard let rootKey else { return }
        do {
            try await store.eraseAudit(using: rootKey)
            auditEvents = []
        } catch {
            errorMessage = "Could not erase Security Activity."
        }
    }

    func configureAuditLogging(_ enabled: Bool) async {
        guard !enabled else { return }
        auditEvents = []
        guard let rootKey else { return } // Next unlock retries cleanup.
        do {
            try await store.eraseAudit(using: rootKey)
        } catch {
            errorMessage = "Security Activity cleanup failed. It will retry on unlock."
        }
    }

    func configureAuditHistoryLimit(_ limit: Int) async {
        do {
            try await store.setAuditHistoryLimit(limit)
            if !auditEvents.isEmpty {
                await loadAuditEvents()
            }
        } catch {
            errorMessage = "Could not update Security Activity history."
        }
    }

    func configureAutoDestroy(enabled: Bool? = nil, threshold: Int? = nil) {
        Task {
            guard let state = try? await attemptStore.configureChecked({ state in
                if let enabled { state.autoDestroyEnabled = enabled }
                if let threshold { state.autoDestroyThreshold = threshold }
            }) else { errorMessage = "Security settings could not be saved."; return }
            autoDestroyEnabled = state.autoDestroyEnabled
            autoDestroyThreshold = state.autoDestroyThreshold
            unlockStatistics = state
            await store.appendAudit(AuditEvent(timestamp: Date(), method: .lifecycle,
                                               result: "auto-destroy-configured enabled=\(state.autoDestroyEnabled) threshold=\(state.autoDestroyThreshold)",
                                               enteredSecret: nil))
        }
    }

    func configureConvenienceThresholds(pin: Int? = nil, faceID: Int? = nil) {
        Task {
            guard let state = try? await attemptStore.configureChecked({ state in
                if let pin { state.pinThreshold = pin }
                if let faceID { state.faceIDThreshold = faceID }
            }) else { errorMessage = "Security settings could not be saved."; return }
            pinFailureThreshold = state.pinThreshold
            faceIDFailureThreshold = state.faceIDThreshold
        }
    }

    func loadStorageStatistics() async {
        guard let rootKey else { return }
        storageStatistics = try? await store.storageStatistics(using: rootKey)
    }

    func changeMasterPassword(_ password: String) async {
        guard let rootKey else { return }
        do {
            try await store.changePassword(password, using: rootKey)
            errorMessage = "Master password changed."
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func enablePIN(_ pin: String) {
        guard let rootKey else { return }
        guard (4...8).contains(pin.count), pin.allSatisfy(\.isNumber) else {
            errorMessage = "PIN must contain 4–8 digits."
            return
        }
        do {
            try ConvenienceUnlockStore.removeFaceIDChecked()
        } catch {
            errorMessage = "Face ID removal could not be verified. It may still be active; retry."
            return
        }
        faceIDEnabled = false
        do {
            try ConvenienceUnlockStore.configurePIN(pin, rootKey: rootKey)
            pinEnabled = true
            Task {
                await store.appendAudit(AuditEvent(timestamp: Date(), method: .lifecycle, result: "convenience-unlock-enabled pin", enteredSecret: nil))
            }
        } catch {
            pinEnabled = ConvenienceUnlockStore.hasPIN()
            errorMessage = "PIN setup failed. An old PIN may still be active; use your password and retry."
        }
    }

    func enableFaceID() async {
        guard let rootKey else { return }
        do {
            try ConvenienceUnlockStore.removePINChecked()
        } catch {
            errorMessage = "PIN removal could not be verified. It may still be active; retry."
            return
        }
        pinEnabled = false
        do {
            try ConvenienceUnlockStore.configureFaceID(rootKey)
            faceIDEnabled = true
            await store.appendAudit(AuditEvent(timestamp: Date(), method: .lifecycle, result: "convenience-unlock-enabled faceID", enteredSecret: nil))
        } catch {
            // A failed replacement may leave the previous biometric wrapper in Keychain.
            // Do not claim that it was removed or that password is the only method.
            errorMessage = "Face ID setup failed. An old Face ID key may still be active; use your password and retry."
        }
    }

    func disableConvenienceUnlock() {
        do {
            try ConvenienceUnlockStore.removeAllChecked()
            pinEnabled = false
            faceIDEnabled = false
            Task {
                await store.appendAudit(AuditEvent(timestamp: Date(), method: .lifecycle, result: "convenience-unlock-disabled", enteredSecret: nil))
            }
        } catch {
            errorMessage = "Convenience credentials could not be removed. Retry; they may still be active."
        }
    }

    func lock(reason: String? = nil) {
        sessionGeneration &+= 1
        BackgroundOperationCoordinator.shared.cancelCurrentOperation()
        webImportServer.stop()
        Task {
            await store.revokeAccess()
            await webImportServer.stopAndDrain()
        }
        rootKey = nil
        records = []
        auditEvents = []
        generatedPreviewIDs.removeAll()
        // An onboarding flow has no vault to protect. Keep it visible when the
        // app is backgrounded or privacy protection is triggered before the
        // first vault has been created. Cold-boot loading is the same: the
        // final phase is decided by load(), not by the scene transition.
        guard phase != .onboarding, phase != .loading else { return }
        phase = .locked
        if let reason {
            Task {
                await store.appendAudit(AuditEvent(timestamp: Date(), method: .lifecycle, result: "lock \(reason)", enteredSecret: nil))
            }
        }
    }

    private func completeAutoDestroy() async {
        guard !destructionInProgress else { return }
        destructionInProgress = true
        sessionGeneration &+= 1
        // A new vault must not inherit an earlier vault's audit opt-in.
        UserDefaults.standard.set(false, forKey: "auditLoggingEnabled")
        webImportServer.stop()
        WebImportBackgroundSession.shared.end()
        await store.revokeAccess()
        await webImportServer.stopAndDrain()
        await BackgroundOperationCoordinator.shared.cancelAndDrain()
        rootKey = nil
        records = []
        auditEvents = []
        generatedPreviewIDs.removeAll()
        // A restart must finish cleanup even if deletion was interrupted.
        UserDefaults.standard.set(true, forKey: "vaultDestructionPending")
        do {
            try await store.destroyVault()
            // Verify removal of all remaining wrappers and attempt state before
            // clearing the resumable destruction marker.
            try KeychainStore.deleteAllVaulthallaItems()
        } catch {
            errorMessage = "Vault destruction failed. Cleanup must be retried."
            destructionInProgress = false
            return
        }
        UserDefaults.standard.removeObject(forKey: "vaultDestructionPending")
        resetUnlockState()
        phase = .onboarding
        destructionInProgress = false
    }

    func destroyVault() async {
        await completeAutoDestroy()
    }

    /// Resets every in-memory unlock setting after a vault is destroyed.
    private func resetUnlockState() {
        pinEnabled = false
        faceIDEnabled = false
        unlockStatistics = AttemptState()
        autoDestroyEnabled = false
        autoDestroyThreshold = 5
        pinFailureThreshold = 5
        faceIDFailureThreshold = 3
        auditEvents = []
        storageStatistics = nil
        integrityState = "Not verified"
        lastVerifiedAt = nil
        importMessage = ""
        errorMessage = ""
    }
}

/// One-time migration: earlier versions staged USB files in an Import/
/// subfolder. The inbox is now the Documents root itself (that is where
/// Finder drops land), so move any leftovers out and delete the folder —
/// it only confused users.
/// Free function: runs off the main actor inside import tasks.
private func migrateLegacyInboxFolder() {
    let fileManager = FileManager.default
    guard let documents = fileManager.urls(for: .documentDirectory, in: .userDomainMask).first else { return }
    let inbox = documents.appendingPathComponent("Import", isDirectory: true)
    guard fileManager.fileExists(atPath: inbox.path) else { return }
    let urls = (try? fileManager.contentsOfDirectory(at: inbox, includingPropertiesForKeys: nil)) ?? []
    for url in urls {
        let destination = documents.appendingPathComponent(url.lastPathComponent)
        if fileManager.fileExists(atPath: destination.path) {
            try? fileManager.removeItem(at: url)
        } else {
            try? fileManager.moveItem(at: url, to: destination)
        }
    }
    try? fileManager.removeItem(at: inbox)
}

/// Supported media in the USB inbox (Documents root).
private func usbInboxURLs() -> [URL] {
    let fileManager = FileManager.default
    guard let documents = fileManager.urls(for: .documentDirectory, in: .userDomainMask).first else { return [] }
    let ok: Set<String> = ["jpg", "jpeg", "png", "gif", "heic", "heif", "mp4", "mov", "m4v"]
    let urls = (try? fileManager.contentsOfDirectory(at: documents, includingPropertiesForKeys: [.isRegularFileKey])) ?? []
    return urls
        .filter { (try? $0.resourceValues(forKeys: [.isRegularFileKey]))?.isRegularFile == true }
        .filter { ok.contains($0.pathExtension.lowercased()) }
        .sorted { $0.lastPathComponent.localizedStandardCompare($1.lastPathComponent) == .orderedAscending }
}

/// User-configurable grid columns: pinch the grid to change the count.
/// Pinch out (fingers apart) = fewer columns / bigger thumbnails;
/// pinch in (fingers together) = more columns / smaller thumbnails.
/// Per-orientation values persist across launches.
enum VaultGridColumns {
    static let portraitKey = "gridColumnsPortrait"
    static let landscapeKey = "gridColumnsLandscape"
    static let portraitDefault = 3
    static let landscapeDefault = 5
    static let minimum = 2
    static let maximum = 6
}

enum VaultUI {
    static let accent = Color(red: 0.10, green: 0.46, blue: 0.98)
    static let accentGradient = LinearGradient(
        colors: [Color(red: 0.12, green: 0.57, blue: 1.0), Color(red: 0.08, green: 0.30, blue: 0.92)],
        startPoint: .topLeading,
        endPoint: .bottomTrailing
    )
    static let cardRadius = 24.0
}

/// Neutral cold-boot screen shown while the vault state is being determined —
/// no onboarding or lock flash before load() finishes.
struct VaultLoadingView: View {
    var body: some View {
        ZStack {
            Color(uiColor: .systemGroupedBackground)
                .ignoresSafeArea()
            VaultBrandMark()
                .opacity(0.9)
        }
        .tint(VaultUI.accent)
    }
}

struct VaultBrandMark: View {
    var body: some View {
        Image("VaultMark")
            .resizable()
            .scaledToFit()
            .frame(width: 88, height: 88)
            .clipShape(RoundedRectangle(cornerRadius: 26, style: .continuous))
            .shadow(color: .black.opacity(0.22), radius: 18, y: 10)
            .accessibilityLabel("Vaulthalla")
    }
}

struct VaultPrimaryButtonStyle: ButtonStyle {
    @Environment(\.isEnabled) private var isEnabled

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.body.weight(.semibold))
            .foregroundStyle(isEnabled ? .white : .white.opacity(0.72))
            .padding(.horizontal, 18)
            .frame(minHeight: 50)
            .background(
                isEnabled
                    ? AnyShapeStyle(VaultUI.accentGradient)
                    : AnyShapeStyle(Color.white.opacity(0.18)),
                in: Capsule()
            )
            .overlay {
                Capsule()
                    .stroke(.white.opacity(isEnabled ? 0.12 : 0.08), lineWidth: 1)
            }
            .opacity(configuration.isPressed ? 0.82 : 1)
            .animation(.easeOut(duration: 0.15), value: configuration.isPressed)
    }
}

struct LockView: View {
    @Bindable var model: VaultAppModel
    @State private var showMasterPassword = false

    private var convenienceUnlockEnabled: Bool {
        model.pinEnabled || model.faceIDEnabled
    }

    var body: some View {
        NavigationStack {
            ZStack {
                Color(uiColor: .systemGroupedBackground)
                    .ignoresSafeArea()

                ScrollView {
                    VStack(alignment: .leading, spacing: 28) {
                        Spacer(minLength: 28)

                        VStack(alignment: .leading, spacing: 14) {
                            VaultBrandMark()
                            Text("Welcome back")
                                .font(.largeTitle.bold())
                                .tracking(-0.5)
                            Text("Your private library is protected and ready when you are.")
                                .font(.body)
                                .foregroundStyle(.secondary)
                        }

                        VStack(alignment: .leading, spacing: 18) {
                            // The enabled convenience method is the main, big action.
                            if model.faceIDEnabled {
                                Button {
                                    Task { await model.unlockWithFaceID() }
                                } label: {
                                    Label(model.isBusy ? "Unlocking…" : "Unlock with Face ID", systemImage: "faceid")
                                        .frame(maxWidth: .infinity)
                                }
                                .buttonStyle(VaultPrimaryButtonStyle())
                                .controlSize(.large)
                                .disabled(model.isBusy)
                                .accessibilityIdentifier("faceIDUnlockButton")
                            }

                            if model.pinEnabled {
                                VStack(alignment: .leading, spacing: 10) {
                                    Text("Enter your PIN")
                                        .font(.footnote.weight(.medium))
                                        .foregroundStyle(.secondary)
                                    SecureField("PIN", text: $model.pendingPIN)
                                        .keyboardType(.numberPad)
                                        .textContentType(.oneTimeCode)
                                        .font(.title3.weight(.medium))
                                        .multilineTextAlignment(.center)
                                        .padding(.horizontal, 14)
                                        .frame(maxWidth: .infinity, minHeight: 46)
                                        .background(.quaternary.opacity(0.45), in: RoundedRectangle(cornerRadius: 14, style: .continuous))
                                    Button {
                                        Task { await model.unlockWithPIN() }
                                    } label: {
                                        Label(model.isBusy ? "Unlocking…" : "Unlock with PIN", systemImage: "number")
                                            .frame(maxWidth: .infinity)
                                    }
                                    .buttonStyle(VaultPrimaryButtonStyle())
                                    .controlSize(.large)
                                    .disabled(model.isBusy || model.pendingPIN.isEmpty)
                                    .accessibilityIdentifier("pinUnlockButton")
                                }
                            }

                            if !convenienceUnlockEnabled {
                                // Password is the main action when no convenience method exists.
                                VStack(alignment: .leading, spacing: 10) {
                                    Text("Master password")
                                        .font(.footnote.weight(.medium))
                                        .foregroundStyle(.secondary)
                                    SecureField("Master password", text: $model.pendingPassword)
                                        .textContentType(.password)
                                        .textInputAutocapitalization(.never)
                                        .autocorrectionDisabled()
                                        .submitLabel(.go)
                                        .onSubmit {
                                            guard !model.pendingPassword.isEmpty else { return }
                                            Task { await model.unlock() }
                                        }
                                        .padding(.horizontal, 14)
                                        .frame(maxWidth: .infinity, minHeight: 46)
                                        .background(.quaternary.opacity(0.45), in: RoundedRectangle(cornerRadius: 14, style: .continuous))
                                        .accessibilityIdentifier("masterPasswordField")
                                    Button {
                                        Task { await model.unlock() }
                                    } label: {
                                        Label(model.isBusy ? "Unlocking…" : "Unlock", systemImage: "arrow.right")
                                            .frame(maxWidth: .infinity)
                                    }
                                    .buttonStyle(VaultPrimaryButtonStyle())
                                    .controlSize(.large)
                                    .disabled(model.isBusy || model.pendingPassword.isEmpty)
                                    .accessibilityIdentifier("unlockButton")
                                }
                            }

                            if convenienceUnlockEnabled {
                                // Password stays the smaller alternative below the main method.
                                if showMasterPassword {
                                    VStack(alignment: .leading, spacing: 12) {
                                        SecureField("Master password", text: $model.pendingPassword)
                                            .textContentType(.password)
                                            .textInputAutocapitalization(.never)
                                            .autocorrectionDisabled()
                                            .submitLabel(.go)
                                            .onSubmit {
                                                guard !model.pendingPassword.isEmpty else { return }
                                                Task { await model.unlock() }
                                            }
                                            .padding(.horizontal, 14)
                                            .frame(maxWidth: .infinity, minHeight: 46)
                                            .background(.quaternary.opacity(0.45), in: RoundedRectangle(cornerRadius: 14, style: .continuous))
                                            .accessibilityIdentifier("masterPasswordField")
                                        Button {
                                            Task { await model.unlock() }
                                        } label: {
                                            Label(model.isBusy ? "Unlocking…" : "Unlock", systemImage: "arrow.right")
                                                .frame(maxWidth: .infinity)
                                        }
                                        .buttonStyle(.bordered)
                                        .tint(VaultUI.accent)
                                        .disabled(model.isBusy || model.pendingPassword.isEmpty)
                                        .accessibilityIdentifier("unlockButton")
                                    }
                                    Button {
                                        showMasterPassword = false
                                    } label: {
                                        Label("Hide password", systemImage: "chevron.up")
                                            .font(.subheadline.weight(.medium))
                                            .foregroundStyle(.secondary)
                                    }
                                    .buttonStyle(.plain)
                                } else {
                                    Button {
                                        showMasterPassword = true
                                    } label: {
                                        Label("Unlock with password", systemImage: "key.fill")
                                            .font(.subheadline.weight(.medium))
                                            .foregroundStyle(.secondary)
                                    }
                                    .buttonStyle(.plain)
                                    .accessibilityIdentifier("useMasterPasswordButton")
                                }
                            }
                        }
                        .padding(20)
                        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: VaultUI.cardRadius, style: .continuous))

                        if model.isBusy {
                            HStack(spacing: 10) {
                                ProgressView()
                                Text("Unlocking your private library…")
                                    .font(.subheadline.weight(.medium))
                                    .foregroundStyle(.secondary)
                            }
                            .frame(maxWidth: .infinity, alignment: .center)
                            .padding(.vertical, 8)
                            .accessibilityIdentifier("unlockProgress")
                        }

                        if !model.errorMessage.isEmpty {
                            Label(model.errorMessage, systemImage: "exclamationmark.triangle.fill")
                                .font(.subheadline)
                                .foregroundStyle(.red)
                                .padding(.horizontal, 4)
                                .accessibilityIdentifier("unlockError")
                        }

                        Label("Your vault never leaves this device.", systemImage: "checkmark.shield.fill")
                            .font(.footnote.weight(.medium))
                            .foregroundStyle(.secondary)
                            .padding(.horizontal, 4)

                        Spacer(minLength: 24)
                    }
                    .padding(.horizontal, 24)
                }
            }
            .tint(VaultUI.accent)
            .toolbar(.hidden, for: .navigationBar)
        }
    }
}

struct OnboardingView: View {
    @Bindable var model: VaultAppModel
    /// Presentation state is mirrored into real @State and armed in onAppear.
    /// An .alert whose isPresented is already true when the view is installed
    /// is never presented until the next re-render (the "message only appears
    /// after I touch the password field" bug).
    @State private var showDestructionAlert = false
    @FocusState private var focusedField: OnboardingField?

    enum OnboardingField { case password, confirm }

    var body: some View {
        NavigationStack {
            ZStack {
                Color(uiColor: .systemGroupedBackground)
                    .ignoresSafeArea()

                ScrollView {
                    VStack(alignment: .leading, spacing: 24) {
                        VaultBrandMark()
                            .padding(.top, 12)

                        VStack(alignment: .leading, spacing: 8) {
                            Text("A private place for your memories")
                                .font(.largeTitle.bold())
                                .tracking(-0.5)
                            Text("Vaulthalla encrypts your library on this device. No account, no cloud, no recovery shortcut.")
                                .font(.body)
                                .foregroundStyle(.secondary)
                        }

                        VStack(alignment: .leading, spacing: 14) {
                            Label("Private by design", systemImage: "lock.shield.fill")
                                .font(.headline)
                            Text("Your media stays byte-for-byte unchanged while its encrypted copy is stored inside the vault.")
                                .font(.subheadline)
                                .foregroundStyle(.secondary)
                            Divider()
                            Label("One password. No recovery.", systemImage: "key.fill")
                                .font(.headline)
                            Text("Choose a password you can keep safe. Losing it permanently loses access to this vault.")
                                .font(.subheadline)
                                .foregroundStyle(.secondary)
                        }
                        .padding(20)
                        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: VaultUI.cardRadius, style: .continuous))

                        // Generous spacing and labelled fields: the two password
                        // inputs are easy to distinguish and easy to tap.
                        VStack(alignment: .leading, spacing: 20) {
                            Text("Create your vault")
                                .font(.title2.bold())

                            VStack(alignment: .leading, spacing: 7) {
                                Text("Master password")
                                    .font(.footnote.weight(.medium))
                                    .foregroundStyle(.secondary)
                                SecureField("Master password", text: $model.pendingPassword)
                                    .focused($focusedField, equals: .password)
                                    .submitLabel(.next)
                                    .onSubmit { focusedField = .confirm }
                                    .textInputAutocapitalization(.never)
                                    .autocorrectionDisabled()
                                    .padding(.horizontal, 14)
                                    .frame(maxWidth: .infinity, minHeight: 46)
                                    .background(.quaternary.opacity(0.45), in: RoundedRectangle(cornerRadius: 14, style: .continuous))
                                    .accessibilityIdentifier("createPasswordField")
                            }

                            VStack(alignment: .leading, spacing: 7) {
                                Text("Confirm password")
                                    .font(.footnote.weight(.medium))
                                    .foregroundStyle(.secondary)
                                SecureField("Confirm password", text: $model.confirmPassword)
                                    .focused($focusedField, equals: .confirm)
                                    .submitLabel(.done)
                                    .onSubmit { focusedField = nil }
                                    .textInputAutocapitalization(.never)
                                    .autocorrectionDisabled()
                                    .padding(.horizontal, 14)
                                    .frame(maxWidth: .infinity, minHeight: 46)
                                    .background(.quaternary.opacity(0.45), in: RoundedRectangle(cornerRadius: 14, style: .continuous))
                                    .accessibilityIdentifier("confirmPasswordField")
                            }

                            PasswordStrengthView(password: model.pendingPassword)

                            Picker("Vault capacity", selection: $model.selectedSegment) {
                                ForEach(SegmentCapacity.allCases) { capacity in
                                    Text(capacity.title).tag(capacity)
                                }
                            }

                            if !model.errorMessage.isEmpty {
                                Label(model.errorMessage, systemImage: "exclamationmark.triangle.fill")
                                    .font(.subheadline)
                                    .foregroundStyle(.red)
                            }

                            Button {
                                Task { await model.createVault() }
                            } label: {
                                Label(model.isBusy ? "Creating…" : "Create vault", systemImage: "lock.open.fill")
                                    .frame(maxWidth: .infinity)
                            }
                            .buttonStyle(VaultPrimaryButtonStyle())
                            .controlSize(.large)
                            .disabled(model.isBusy || model.pendingPassword.count < VaultConstants.minimumPasswordLength)
                            .accessibilityIdentifier("createVaultButton")
                        }
                        .padding(20)
                        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: VaultUI.cardRadius, style: .continuous))

                        Text("You can change storage maintenance options later in Settings.")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                            .padding(.horizontal, 4)
                    }
                    .padding(.horizontal, 24)
                    .padding(.bottom, 32)
                }
            }
            .tint(VaultUI.accent)
            .toolbar(.hidden, for: .navigationBar)
            .onAppear {
                showDestructionAlert = !model.destructionMessage.isEmpty
            }
            .onChange(of: model.destructionMessage) { _, message in
                showDestructionAlert = !message.isEmpty
            }
            .alert("Vault destroyed", isPresented: $showDestructionAlert) {
                Button("OK") {
                    showDestructionAlert = false
                    model.destructionMessage = ""
                }
            } message: {
                Text(model.destructionMessage)
            }
        }
    }
}

struct PasswordStrengthView: View {
    let password: String

    var body: some View {
        let score = min(4, max(0, password.count / 4))
        VStack(alignment: .leading, spacing: 6) {
            Text("Password strength")
            ProgressView(value: Double(score), total: 4)
                .tint(score < 2 ? .red : score < 3 ? .orange : .green)
            Text(score < 2 ? "Consider a longer password." : "Strength is advice, not a requirement.")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }
}

struct MainVaultView: View {
    @Bindable var model: VaultAppModel

    var body: some View {
        GeometryReader { geometry in
            TabView(selection: $model.selectedTab) {
                MediaLibraryView(title: "Images", systemImage: "photo.on.rectangle", emptyMessage: "Import photos to see them here.", model: model, topInset: geometry.safeAreaInsets.top)
                    .tag(0)
                MediaLibraryView(title: "Videos", systemImage: "video", emptyMessage: "Import videos to see them here.", model: model, topInset: geometry.safeAreaInsets.top)
                    .tag(1)
                SettingsView(model: model, topInset: geometry.safeAreaInsets.top)
                    .tag(2)
            }
            .tabViewStyle(.page(indexDisplayMode: .never))
            .toolbarBackground(.hidden, for: .navigationBar)
            // The page container itself must reach the status bar. Extending
            // only a background or a nested ScrollView leaves a black strip.
            .ignoresSafeArea(.container, edges: [.top, .bottom])
            .overlay(alignment: .bottom) {
                HStack(spacing: 0) {
                    tabButton(title: "Images", systemImage: "photo.on.rectangle", tag: 0)
                    tabButton(title: "Videos", systemImage: "video", tag: 1)
                    tabButton(title: "Settings", systemImage: "gearshape", tag: 2)
                }
                .fixedSize(horizontal: true, vertical: false)
                .padding(.vertical, 8)
                .padding(.horizontal, 6)
                .glassEffect(.regular, in: .rect(cornerRadius: 24))
                .padding(.bottom, 2)
                .offset(y: 10)
            }
            .tint(VaultUI.accent)
        }
        .background {
            // Only the background extends beneath the status bar and Dynamic Island.
            // Controls remain in the safe area instead of being clipped by the cutout.
            Color(uiColor: .systemGroupedBackground).ignoresSafeArea(.container, edges: .top)
        }
    }

    private func tabButton(title: String, systemImage: String, tag: Int) -> some View {
        Button {
            withAnimation(.easeInOut(duration: 0.25)) {
                model.selectedTab = tag
            }
        } label: {
            VStack(spacing: 3) {
                Image(systemName: systemImage)
                    .font(.system(size: 20))
                Text(title)
                    .font(.caption2)
            }
            .foregroundStyle(model.selectedTab == tag ? .white : .white.opacity(0.6))
            .frame(width: 72)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        // Keep the icon stable while the page itself animates on a button tap.
        .transaction { $0.animation = nil }
        .accessibilityAddTraits(model.selectedTab == tag ? .isSelected : [])
    }
}

struct GroupTileView: View {
    let group: MediaGroup
    @Bindable var model: VaultAppModel
    @State private var image: UIImage?

    private var cover: MediaRecord? { group.items.first }

    var body: some View {
        // Frame forced by a shape with no intrinsic size (see MediaTile):
        // every group tile is exactly 3:4 regardless of the source ratio.
        Color.clear
            .aspectRatio(3.0 / 4.0, contentMode: .fit)
            .overlay {
                if let image {
                    Image(uiImage: image)
                        .resizable()
                        .scaledToFill()
                } else {
                    Rectangle().fill(.quaternary)
                        .overlay {
                            Image(systemName: cover?.mimeType.hasPrefix("video/") == true ? "video.fill" : group.isUngrouped ? "tray.fill" : "rectangle.stack.fill")
                                .font(.system(size: 30, weight: .semibold))
                                .foregroundStyle(.secondary)
                        }
                }
            }
            .clipped()
            .clipShape(RoundedRectangle(cornerRadius: 20, style: .continuous))
        .overlay(alignment: .bottom) {
            // Title and counter on one line inside the thumbnail, near the bottom:
            // title aligned left, counter aligned right.
            HStack(spacing: 8) {
                Text(group.displayName)
                    .font(.subheadline.weight(.semibold))
                    .foregroundStyle(.white)
                    .lineLimit(1)
                    .truncationMode(.tail)
                Spacer(minLength: 8)
                Text("\(group.items.count)")
                    .font(.caption2.weight(.bold))
                    .foregroundStyle(.primary)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 5)
                    .background(.regularMaterial, in: Capsule())
            }
            .padding(.horizontal, 12)
            .padding(.top, 26)
            .padding(.bottom, 10)
            .frame(maxWidth: .infinity)
            .background(
                LinearGradient(
                    colors: [.black.opacity(0.62), .black.opacity(0.28), .clear],
                    startPoint: .bottom,
                    endPoint: .top
                )
            )
            .allowsHitTesting(false)
        }
        .clipShape(RoundedRectangle(cornerRadius: 20, style: .continuous))
        .task(id: cover?.id) {
            guard let cover else { return }
            if let data = await model.preview(for: cover) {
                image = UIImage(data: data)
            }
        }
    }
}

struct GroupRowView: View {
    let group: MediaGroup

    var body: some View {
        HStack(spacing: 14) {
            Image(systemName: group.isUngrouped ? "tray.fill" : "rectangle.stack.fill")
                .font(.title3.weight(.semibold))
                .foregroundStyle(VaultUI.accent)
                .frame(width: 42, height: 42)
                .background(VaultUI.accent.opacity(0.12), in: RoundedRectangle(cornerRadius: 13, style: .continuous))

            VStack(alignment: .leading, spacing: 3) {
                Text(group.displayName)
                    .font(.body.weight(.semibold))
                Text("\(group.items.count) " + (group.items.count == 1 ? "item" : "items"))
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }

            Spacer()
        }
        .padding(.vertical, 6)
    }
}

struct EmptyLibraryView: View {
    let title: String
    let systemImage: String
    let message: String
    let action: () -> Void

    var body: some View {
        ContentUnavailableView {
            Label(title, systemImage: systemImage)
        } description: {
            Text(message)
        } actions: {
            Button("Import", systemImage: "plus", action: action)
                .buttonStyle(.borderedProminent)
        }
    }
}

struct ImportOptionsSheet: View {
    let mediaTitle: String
    @Binding var deleteOriginals: Bool
    var usbInboxCount: Int = 0
    let importPhotos: () -> Void
    let importFiles: () -> Void
    let importWiFi: () -> Void
    let importCable: () -> Void
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            VStack(spacing: 12) {
                ImportOptionRow(
                    title: "Import from Photos",
                    systemImage: "photo.on.rectangle.angled",
                    tint: VaultUI.accent,
                    action: {
                        dismiss()
                        importPhotos()
                    }
                )
                ImportOptionRow(
                    title: "Import from Files",
                    systemImage: "folder",
                    tint: VaultUI.accent,
                    action: {
                        dismiss()
                        importFiles()
                    }
                )
                ImportOptionRow(
                    title: "Import by Wi-Fi",
                    systemImage: "wifi",
                    tint: VaultUI.accent,
                    action: {
                        dismiss()
                        importWiFi()
                    }
                )
                ImportOptionRow(
                    title: "Import by Cable",
                    systemImage: "cable.connector",
                    tint: VaultUI.accent,
                    badge: usbInboxCount > 0 ? "\(usbInboxCount)" : nil,
                    identifier: "importCableButton",
                    action: {
                        dismiss()
                        importCable()
                    }
                )

                Divider()
                    .padding(.vertical, 4)

                Toggle("Delete originals after successful import", isOn: $deleteOriginals)
                    .font(.body.weight(.medium))
                    .foregroundStyle(.white)
                    .tint(.white)
                    .padding(.horizontal, 16)
                    .padding(.vertical, 14)
                    .glassEffect(.regular, in: .rect(cornerRadius: 18))
            }
            .padding(20)
            .navigationTitle("Import")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Done") { dismiss() }
                        .foregroundStyle(.white)
                }
            }
            .toolbarColorScheme(.dark, for: .navigationBar)
            .tint(.white)
        }
        .presentationDetents([.medium])
        .presentationDragIndicator(.visible)
        .preferredColorScheme(.dark)
    }
}

struct ImportOptionRow: View {
    let title: String
    let systemImage: String
    let tint: Color
    var badge: String? = nil
    var identifier: String = ""
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 14) {
                Image(systemName: systemImage)
                    .font(.title3.weight(.semibold))
                    .foregroundStyle(.white)
                    .frame(width: 28)

                Text(title)
                    .font(.body.weight(.semibold))
                    .foregroundStyle(.white)

                Spacer()

                if let badge {
                    Text(badge)
                        .font(.caption.weight(.bold))
                        .foregroundStyle(.white)
                        .padding(.horizontal, 8)
                        .padding(.vertical, 3)
                        .background(tint, in: Capsule())
                }

                Image(systemName: "chevron.right")
                    .font(.footnote.weight(.bold))
                    .foregroundStyle(.white.opacity(0.7))
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 15)
            .glassEffect(.regular.interactive(), in: .rect(cornerRadius: 18))
        }
        .buttonStyle(.plain)
        .accessibilityIdentifier(identifier)
    }
}

struct MediaLibraryView: View {
    let title: String
    let systemImage: String
    let emptyMessage: String
    @Bindable var model: VaultAppModel
    var topInset: CGFloat = 0
    @State private var showImporter = false
    @State private var groupLongPressAt: TimeInterval = 0
    @State private var showImportOptions = false
    @State private var showPhotosPicker = false
    @State private var showWebImport = false
    @State private var photosSelection: [PhotosPickerItem] = []
    @State private var deleteOriginals = true
    @State private var selectedGroupIDs = Set<String>()
    @State private var showGroupDeleteConfirmation = false
    @State private var selectionMode = false
    @State private var path: [String] = []

    @AppStorage(VaultGridColumns.portraitKey) private var portraitColumns = VaultGridColumns.portraitDefault
    @AppStorage(VaultGridColumns.landscapeKey) private var landscapeColumns = VaultGridColumns.landscapeDefault
    @State private var isLandscape = false

    private var columns: [GridItem] {
        let count = isLandscape ? landscapeColumns : portraitColumns
        return Array(repeating: GridItem(.flexible(), spacing: 10), count: count)
    }

    /// Pinch out = fewer columns (bigger thumbs); pinch in = more columns.
    private var columnPinch: some Gesture {
        MagnifyGesture()
            .onEnded { value in
                if value.magnification > 1.1 {
                    if isLandscape { landscapeColumns = max(VaultGridColumns.minimum, landscapeColumns - 1) }
                    else { portraitColumns = max(VaultGridColumns.minimum, portraitColumns - 1) }
                } else if value.magnification < 0.9 {
                    if isLandscape { landscapeColumns = min(VaultGridColumns.maximum, landscapeColumns + 1) }
                    else { portraitColumns = min(VaultGridColumns.maximum, portraitColumns + 1) }
                }
            }
    }


    private var groups: [MediaGroup] {
        GroupingEngine.groups(
            from: model.records,
            mediaPrefix: title == "Images" ? "image/" : "video/"
        )
    }

    private func group(id: String) -> MediaGroup? {
        groups.first { $0.id == id }
    }


    var body: some View {
        NavigationStack(path: $path) {
            Group {
                if groups.isEmpty {
                    EmptyLibraryView(
                        title: title,
                        systemImage: systemImage,
                        message: emptyMessage,
                        action: { showImportOptions = true }
                    )
                } else if model.importProgress.isRunning {
                    ImportProgressCard(model: model)
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                        .background(Color(.systemBackground))
                } else {
                    GeometryReader { proxy in
                        ScrollView {
                            LazyVGrid(columns: columns, spacing: 10) {
                                ForEach(groups) { group in
                                    groupTile(for: group)
                                }
                            }
                            .padding(16)
                        }
                        .contentMargins(.top, topInset, for: .scrollContent)
                        .ignoresSafeArea(.container, edges: .top)
                        .scrollClipDisabled()
                        .simultaneousGesture(columnPinch)
                        .onAppear { isLandscape = proxy.size.width > proxy.size.height }
                        .onChange(of: proxy.size) { _, newSize in
                            isLandscape = newSize.width > newSize.height
                        }
                    }
                }
            }
            .scrollContentBackground(.hidden)
            .toolbarBackground(.hidden, for: .navigationBar)
            .background(Color(uiColor: .systemGroupedBackground).ignoresSafeArea(.container, edges: .top))
            .navigationDestination(for: String.self) { id in
                if let group = group(id: id) {
                    GroupDetailView(group: group, model: model, topInset: topInset)
                }
            }
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    if selectionMode {
                        HStack(spacing: 18) {
                            Button("Cancel") {
                                selectionMode = false
                                selectedGroupIDs.removeAll()
                            }
                            .font(.subheadline.weight(.medium))
                            Button("Delete", role: .destructive) {
                                showGroupDeleteConfirmation = true
                            }
                            .disabled(selectedGroupIDs.isEmpty)
                        }
                    } else {
                        Menu {
                            Button("Import", systemImage: "plus") {
                                showImportOptions = true
                            }
                            .accessibilityIdentifier("menuImportButton")
                        } label: {
                            Image(systemName: "ellipsis.circle")
                                .foregroundStyle(.white)
                                .accessibilityIdentifier("moreMenuButton")
                        }
                        .environment(\.colorScheme, .dark)
                        .tint(.white)
                    }
                }
            }
            .confirmationDialog(
                "Delete selected groups?",
                isPresented: $showGroupDeleteConfirmation,
                titleVisibility: .visible
            ) {
                Button("Delete", role: .destructive) {
                    let ids = selectedGroupIDs
                    Task {
                        let records = groups.filter { ids.contains($0.id) }.flatMap(\.items)
                        await model.delete(Set(records.map(\.id)))
                        selectedGroupIDs.removeAll()
                        selectionMode = false
                    }
                }
                Button("Cancel", role: .cancel) {}
            }
            .sheet(isPresented: $showImportOptions) {
                ImportOptionsSheet(
                    mediaTitle: title,
                    deleteOriginals: $deleteOriginals,
                    usbInboxCount: model.usbInboxWaitingCount,
                    importPhotos: { showPhotosPicker = true },
                    importFiles: { showImporter = true },
                    importWiFi: { showWebImport = true },
                    importCable: {
                        model.scheduleImportUSBInbox(deleteOriginals: deleteOriginals)
                    }
                )
            }
            .photosPicker(
                isPresented: $showPhotosPicker,
                selection: $photosSelection,
                maxSelectionCount: nil,
                matching: title == "Images" ? .images : .videos,
                photoLibrary: PHPhotoLibrary.shared()
            )
            .sheet(isPresented: $showWebImport) {
                WebImportView(model: model)
            }
            .onChange(of: photosSelection) { _, selection in
                guard !selection.isEmpty else { return }
                model.scheduleImportPhotos(selection, deleteOriginals: deleteOriginals)
                photosSelection = []
            }
            .fileImporter(
                isPresented: $showImporter,
                allowedContentTypes: title == "Images" ? [.image] : [.movie],
                allowsMultipleSelection: true
            ) { result in
                if case .success(let urls) = result {
                    model.scheduleImportFiles(urls, deleteOriginals: deleteOriginals)
                }
            }
            .overlay(alignment: .bottom) {
                if !model.importMessage.isEmpty {
                    Text(model.importMessage)
                        .font(.footnote)
                        .padding()
                        .background(.thinMaterial, in: Capsule())
                        .padding()
                }
            }
        }
    }

    /// Group tiles: in selection mode a tap toggles the accented top-right
    /// toggle; otherwise a long press enters selection mode and a tap opens
    /// the group. Selection is a toggle on the thumbnail, not a separate screen.
    @ViewBuilder
    private func groupTile(for group: MediaGroup) -> some View {
        let selected = selectedGroupIDs.contains(group.id)
        if selectionMode {
            Button {
                if selected {
                    selectedGroupIDs.remove(group.id)
                } else {
                    selectedGroupIDs.insert(group.id)
                }
            } label: {
                GroupTileView(group: group, model: model)
            }
            .buttonStyle(.plain)
            .overlay(alignment: .topTrailing) {
                Image(systemName: selected ? "checkmark.circle.fill" : "circle")
                    .font(.title3.weight(.bold))
                    .symbolRenderingMode(.hierarchical)
                    .foregroundStyle(selected ? VaultUI.accent : .white)
                    .padding(7)
                    .background(.black.opacity(0.35), in: Circle())
                    .padding(8)
            }
            .accessibilityIdentifier("group-\(group.id)")
        } else {
            // Plain view (not a Button): a Button swallows long-presses,
            // which broke "long-press = select mode" on groups.
            GroupTileView(group: group, model: model)
                .contentShape(Rectangle())
                .onTapGesture {
                    // Same stray-tap-after-long-press guard as MediaTile.
                    if Date().timeIntervalSinceReferenceDate - groupLongPressAt < 0.4 { return }
                    path.append(group.id)
                }
                .simultaneousGesture(
                    LongPressGesture(minimumDuration: 0.35)
                        .onEnded { _ in
                            groupLongPressAt = Date().timeIntervalSinceReferenceDate
                            selectionMode = true
                            selectedGroupIDs = [group.id]
                        }
                )
                .accessibilityIdentifier("group-\(group.id)")
                .accessibilityAddTraits(.isButton)
        }
    }
}

/// §17 — Apple-style live import card: overall percent, current item, byte counters, Pause/Resume, Cancel.
struct ImportProgressCard: View {
    var model: VaultAppModel

    private var progressBytesText: String {
        let p = model.importProgress
        let done = ByteCountFormatter.string(fromByteCount: p.processedBytes, countStyle: .memory)
        if p.totalBytes > 0 {
            let total = ByteCountFormatter.string(fromByteCount: p.totalBytes, countStyle: .memory)
            return "\(done) of \(total)"
        }
        return done
    }

    var body: some View {
        let p = model.importProgress
        VStack(alignment: .leading, spacing: 14) {
            HStack(spacing: 10) {
                if p.isPaused {
                    Image(systemName: "pause.circle.fill")
                        .font(.title2)
                        .foregroundStyle(.orange)
                } else {
                    ProgressView()
                        .tint(VaultUI.accent)
                }
                Text(p.isPaused ? "Import paused" : "Importing…")
                    .font(.headline)
            }

            Group {
                if let percent = p.percent {
                    ProgressView(value: percent)
                        .tint(VaultUI.accent)
                } else {
                    ProgressView()
                        .tint(VaultUI.accent)
                }
            }

            if p.total > 0 {
                Text("Item \(min(p.completed + 1, p.total)) of \(p.total)")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }
            if !p.currentFilename.isEmpty {
                Text(p.currentFilename)
                    .font(.footnote)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
            Text(progressBytesText)
                .font(.footnote)
                .foregroundStyle(.secondary)

            HStack(spacing: 12) {
                Button(p.isPaused ? "Resume" : "Pause") {
                    if p.isPaused { model.resumeImport() } else { model.pauseImport() }
                }
                .buttonStyle(.bordered)

                Button("Cancel", role: .destructive) {
                    model.cancelCurrentOperation()
                }
                .buttonStyle(.bordered)
            }
        }
        .padding(24)
        .frame(width: 300)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 20, style: .continuous))
    }
}

struct GroupDetailView: View {
    let group: MediaGroup
    @Bindable var model: VaultAppModel
    var topInset: CGFloat = 0
    @State private var selectedIDs = Set<UUID>()
    @State private var selectionMode = false
    @State private var showDeleteConfirmation = false
    @State private var showSlideshow = false
    @State private var isLandscape = false
    @AppStorage(VaultGridColumns.portraitKey) private var portraitColumns = VaultGridColumns.portraitDefault
    @AppStorage(VaultGridColumns.landscapeKey) private var landscapeColumns = VaultGridColumns.landscapeDefault

    private var columns: [GridItem] {
        let count = isLandscape ? landscapeColumns : portraitColumns
        return Array(repeating: GridItem(.flexible(), spacing: 2), count: count)
    }

    /// Pinch out = fewer columns (bigger thumbs); pinch in = more columns.
    private var columnPinch: some Gesture {
        MagnifyGesture()
            .onEnded { value in
                if value.magnification > 1.1 {
                    if isLandscape { landscapeColumns = max(VaultGridColumns.minimum, landscapeColumns - 1) }
                    else { portraitColumns = max(VaultGridColumns.minimum, portraitColumns - 1) }
                } else if value.magnification < 0.9 {
                    if isLandscape { landscapeColumns = min(VaultGridColumns.maximum, landscapeColumns + 1) }
                    else { portraitColumns = min(VaultGridColumns.maximum, portraitColumns + 1) }
                }
            }
    }

    var body: some View {
        GeometryReader { proxy in
            ScrollView {
                LazyVGrid(columns: columns, spacing: 2) {
                    ForEach(group.items) { record in
                        mediaTile(for: record)
                    }
                }
                .padding(2)
            }
            .contentMargins(.top, topInset, for: .scrollContent)
            .ignoresSafeArea(.container, edges: .top)
            .scrollClipDisabled()
            .simultaneousGesture(columnPinch)
            .onAppear { isLandscape = proxy.size.width > proxy.size.height }
            .onChange(of: proxy.size) { _, newSize in
                isLandscape = newSize.width > newSize.height
            }
            // Registered once on the screen (per-tile registration drew one
            // menu button per tile).
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    if !selectionMode {
                        Menu {
                            // Slideshow runs inside the viewer, starting from
                            // the first item — never a separate slideshow screen.
                            Button("Slideshow", systemImage: "play.rectangle") { showSlideshow = true }
                                .accessibilityIdentifier("menuSlideshowButton")
                            Button("Select all", systemImage: "checkmark.circle") {
                                selectionMode = true
                                selectedIDs = Set(group.items.map(\.id))
                            }
                            .accessibilityIdentifier("menuSelectAllButton")
                        } label: {
                            Image(systemName: "ellipsis.circle")
                                .foregroundStyle(.white)
                                .accessibilityIdentifier("groupMoreMenuButton")
                        }
                        .environment(\.colorScheme, .dark)
                        .tint(.white)
                    } else {
                        HStack(spacing: 4) {
                            Text("\(selectedIDs.count) selected")
                                .font(.subheadline)
                                .foregroundStyle(.secondary)
                            Button("Cancel") {
                                selectionMode = false
                                selectedIDs.removeAll()
                            }
                            Button("Delete", role: .destructive) { showDeleteConfirmation = true }
                        }
                    }
                }
            }
            .fullScreenCover(isPresented: $showSlideshow) {
                MediaViewer(
                    group: group,
                    startIndex: 0,
                    model: model,
                    autoSlideshow: true
                )
            }
            .confirmationDialog(
                "Delete selected media?",
                isPresented: $showDeleteConfirmation,
                titleVisibility: .visible
            ) {
                Button("Delete", role: .destructive) {
                    Task {
                        await model.delete(selectedIDs)
                        selectedIDs.removeAll()
                    }
                }
                Button("Cancel", role: .cancel) {}
            }
        }
    }

    private func mediaTile(for record: MediaRecord) -> some View {
        MediaTile(
            record: record,
            group: group,
            model: model,
            isSelected: selectedIDs.contains(record.id),
            onTap: {
                if selectionMode {
                    if selectedIDs.contains(record.id) {
                        selectedIDs.remove(record.id)
                    } else {
                        selectedIDs.insert(record.id)
                    }
                }
            },
            selectionMode: selectionMode,
            onLongPress: {
                selectionMode = true
                selectedIDs = [record.id]
            }
        )
        .overlay(alignment: .topTrailing) {
            if !selectedIDs.isEmpty {
                Image(systemName: selectedIDs.contains(record.id) ? "checkmark.circle.fill" : "circle")
                    .padding(8)
                    .foregroundStyle(selectedIDs.contains(record.id) ? .blue : .white)
            }
        }
    }

}
struct MediaTile: View {
    let record: MediaRecord
    let group: MediaGroup
    @Bindable var model: VaultAppModel
    let isSelected: Bool
    let onTap: () -> Void
    var selectionMode: Bool = false
    var onLongPress: (() -> Void)? = nil
    @State private var image: UIImage?
    @State private var showViewer = false
    @State private var longPressAt: TimeInterval = 0

    var body: some View {
        // A plain view (not a Button): a Button's own touch handling swallows
        // long-presses, which broke the "long-press = select mode" interaction.
        tile
            .contentShape(Rectangle())
            .onTapGesture {
                // A long-press ends with a touch-up that SwiftUI also reports
                // as a tap; that stray tap used to deselect the tile instantly
                // (bug: "long-press select doesn't work"). Ignore taps that
                // follow a long-press.
                if Date().timeIntervalSinceReferenceDate - longPressAt < 0.4 { return }
                // In select mode a tap always toggles the selection — it never
                // opens the viewer (bug: second thumb opened the photo).
                if selectionMode || isSelected {
                    onTap()
                } else {
                    showViewer = true
                }
            }
            // simultaneousGesture: an onLongPressGesture chained after
            // onTapGesture loses the touch race and never fires; a
            // simultaneous long-press is recognized independently.
            .simultaneousGesture(
                LongPressGesture(minimumDuration: 0.35)
                    .onEnded { _ in
                        longPressAt = Date().timeIntervalSinceReferenceDate
                        onLongPress?()
                    }
            )
            .accessibilityIdentifier("media-\(record.id)")
            .accessibilityAddTraits(.isButton)
        .fullScreenCover(isPresented: $showViewer) {
            MediaViewer(
                group: group,
                startIndex: group.items.firstIndex { $0.id == record.id } ?? 0,
                model: model
            )
        }
        .task {
            if let data = await model.preview(for: record) {
                image = UIImage(data: data)
            }
        }
        .accessibilityLabel(record.filename)
        .accessibilityValue(record.mimeType.hasPrefix("video/") ? "Video" : "Photo")
    }

    /// The tile face. The frame is forced by a shape with no intrinsic size.
    /// An Image inside a ZStack leaks its native pixel ratio into the tile
    /// size (bug: non-uniform grid), so the image only ever fills a fixed
    /// 3:4 frame, center-cropped.
    private var tile: some View {
        Color.clear
            .aspectRatio(3.0 / 4.0, contentMode: .fit)
            .overlay {
                if let image {
                    Image(uiImage: image)
                        .resizable()
                        .scaledToFill()
                } else {
                    Rectangle().fill(.quaternary)
                        .overlay {
                            Image(systemName: record.mimeType.hasPrefix("video/") ? "play.circle" : "photo")
                                .font(.title2)
                                .foregroundStyle(.secondary)
                        }
                }
            }
            .clipped()
            .clipShape(RoundedRectangle(cornerRadius: 4, style: .continuous))
            .overlay(alignment: .bottomTrailing) {
                if record.mimeType.hasPrefix("video/") {
                    Image(systemName: "play.fill")
                        .font(.system(size: 9, weight: .bold))
                        .foregroundStyle(.white)
                        .padding(5)
                        .background(.black.opacity(0.55), in: Circle())
                        .padding(6)
                }
            }
            .overlay {
                if isSelected {
                    RoundedRectangle(cornerRadius: 4, style: .continuous)
                        .fill(.blue.opacity(0.25))
                        .overlay {
                            RoundedRectangle(cornerRadius: 4, style: .continuous)
                                .stroke(.blue, lineWidth: 3)
                        }
                }
            }
    }
}

/// AVPlayerLayer-backed surface so the viewer owns the chrome (Apple-style on-demand controls).
private final class PlayerSurfaceView: UIView {
    override static var layerClass: AnyClass { AVPlayerLayer.self }
    var playerLayer: AVPlayerLayer { layer as! AVPlayerLayer }
    private var readinessObservation: NSKeyValueObservation?

    func watchFirstFrame(_ onReady: @escaping @MainActor () -> Void) {
        readinessObservation?.invalidate()
        readinessObservation = playerLayer.observe(\.isReadyForDisplay, options: [.initial, .new]) { layer, _ in
            guard layer.isReadyForDisplay else { return }
            Task { @MainActor in onReady() }
        }
    }
}

private struct VaultPlayerSurface: UIViewRepresentable {
    let player: AVPlayer
    var fillMode: Bool
    var onFirstFrame: (@MainActor () -> Void)? = nil

    func makeUIView(context: Context) -> PlayerSurfaceView {
        let view = PlayerSurfaceView()
        view.backgroundColor = .black
        view.playerLayer.player = player
        view.playerLayer.videoGravity = fillMode ? .resizeAspectFill : .resizeAspect
        if let onFirstFrame { view.watchFirstFrame(onFirstFrame) }
        return view
    }

    func updateUIView(_ uiView: PlayerSurfaceView, context: Context) {
        if uiView.playerLayer.player !== player {
            uiView.playerLayer.player = player
            if let onFirstFrame { uiView.watchFirstFrame(onFirstFrame) }
        }
        uiView.playerLayer.videoGravity = fillMode ? .resizeAspectFill : .resizeAspect
    }
}

private func vaultTimeCode(_ time: Double) -> String {
    guard time.isFinite, time >= 0 else { return "0:00" }
    let t = Int(time)
    return String(format: "%d:%02d", t / 60, t % 60)
}

struct MediaViewer: View {
    let group: MediaGroup
    @Bindable var model: VaultAppModel
    var autoSlideshow: Bool = false
    @Environment(\.dismiss) private var dismiss
    @State private var currentIndex: Int
    @State private var showChrome = false
    @State private var showInfo = false
    @State private var slideshowActive = false
    @State private var zoomScale: CGFloat = 1.0
    @State private var panOffset: CGSize = .zero
    @State private var videoZoomScale: CGFloat = 1.0
    @State private var videoPanOffset: CGSize = .zero
    @State private var videoBaseZoom: CGFloat = 0
    @State private var videoPinchStartPan: CGSize = .zero
    @State private var videoPinchAnchor: CGPoint = .zero
    @State private var isVideoPanning = false
    @State private var videoPanStart: CGSize = .zero
    @State private var dragPanStart: CGSize = .zero
    @State private var isPanning = false
    @State private var baseZoom: CGFloat = 0
    @State private var pinchStartPan: CGSize = .zero
    @State private var pinchAnchor: CGPoint = .zero
    @State private var pageOffset: CGFloat = 0
    @State private var isPageTransitioning = false
    @State private var pendingImageTarget: Int?
    @State private var viewportSize: CGSize = .zero
    @State private var currentItemImage: UIImage?
    @State private var userZoomTouched = false
    @State private var zoomModeOverride: Bool?
    @State private var isDoubleTapAnimating = false
    @State private var isPlaying = false
    @State private var isScrubbing = false
    @State private var isMuted = false
    @State private var currentTime: Double = 0
    @State private var duration: Double = 0
    @State private var chromeHideTask: Task<Void, Never>?
    @State private var timeTask: Task<Void, Never>?
    @State private var slideTask: Task<Void, Never>?
    @AppStorage("imageFillMode") private var fillMode = false
    @AppStorage("videoFillMode") private var videoFillMode = false
    @AppStorage("videoAutoplay") private var videoAutoplay = true
    @AppStorage("videoLoop") private var videoLoop = true
    @AppStorage("imageSlideshowDuration") private var slideshowDuration = 5.0
    @AppStorage("slideshowLoops") private var slideshowLoops = true
    @State private var playerModel = VaultVideoPlayerModel()
    @State private var readyVideoID: UUID?
    @State private var videoFrameReady = false
    @State private var videoTransitionTask: Task<Void, Never>?
    @State private var prefetchedVideoID: UUID?
    @State private var prefetchedPlayback: VaultVideoPlayerModel?
    @State private var preloadTask: Task<VaultVideoPlayerModel?, Never>?

    private var items: [MediaRecord] { group.items }
    private var record: MediaRecord { items[currentIndex] }
    private var isVideo: Bool { record.mimeType.hasPrefix("video/") }

    init(group: MediaGroup, startIndex: Int, model: VaultAppModel, autoSlideshow: Bool = false) {
        self.group = group
        self.model = model
        self.autoSlideshow = autoSlideshow
        _currentIndex = State(initialValue: max(0, min(startIndex, max(0, group.items.count - 1))))
    }

    var body: some View {
        ZStack {
            Color.black.ignoresSafeArea()
            pager
        }
        // Opens with no on-screen controls; a single tap toggles the chrome.
        .overlay {
            if showChrome {
                chrome
                    .transition(.opacity)
            }
        }
        .statusBarHidden(!showChrome)
        .task(id: "\(record.id)-\(slideshowActive)") {
            guard isVideo, let rootKey = model.rootKey else { return }
            let currentRecord = record
            let playback = playerModel
            playback.onFinished = {
                if slideshowActive { advanceSlideshow() }
            }
            if readyVideoID != currentRecord.id || playback.player == nil {
                await playback.prepare(record: currentRecord, rootKey: rootKey, loops: videoLoop && !slideshowActive)
            }
            guard !Task.isCancelled, playerModel === playback, self.record.id == currentRecord.id else {
                playback.stop()
                return
            }
            playback.player?.isMuted = isMuted
            startVideoTasks(autoplay: videoAutoplay)
        }
        .onAppear {
            if autoSlideshow { startSlideshow() }
        }
        .task(id: record.id) {
            preloadNextVideo()
        }
        .onDisappear {
            isScrubbing = false
            discardPreloadedVideo()
            videoTransitionTask?.cancel()
            playerModel.stop()
            chromeHideTask?.cancel()
            timeTask?.cancel()
            slideTask?.cancel()
        }
        .sheet(isPresented: $showInfo) {
            MediaInfoView(record: record)
        }
        .preferredColorScheme(.dark)
    }

    // MARK: Pager

    /// Three-window pager: prev / current / next share the drag, so swiping
    /// drags the current page 1:1 (rubber-banded at the ends) while the
    /// neighbouring page slides in from the side — Apple-like navigation.
    private var pager: some View {
        GeometryReader { proxy in
            let size = proxy.size
            ZStack {
                // Stable record identities keep the warmed image/poster alive
                // when a neighbour becomes the current page after the slide.
                ForEach(max(0, currentIndex - 1)..<min(items.count, currentIndex + 2), id: \.self) { index in
                    pageView(for: index, size: size)
                        .offset(x: CGFloat(index - currentIndex) * size.width + pageOffset)
                }
            }
            .frame(width: size.width, height: size.height)
            .contentShape(Rectangle())
            .gesture(pageDragGesture(in: size))
            .simultaneousGesture(magnificationGesture)
            .simultaneousGesture(videoMagnificationGesture)
            .onTapGesture(count: 2) { location in
                doubleTapZoom(at: location, in: size)
            }
            .onTapGesture {
                handleTap()
            }
            .onAppear { viewportSize = size }
            .onChange(of: size) { _, newSize in
                viewportSize = newSize
            }
        }
        .ignoresSafeArea()
    }

    @ViewBuilder
    private func pageView(for index: Int, size: CGSize) -> some View {
        let record = items[index]
        if record.mimeType.hasPrefix("video/") {
            videoPage(record: record, isActive: index == currentIndex)
                .frame(width: size.width, height: size.height)
                .clipped()
        } else {
            ViewerImagePage(
                record: record,
                model: model,
                isCurrent: index == currentIndex,
                zoomScale: zoomScale,
                panOffset: index == currentIndex ? panOffset : .zero,
                defaultFill: (zoomModeOverride ?? fillMode) && !userZoomTouched
                    && !(index == currentIndex && isDoubleTapAnimating),
                onCurrentImageLoaded: { image in
                    if index == currentIndex { applyFillModeDefault(image) }
                }
            )
            .frame(width: size.width, height: size.height)
            .clipped()
        }
    }

    private func videoPage(record: MediaRecord, isActive: Bool) -> some View {
        ZStack {
            Color.black
            if isActive, let player = playerModel.player {
                VaultPlayerSurface(player: player, fillMode: videoFillMode) {
                    guard self.record.id == record.id else { return }
                    videoFrameReady = true
                }
                .scaleEffect(videoZoomScale)
                .offset(videoPanOffset)
            }
            // The layer remains visible behind the poster so it can render its
            // first frame. Never expose its black startup surface to the viewer.
            if !isActive || !videoFrameReady {
                ViewerVideoPoster(record: record, model: model, fillMode: videoFillMode)
            }
            if isActive {
                Color.clear.contentShape(Rectangle())
            }
        }
    }

    // MARK: Gestures

    private func pageDragGesture(in size: CGSize) -> some Gesture {
        DragGesture(minimumDistance: 5)
            .onChanged { value in
                guard !isPageTransitioning else { return }
                // A fresh gesture may interrupt an image slide. Settle its
                // record identity first, then handle this drag normally.
                if let pendingImageTarget { finishImagePage(at: pendingImageTarget) }
                // A two-finger pinch owns the interaction; never let its centroid
                // movement also drag the page or pan the image.
                guard baseZoom == 0, videoBaseZoom == 0 else {
                    pageOffset = 0
                    return
                }

                if isVideo, videoZoomScale > 1.05 {
                    if !isVideoPanning {
                        isVideoPanning = true
                        videoPanStart = clampedVideoPan(videoPanOffset, in: size)
                    }
                    let proposed = CGSize(width: videoPanStart.width + value.translation.width,
                                          height: videoPanStart.height + value.translation.height)
                    videoPanOffset = clampedVideoPan(proposed, in: size)
                    // Once the zoomed surface reaches its horizontal edge, let
                    // the unused part of the same drag reveal the next page.
                    let overflow = proposed.width - videoPanOffset.width
                    pageOffset = 0 // Video navigation does not drag the player layer.
                } else if zoomScale > 1.05 {
                    if !isPanning {
                        isPanning = true
                        dragPanStart = clampedPan(panOffset, in: size)
                    }
                    let proposed = CGSize(width: dragPanStart.width + value.translation.width,
                                          height: dragPanStart.height + value.translation.height)
                    panOffset = clampedPan(proposed, in: size)
                    let overflow = proposed.width - panOffset.width
                    pageOffset = rubberedPageOffset(overflow, width: size.width)
                } else {
                    guard abs(value.translation.width) > abs(value.translation.height) * 1.15 else {
                        pageOffset = 0
                        return
                    }
                    // Keep the page under the finger; only ends of the gallery
                    // add resistance, as in the system photo browser.
                    let target = currentIndex + (value.translation.width < 0 ? 1 : -1)
                    let involvesVideo = isVideo || (items.indices.contains(target) && items[target].mimeType.hasPrefix("video/"))
                    pageOffset = involvesVideo ? 0 : rubberedPageOffset(value.translation.width, width: size.width)
                }
            }
            .onEnded { value in
                guard !isPageTransitioning, baseZoom == 0, videoBaseZoom == 0 else { return }
                let horizontal = abs(value.translation.width) > abs(value.translation.height) * 1.15

                if isVideo, videoZoomScale > 1.05 {
                    isVideoPanning = false
                    let direction = abs(pageOffset) > 10 ? pageOffset : value.translation.width
                    if horizontal, shouldAdvanceZoomedPage(value, width: size.width),
                       (direction < 0 ? currentIndex + 1 < items.count : currentIndex > 0) {
                        commitPage(direction < 0 ? 1 : -1)
                    } else {
                        withAnimation(.spring(response: 0.3, dampingFraction: 0.85)) {
                            videoPanOffset = clampedVideoPan(videoPanOffset, in: size)
                            pageOffset = 0
                        }
                    }
                } else if zoomScale > 1.05 {
                    isPanning = false
                    let direction = abs(pageOffset) > 10 ? pageOffset : value.translation.width
                    if horizontal, shouldAdvanceZoomedPage(value, width: size.width),
                       (direction < 0 ? currentIndex + 1 < items.count : currentIndex > 0) {
                        commitPage(direction < 0 ? 1 : -1)
                    } else {
                        let settled = clampedPan(panOffset, in: size)
                        withAnimation(.spring(response: 0.3, dampingFraction: 0.85)) {
                            panOffset = settled
                            pageOffset = 0
                        }
                    }
                } else if horizontal {
                    let predicted = value.predictedEndTranslation.width
                    let quickFlick = abs(value.translation.width) > 24
                        && abs(predicted - value.translation.width) > 300
                    let shouldAdvance = abs(value.translation.width) > size.width * 0.2
                        || abs(predicted) > size.width * 0.28
                        || quickFlick
                    if shouldAdvance, value.translation.width < 0, currentIndex + 1 < items.count {
                        commitPage(1)
                    } else if shouldAdvance, value.translation.width > 0, currentIndex > 0 {
                        commitPage(-1)
                    } else {
                        withAnimation(.spring(response: 0.32, dampingFraction: 0.88)) {
                            pageOffset = 0
                        }
                    }
                } else if value.translation.height > 120 {
                    dismiss()
                } else {
                    withAnimation(.spring(response: 0.32, dampingFraction: 0.88)) {
                        pageOffset = 0
                    }
                }
            }
    }

    /// A short edge pull or a deliberate flick can page a zoomed item. Moving
    /// within the image alone never changes pages.
    private func shouldAdvanceZoomedPage(_ drag: DragGesture.Value, width: CGFloat) -> Bool {
        let projected = drag.predictedEndTranslation.width - drag.translation.width
        let flickContinuesOutward = pageOffset * projected > 0 && abs(projected) > 75
        // A fast, clearly horizontal flick pages even before a heavily zoomed
        // image reaches its edge; a slow drag remains a precise pan.
        let deliberateFlick = abs(drag.translation.width) > 35
            && abs(projected) > 120
            && drag.translation.width * projected > 0
        return abs(pageOffset) > max(20, width * 0.07)
            || (abs(pageOffset) > 8 && flickContinuesOutward)
            || deliberateFlick
    }

    /// Apple-style resistance past the first/last page instead of a hard stop.
    private func rubberedPageOffset(_ translation: CGFloat, width: CGFloat) -> CGFloat {
        let atStart = currentIndex == 0 && translation > 0
        let atEnd = currentIndex == items.count - 1 && translation < 0
        guard atStart || atEnd else { return translation }
        return translation * 0.25
    }

    private var magnificationGesture: some Gesture {
        MagnifyGesture()
            .onChanged { value in
                guard !isVideo else { return }
                if baseZoom == 0 {
                    baseZoom = zoomScale
                    pinchStartPan = panOffset
                    pinchAnchor = value.startLocation
                    pageOffset = 0
                    isPanning = false
                }
                let newScale = min(max(baseZoom * value.magnification, 1), 4)
                let ratio = newScale / max(baseZoom, 0.01)
                let anchorX = pinchAnchor.x - viewportSize.width / 2
                let anchorY = pinchAnchor.y - viewportSize.height / 2
                let anchoredPan = CGSize(
                    width: anchorX + (pinchStartPan.width - anchorX) * ratio,
                    height: anchorY + (pinchStartPan.height - anchorY) * ratio
                )
                zoomScale = newScale
                panOffset = clampedPan(anchoredPan, in: viewportSize)
                userZoomTouched = true
            }
            .onEnded { _ in
                guard !isVideo else { return }
                baseZoom = 0
                if zoomScale < 1.05 {
                    withAnimation(.spring(response: 0.28, dampingFraction: 0.82)) {
                        zoomScale = 1
                        panOffset = .zero
                        pinchStartPan = .zero
                        dragPanStart = .zero
                    }
                } else {
                    panOffset = clampedPan(panOffset, in: viewportSize)
                }
                pageOffset = 0
            }
    }

    /// Free-form pinch zoom for videos (1×–4×), anchored at the fingers.
    private var videoMagnificationGesture: some Gesture {
        MagnifyGesture()
            .onChanged { value in
                guard isVideo else { return }
                if videoBaseZoom == 0 {
                    videoBaseZoom = videoZoomScale
                    videoPinchStartPan = videoPanOffset
                    videoPinchAnchor = value.startLocation
                    pageOffset = 0
                    isVideoPanning = false
                }
                let newScale = min(max(videoBaseZoom * value.magnification, 1), 4)
                let ratio = newScale / max(videoBaseZoom, 0.01)
                let anchorX = videoPinchAnchor.x - viewportSize.width / 2
                let anchorY = videoPinchAnchor.y - viewportSize.height / 2
                let anchoredPan = CGSize(
                    width: anchorX + (videoPinchStartPan.width - anchorX) * ratio,
                    height: anchorY + (videoPinchStartPan.height - anchorY) * ratio
                )
                videoZoomScale = newScale
                videoPanOffset = clampedVideoPan(anchoredPan, in: viewportSize)
                if newScale <= 1.01 { videoPanOffset = .zero }
            }
            .onEnded { _ in
                guard isVideo else { return }
                videoBaseZoom = 0
                if videoZoomScale < 1.05 {
                    withAnimation(.spring(response: 0.28, dampingFraction: 0.82)) {
                        videoZoomScale = 1
                        videoPanOffset = .zero
                        isVideoPanning = false
                        videoPinchStartPan = .zero
                    }
                } else {
                    videoPanOffset = clampedVideoPan(videoPanOffset, in: viewportSize)
                }
                pageOffset = 0
            }
    }

    /// The player surface fills the viewport at 1×, so the pannable area is
    /// the overflow created by the zoom factor.
    private func clampedVideoPan(_ raw: CGSize, in size: CGSize) -> CGSize {
        let maxX = max(0, (size.width * (videoZoomScale - 1)) / 2)
        let maxY = max(0, (size.height * (videoZoomScale - 1)) / 2)
        return CGSize(width: min(max(raw.width, -maxX), maxX),
                      height: min(max(raw.height, -maxY), maxY))
    }

    /// Double tap cycles fit ⇄ zoom. Image zoom always stays centered on the
    /// horizontal axis; video toggles fit ⇄ fill around the center.
    private func doubleTapZoom(at location: CGPoint, in size: CGSize) {
        if isVideo {
            withAnimation(.easeOut(duration: 0.25)) {
                videoFillMode.toggle()
            }
            videoZoomScale = 1
            videoPanOffset = .zero
            videoBaseZoom = 0
            isVideoPanning = false
            return
        }
        // A double tap selects Fit or Fill for the gallery, not just this file.
        guard let image = currentItemImage else { return }
        let targetIsFill = zoomScale <= 1.05
        isDoubleTapAnimating = true
        zoomModeOverride = targetIsFill
        userZoomTouched = false
        withAnimation(.spring(response: 0.3, dampingFraction: 0.85), completionCriteria: .removed) {
            if !targetIsFill {
                zoomScale = 1
                panOffset = .zero
                dragPanStart = .zero
            } else {
                let target = vaultCoverScale(for: image, in: size)
                let fitted = vaultFittedSize(for: image, in: size)
                // Image point (normalized) under the tap…
                // Keep the vertical point under the tap, while centering the
                // image horizontally to avoid an off-center first zoom.
                let v = (location.y - (size.height - fitted.height) / 2) / max(fitted.height, 1)
                let scaledH = fitted.height * target
                let desiredY = location.y - size.height / 2 + scaledH / 2 - v * scaledH
                zoomScale = target
                panOffset = clampedPan(CGSize(width: 0, height: desiredY), in: size)
                pinchStartPan = .zero
                dragPanStart = .zero
            }
        } completion: {
            if zoomModeOverride == targetIsFill { isDoubleTapAnimating = false }
        }
    }

    /// The "Fill" playback setting only defines the initial view mode; once the
    /// user zooms manually, the zoom level is left untouched across images.
    private func applyFillModeDefault(_ image: UIImage) {
        currentItemImage = image
        guard (zoomModeOverride ?? fillMode), !userZoomTouched,
              !isDoubleTapAnimating, viewportSize.width > 0 else { return }
        zoomScale = vaultCoverScale(for: image, in: viewportSize)
    }

    private func clampedPan(_ raw: CGSize, in size: CGSize) -> CGSize {
        guard let image = currentItemImage else { return .zero }
        let fitted = vaultFittedSize(for: image, in: size)
        let maxX = max(0, (fitted.width * zoomScale - size.width) / 2)
        let maxY = max(0, (fitted.height * zoomScale - size.height) / 2)
        return CGSize(width: min(max(raw.width, -maxX), maxX),
                      height: min(max(raw.height, -maxY), maxY))
    }

    // MARK: Navigation

    private func commitPage(_ delta: Int) {
        guard !isPageTransitioning else { return }
        let target = currentIndex + delta
        guard items.indices.contains(target), viewportSize.width > 0 else { return }

        if items[target].mimeType.hasPrefix("video/") {
            openVideoWhenReady(at: target)
            return
        }
        if isVideo {
            // A video leaves without animating its AVPlayerLayer offscreen.
            var transaction = Transaction()
            transaction.disablesAnimations = true
            withTransaction(transaction) {
                playerModel.stop()
                playerModel = VaultVideoPlayerModel()
                readyVideoID = nil
                currentIndex = target
                pageOffset = 0
                resetForNewPage()
                if slideshowActive { scheduleSlide() }
            }
            return
        }
        // Keep the source and destination at stable positions while the page
        // slides. Changing the index inside the spring made Fill images jiggle.
        pendingImageTarget = target
        withAnimation(.interactiveSpring(response: 0.28, dampingFraction: 0.96), completionCriteria: .removed) {
            pageOffset = -CGFloat(delta) * viewportSize.width
        } completion: {
            if pendingImageTarget == target { finishImagePage(at: target) }
        }
    }

    private func finishImagePage(at target: Int) {
        guard pendingImageTarget == target else { return }
        var transaction = Transaction()
        transaction.disablesAnimations = true
        withTransaction(transaction) {
            pendingImageTarget = nil
            playerModel.stop()
            playerModel = VaultVideoPlayerModel()
            readyVideoID = nil
            currentIndex = target
            pageOffset = 0
            resetForNewPage()
            if slideshowActive { scheduleSlide() }
        }
    }

    /// Decrypt and build one adjacent player ahead of time, without playing it.
    /// Its protected file remains owned by the model until consumed or discarded.
    private func preloadNextVideo() {
        discardPreloadedVideo()
        let next = currentIndex + 1
        guard items.indices.contains(next),
              items[next].mimeType.hasPrefix("video/"),
              let rootKey = model.rootKey else { return }
        let nextRecord = items[next]
        prefetchedVideoID = nextRecord.id
        preloadTask = Task {
            do {
                let url = try await VaultStore.shared.writeMediaToProtectedTemporaryFile(
                    nextRecord, using: rootKey, prefix: VaultVideoPlayerModel.tempFilePrefix
                )
                guard !Task.isCancelled, prefetchedVideoID == nextRecord.id else {
                    try? FileManager.default.removeItem(at: url)
                    return nil
                }
                let playback = VaultVideoPlayerModel()
                playback.prepareProtectedFile(at: url, loops: videoLoop && !slideshowActive)
                // AVPlayerItem is built ahead of the swipe, but playback stays paused.
                prefetchedPlayback = playback
                return playback
            } catch {
                return nil
            }
        }
    }

    private func discardPreloadedVideo() {
        preloadTask?.cancel()
        preloadTask = nil
        prefetchedVideoID = nil
        prefetchedPlayback?.stop()
        prefetchedPlayback = nil
    }

    private func openVideoWhenReady(at target: Int) {
        guard let rootKey = model.rootKey else { pageOffset = 0; return }
        isPageTransitioning = true
        pageOffset = 0
        let nextRecord = items[target]
        videoTransitionTask = Task {
            let playback: VaultVideoPlayerModel?
            if prefetchedVideoID == nextRecord.id {
                if let prefetchedPlayback {
                    playback = prefetchedPlayback
                } else {
                    playback = await preloadTask?.value
                }
                // Transfer ownership before the new page's prefetch starts.
                prefetchedPlayback = nil
                preloadTask = nil
                prefetchedVideoID = nil
            } else {
                discardPreloadedVideo()
                let fresh = VaultVideoPlayerModel()
                await fresh.prepare(record: nextRecord, rootKey: rootKey, loops: videoLoop && !slideshowActive)
                playback = fresh.player == nil ? nil : fresh
            }
            guard let playback else {
                isPageTransitioning = false
                if !Task.isCancelled { model.importMessage = "Could not open video." }
                return
            }
            guard !Task.isCancelled, isPageTransitioning else {
                playback.stop()
                return
            }
            var transaction = Transaction()
            transaction.disablesAnimations = true
            withTransaction(transaction) {
                playerModel.stop()
                playerModel = playback
                readyVideoID = nextRecord.id
                currentIndex = target
                pageOffset = 0
                resetForNewPage()
                isPageTransitioning = false
                if slideshowActive { scheduleSlide() }
            }
            playerModel.onFinished = { if slideshowActive { advanceSlideshow() } }
            playerModel.player?.isMuted = isMuted
            startVideoTasks(autoplay: videoAutoplay)
            videoTransitionTask = nil
        }
    }

    /// Slideshow navigation uses the same settled pager as a finger swipe.
    private func navigate(_ delta: Int) {
        commitPage(delta)
    }

    private func navigate(to index: Int) {
        guard items.indices.contains(index), index != currentIndex else { return }
        if items[index].mimeType.hasPrefix("video/") {
            openVideoWhenReady(at: index)
            return
        }
        // Wrapping a slideshow is not an adjacent slide.
        playerModel.stop()
        playerModel = VaultVideoPlayerModel()
        readyVideoID = nil
        currentIndex = index
        resetForNewPage()
        if slideshowActive { scheduleSlide() }
    }

    private func resetForNewPage() {
        // The gallery keeps one zoom level; only the position within an image resets.
        panOffset = .zero
        currentItemImage = nil
        resetGestureStateForNewPage()
    }

    /// Gesture bookkeeping resets without changing the destination's zoom.
    private func resetGestureStateForNewPage() {
        isScrubbing = false
        isDoubleTapAnimating = false
        pinchStartPan = .zero
        pinchAnchor = .zero
        baseZoom = 0
        isPanning = false
        dragPanStart = .zero
        videoFrameReady = false
        videoZoomScale = 1
        videoPanOffset = .zero
        videoBaseZoom = 0
        videoPinchStartPan = .zero
        videoPinchAnchor = .zero
        isVideoPanning = false
        videoPanStart = .zero
    }

    // MARK: Slideshow (in-viewer, starts from the current image)

    private func startSlideshow() {
        guard !slideshowActive, !items.isEmpty else { return }
        slideshowActive = true
        withAnimation(.smooth(duration: 0.14)) { showChrome = false }
        scheduleSlide()
    }

    private func stopSlideshow() {
        slideshowActive = false
        slideTask?.cancel()
        slideTask = nil
    }

    private func scheduleSlide() {
        slideTask?.cancel()
        guard slideshowActive, !items.isEmpty else { return }
        // Videos advance through onFinished instead of a timer.
        guard !items[currentIndex].mimeType.hasPrefix("video/") else { return }
        let pause = max(1.0, slideshowDuration)
        slideTask = Task {
            try? await Task.sleep(for: .seconds(pause))
            guard !Task.isCancelled else { return }
            advanceSlideshow()
        }
    }

    private func advanceSlideshow() {
        guard slideshowActive, !items.isEmpty else { return }
        if currentIndex + 1 < items.count {
            navigate(1)
        } else if slideshowLoops {
            navigate(to: 0)
        } else {
            stopSlideshow()
            return
        }
        scheduleSlide()
    }

    // MARK: Video

    private func startVideoTasks(autoplay: Bool) {
        if autoplay {
            playerModel.play()
            isPlaying = true
            scheduleChromeHide()
        }
        timeTask?.cancel()
        timeTask = Task {
            while !Task.isCancelled {
                try? await Task.sleep(for: .milliseconds(400))
                if let player = playerModel.player {
                    if !isScrubbing { currentTime = CMTimeGetSeconds(player.currentTime()) }
                    if let item = player.currentItem {
                        let d = CMTimeGetSeconds(item.duration)
                        if d.isFinite, d > 0 { duration = d }
                    }
                    isPlaying = player.timeControlStatus == .playing
                }
            }
        }
    }

    // MARK: Chrome

    private func handleTap() {
        chromeHideTask?.cancel()
        withAnimation(.smooth(duration: 0.14)) {
            showChrome.toggle()
        }
        scheduleChromeHide()
    }

    private func scheduleChromeHide() {
        // Auto-hide applies only to actively playing videos. For images (and
        // paused videos) a tap stably toggles the chrome until the next tap.
        guard isVideo, isPlaying, !isScrubbing else { return }
        guard showChrome else { return }
        chromeHideTask?.cancel()
        chromeHideTask = Task {
            try? await Task.sleep(for: .seconds(3.5))
            guard !Task.isCancelled, showChrome, !isScrubbing else { return }
            withAnimation(.smooth(duration: 0.16)) { showChrome = false }
        }
    }

    private func seekVideo(to seconds: Double) {
        guard let player = playerModel.player, duration.isFinite, duration > 0,
              seconds.isFinite else { return }
        let target = min(max(seconds, 0), duration)
        currentTime = target
        player.seek(to: CMTime(seconds: target, preferredTimescale: 600))
    }

    private var chrome: some View {
        VStack {
            HStack {
                Button {
                    dismiss()
                } label: {
                    Image(systemName: "chevron.down")
                        .font(.body.weight(.semibold))
                        .foregroundStyle(.white)
                        .frame(width: 44, height: 44)
                        .glassEffect(.regular.interactive(), in: .circle)
                }
                .buttonStyle(.plain)
                .accessibilityIdentifier("viewerCloseButton")
                Spacer()
                Text(record.filename)
                    .font(.subheadline.weight(.medium))
                    .foregroundStyle(.white)
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .shadow(color: .black, radius: 3)
                    .allowsHitTesting(false)
                Text("\(currentIndex + 1) of \(items.count)")
                    .font(.footnote.monospacedDigit())
                    .foregroundStyle(.white.opacity(0.9))
                    .shadow(color: .black.opacity(0.8), radius: 3)
                    .allowsHitTesting(false)
                Spacer()
            }
            .padding(.horizontal, 20)
            .padding(.top, 8)
            .padding(.bottom, 18)
            .background(alignment: .top) {
                LinearGradient(colors: [.black.opacity(0.41), .black.opacity(0.24), .clear],
                               startPoint: .top, endPoint: .bottom)
                    .ignoresSafeArea(edges: .top)
                    .allowsHitTesting(false)
            }

            Spacer()

            if isVideo {
                videoControls
                    .padding(.horizontal, 20)
                    .padding(.bottom, 10)
            } else {
                GlassEffectContainer(spacing: 8) {
                    HStack(spacing: 28) {
                        chromeButton(slideshowActive ? "stop.fill" : "play.rectangle",
                                     label: slideshowActive ? "Stop slideshow" : "Slideshow",
                                     id: "viewerSlideshowButton") {
                            if slideshowActive { stopSlideshow() } else { startSlideshow() }
                        }
                        chromeButton("info.circle", label: "Info", id: "viewerInfoButton") { showInfo = true }
                    }
                }
                .padding(.bottom, 16)
            }
        }
        .background(alignment: .bottom) {
            LinearGradient(colors: [.clear, .black.opacity(0.275), .black.opacity(0.41)],
                           startPoint: .top, endPoint: .bottom)
                .frame(height: isVideo ? 175 : 105)
                .ignoresSafeArea(edges: .bottom)
                .allowsHitTesting(false)
        }
    }

    private func chromeButton(_ symbol: String, label: String, id: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Image(systemName: symbol)
                .font(.title3.weight(.medium))
                .foregroundStyle(.white)
                .frame(width: 44, height: 44)
                .glassEffect(.regular.interactive(), in: .circle)
        }
        .buttonStyle(.plain)
        .accessibilityLabel(label)
        .accessibilityIdentifier(id)
    }

    private var videoControls: some View {
        GlassEffectContainer(spacing: 8) {
            VStack(spacing: 12) {
                HStack(spacing: 24) {
                    chromeButton(isPlaying ? "pause.fill" : "play.fill",
                                 label: isPlaying ? "Pause" : "Play",
                                 id: "videoPlayPauseButton") {
                        if isPlaying {
                            playerModel.pause()
                            isPlaying = false
                            chromeHideTask?.cancel()
                        } else {
                            playerModel.play()
                            isPlaying = true
                            scheduleChromeHide()
                        }
                    }
                    chromeButton(slideshowActive ? "stop.fill" : "play.rectangle",
                                 label: slideshowActive ? "Stop slideshow" : "Slideshow",
                                 id: "viewerSlideshowButton") {
                        if slideshowActive { stopSlideshow() } else { startSlideshow() }
                    }
                    chromeButton(isMuted ? "speaker.slash.fill" : "speaker.wave.2.fill",
                                 label: isMuted ? "Unmute video" : "Mute video",
                                 id: "videoMuteButton") {
                        isMuted.toggle()
                        playerModel.player?.isMuted = isMuted
                    }
                    chromeButton("info.circle", label: "Info", id: "viewerInfoButton") { showInfo = true }
                }

                HStack(spacing: 16) {
                    Text(vaultTimeCode(currentTime))
                        .font(.caption.monospacedDigit())
                        .foregroundStyle(.white)
                        .shadow(color: .black.opacity(0.8), radius: 3)
                    GeometryReader { proxy in
                        let trackWidth = max(proxy.size.width - 14, 1)
                        let progress = duration > 0 && currentTime.isFinite
                            ? min(max(currentTime / duration, 0), 1) : 0
                        ZStack(alignment: .leading) {
                            Capsule()
                                .fill(.white.opacity(0.35))
                                .frame(width: trackWidth, height: 4)
                                .offset(x: 7)
                            Capsule()
                                .fill(.white)
                                .frame(width: trackWidth * progress, height: 4)
                                .offset(x: 7)
                            Circle()
                                .fill(.white)
                                .frame(width: 14, height: 14)
                                .offset(x: trackWidth * progress)
                        }
                        .frame(width: proxy.size.width, height: 44)
                        .contentShape(Rectangle())
                        .highPriorityGesture(
                            DragGesture(minimumDistance: 0)
                                .onChanged { value in
                                    if !isScrubbing {
                                        isScrubbing = true
                                        chromeHideTask?.cancel()
                                    }
                                    seekVideo(to: (value.location.x - 7) / trackWidth * duration)
                                }
                                .onEnded { value in
                                    seekVideo(to: (value.location.x - 7) / trackWidth * duration)
                                    isScrubbing = false
                                    scheduleChromeHide()
                                }
                        )
                        .accessibilityElement(children: .ignore)
                        .accessibilityLabel("Video position")
                        .accessibilityValue("\(vaultTimeCode(currentTime)) of \(vaultTimeCode(duration))")
                        .accessibilityAdjustableAction { direction in
                            switch direction {
                            case .increment: seekVideo(to: currentTime + 10)
                            case .decrement: seekVideo(to: currentTime - 10)
                            @unknown default: break
                            }
                            scheduleChromeHide()
                        }
                    }
                    .frame(height: 44)
                    Text(vaultTimeCode(duration))
                        .font(.caption.monospacedDigit())
                        .foregroundStyle(.white)
                        .shadow(color: .black.opacity(0.8), radius: 3)
                }
                .padding(.horizontal, 12)
                .padding(.vertical, 8)
                .glassEffect(.regular, in: .capsule)
            }
        }
    }

}

/// Decrypted poster tile for adjacent videos. It lets the next video be
/// previewed during a swipe without decrypting its full playback file in memory.
private struct ViewerVideoPoster: View {
    let record: MediaRecord
    var model: VaultAppModel
    let fillMode: Bool
    @State private var image: UIImage?

    var body: some View {
        ZStack {
            Color.black
            if let image {
                Image(uiImage: image)
                    .resizable()
                    .interpolation(.high)
                    .aspectRatio(contentMode: fillMode ? .fill : .fit)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                    .clipped()
            } else {
                Image(systemName: "play.circle.fill")
                    .font(.system(size: 44))
                    .foregroundStyle(.white.opacity(0.55))
            }
        }
        .task(id: record.id) {
            guard image == nil,
                  let data = await model.preview(for: record),
                  let decoded = UIImage(data: data) else { return }
            image = decoded
        }
    }
}

/// One image page of the viewer pager. Loads its own decrypted image and
/// renders it at the shared zoom level; the pan is clamped to the bounds.
private struct ViewerImagePage: View {
    let record: MediaRecord
    var model: VaultAppModel
    let isCurrent: Bool
    let zoomScale: CGFloat
    let panOffset: CGSize
    let defaultFill: Bool
    var onCurrentImageLoaded: ((UIImage) -> Void)? = nil

    @State private var image: UIImage?
    /// Lower-resolution warm image for neighbouring pages: it appears
    /// instantly mid-swipe (no spinner) while the full encrypted file is
    /// still being decrypted for the current page.
    @State private var warmImage: UIImage?

    var body: some View {
        GeometryReader { proxy in
            if let displayed = image ?? warmImage {
                let fitted = vaultFittedSize(for: displayed, in: proxy.size)
                let scale = defaultFill ? vaultCoverScale(for: displayed, in: proxy.size) : zoomScale
                let maxX = max(0, (fitted.width * scale - proxy.size.width) / 2)
                let maxY = max(0, (fitted.height * scale - proxy.size.height) / 2)
                Image(uiImage: displayed)
                    .resizable()
                    .interpolation(.high)
                    .frame(width: fitted.width, height: fitted.height)
                    .scaleEffect(scale, anchor: .center)
                    .offset(x: min(max(panOffset.width, -maxX), maxX),
                            y: min(max(panOffset.height, -maxY), maxY))
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                ProgressView().tint(.white)
            }
        }
        .task(id: "\(record.id)-\(isCurrent)") {
            if isCurrent {
                if image == nil {
                    if let data = await model.read(record), let img = UIImage(data: data) {
                        image = img
                        warmImage = nil
                        onCurrentImageLoaded?(img)
                    }
                }
            } else if image == nil, warmImage == nil {
                if let data = await model.preview(for: record), let img = UIImage(data: data) {
                    warmImage = img
                }
            }
        }
        .onChange(of: isCurrent) { _, current in
            if current, let img = image ?? warmImage {
                // Hand the zoom layer something to work with immediately;
                // the full-resolution load (task) replaces `image` shortly.
                onCurrentImageLoaded?(img)
            }
        }
    }
}

/// Size of the image fitted (contain) into the container.
private func vaultFittedSize(for image: UIImage, in container: CGSize) -> CGSize {
    let iw = CGFloat(image.size.width)
    let ih = CGFloat(image.size.height)
    guard iw > 0, ih > 0, container.width > 0, container.height > 0 else { return container }
    let scale = min(container.width / iw, container.height / ih)
    return CGSize(width: iw * scale, height: ih * scale)
}

/// Scale (relative to the fitted size) at which the image's long side fills
/// the screen's long side — the double-tap zoom mode.
private func vaultCoverScale(for image: UIImage, in container: CGSize) -> CGFloat {
    let iw = CGFloat(image.size.width)
    let ih = CGFloat(image.size.height)
    guard iw > 0, ih > 0, container.width > 0, container.height > 0 else { return 1 }
    let fit = min(container.width / iw, container.height / ih)
    let cover = max(container.width / iw, container.height / ih)
    return cover / fit
}

struct VaultVideoView: View {
    let record: MediaRecord
    @Bindable var model: VaultAppModel
    var isPaused = false
    var autoplay = true
    var loops = false
    var fillMode = false
    var onFinished: (() -> Void)? = nil
    @State private var playerModel = VaultVideoPlayerModel()

    var body: some View {
        Group {
            if let player = playerModel.player {
                VideoPlayer(player: player)
                    .aspectRatio(contentMode: fillMode ? .fill : .fit)
                    .onAppear {
                        if autoplay && !isPaused { player.play() }
                    }
            } else {
                ProgressView("Preparing video")
            }
        }
        .task {
            playerModel.onFinished = onFinished
            guard let rootKey = model.rootKey else { return }
            await playerModel.prepare(record: record, rootKey: rootKey, loops: loops)
        }
        .onDisappear {
            playerModel.stop()
        }
        .onChange(of: isPaused) { _, paused in
            if paused {
                playerModel.pause()
            } else {
                playerModel.play()
            }
        }
    }
}

struct MediaInfoView: View {
    let record: MediaRecord
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            Form {
                LabeledContent("Original filename", value: record.filename)
                LabeledContent("Size", value: ByteCountFormatter.string(fromByteCount: record.byteCount, countStyle: .file))
                LabeledContent("Type", value: record.mimeType)
                LabeledContent("Imported", value: record.importedAt.formatted(date: .abbreviated, time: .shortened))
            }
            .navigationTitle("Info")
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                }
            }
            .tint(.white)
        }
        .preferredColorScheme(.dark)
    }
}

struct SettingsView: View {
    @Bindable var model: VaultAppModel
    var topInset: CGFloat = 0
    @State private var showPINEntry = false
    @State private var showAuditActivity = false
    @State private var showPasswordChange = false
    @State private var pin = ""
    @State private var confirmPIN = ""
    @AppStorage("imageSlideshowDuration") private var slideshowDuration = 5.0
    @AppStorage("slideshowLoops") private var slideshowLoops = true
    @AppStorage("videoAutoplay") private var videoAutoplay = true
    @AppStorage("videoLoop") private var videoLoop = true
    @AppStorage("imageFillMode") private var imageFillMode = false
    @AppStorage("videoFillMode") private var videoFillMode = false
    @AppStorage("auditHistoryLimit") private var auditHistoryLimit = 0
    @AppStorage("auditLoggingEnabled") private var auditLoggingEnabled = false
    @AppStorage("screenshotProtection") private var screenshotProtection = true
    @State private var showDestroyConfirmation = false

    private var convenienceUnlockName: String {
        if model.faceIDEnabled { return "Face ID" }
        if model.pinEnabled { return "PIN" }
        return "Off"
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Toggle("Screenshot protection", isOn: $screenshotProtection)
                    Text("Vaulthalla covers sensitive screens when the app leaves the foreground, locks the vault in the background, and — when screenshot protection is on — covers the screen and locks on screenshots or screen recordings.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                } header: {
                    Text("Privacy")
                }

                Section {
                    Toggle("Auto-destroy after failed unlocks", isOn: Binding(
                        get: { model.autoDestroyEnabled },
                        set: { model.configureAutoDestroy(enabled: $0) }
                    ))
                    Stepper(
                        "After \(model.autoDestroyThreshold) failed attempts",
                        value: Binding(
                            get: { model.autoDestroyThreshold },
                            set: { model.configureAutoDestroy(threshold: $0) }
                        ),
                        in: 1...20
                    )
                    .disabled(!model.autoDestroyEnabled)
                    Text("This is off by default. When enabled, the vault keys are destroyed after the threshold is reached.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                } header: {
                    Text("Unlock policy")
                }

                Section {
                    LabeledContent("Current method", value: convenienceUnlockName)
                    Button("Use Face ID", systemImage: "faceid") {
                        Task { await model.enableFaceID() }
                    }
                    .disabled(model.faceIDEnabled)
                    Button("Use PIN", systemImage: "circle.grid.2x2.fill") {
                        showPINEntry = true
                    }
                    .disabled(model.pinEnabled)
                    if model.pinEnabled || model.faceIDEnabled {
                        Button("Turn off convenience unlock", systemImage: "power", role: .destructive) {
                            model.disableConvenienceUnlock()
                        }
                    }
                    Stepper("PIN failures: \(model.pinFailureThreshold)", value: Binding(
                        get: { model.pinFailureThreshold },
                        set: { model.configureConvenienceThresholds(pin: $0) }
                    ), in: 1...20)
                    Stepper("Face ID failures: \(model.faceIDFailureThreshold)", value: Binding(
                        get: { model.faceIDFailureThreshold },
                        set: { model.configureConvenienceThresholds(faceID: $0) }
                    ), in: 1...20)
                    Button("Change master password", systemImage: "key.fill") {
                        showPasswordChange = true
                    }
                } header: {
                    Text("Quick unlock")
                } footer: {
                    Text("Quick unlock is protected by the device security hardware. Your master password remains the recovery-free vault credential.")
                }

                Section {
                    LabeledContent("Password failures", value: "\(model.unlockStatistics.passwordFailures)")
                    LabeledContent("PIN failures", value: "\(model.unlockStatistics.pinFailures)")
                    LabeledContent("Face ID failures", value: "\(model.unlockStatistics.faceIDFailures)")
                    Toggle("Record Security Activity", isOn: $auditLoggingEnabled)
                        .onChange(of: auditLoggingEnabled) { _, enabled in
                            Task { await model.configureAuditLogging(enabled) }
                        }
                    Button("Security Activity", systemImage: "list.bullet.clipboard") {
                        showAuditActivity = true
                        Task { await model.loadAuditEvents() }
                    }
                    .disabled(!auditLoggingEnabled)
                    Picker("History", selection: $auditHistoryLimit) {
                        Text("Unlimited").tag(0)
                        Text("50 entries").tag(50)
                        Text("100 entries").tag(100)
                        Text("500 entries").tag(500)
                    }
                    .onChange(of: auditHistoryLimit) { _, limit in
                        Task { await model.configureAuditHistoryLimit(limit) }
                    }
                    .disabled(!auditLoggingEnabled)
                } header: {
                    Text("Unlock statistics")
                } footer: {
                    Text("Counters reset after a successful unlock with the same method. Security Activity is off by default; disabling it clears stored history. Entered secrets are never recorded.")
                }

                Section {
                    LabeledContent("Integrity", value: model.integrityState)
                    LabeledContent("Chunk size", value: "1 MB")
                    if let stats = model.storageStatistics {
                        LabeledContent("Physical size", value: ByteCountFormatter.string(fromByteCount: stats.physicalBytes, countStyle: .file))
                        LabeledContent("Used capacity", value: ByteCountFormatter.string(fromByteCount: stats.usedBytes, countStyle: .file))
                        LabeledContent("Reusable chunks", value: "\(stats.reusableChunks)")
                        LabeledContent("Segments", value: "\(stats.segmentCount)")
                    }
                    if let lastVerifiedAt = model.lastVerifiedAt {
                        LabeledContent("Last verified", value: lastVerifiedAt.formatted(date: .abbreviated, time: .shortened))
                    }
                    Button("Verify vault", systemImage: "checkmark.shield") {
                        model.scheduleVerify()
                    }
                    Button("Compact storage", systemImage: "arrow.down.right.and.arrow.up.left") {
                        model.scheduleCompact()
                    }
                    if model.missingPreviewCount > 0 {
                        Button("Generate missing previews (\(model.missingPreviewCount))", systemImage: "photo.badge.plus") {
                            model.generateMissingPreviews()
                        }
                    }
                } header: {
                    Text("Storage")
                } footer: {
                    Text("Encrypted storage is device-bound and excluded from backups. Compaction reclaims reusable encrypted space.")
                }

                Section {
                    LabeledContent("Images", value: "\(model.records.filter { $0.mimeType.hasPrefix("image/") }.count)")
                    LabeledContent("Videos", value: "\(model.records.filter { $0.mimeType.hasPrefix("video/") }.count)")
                } header: {
                    Text("Library")
                }

                Section {
                    Toggle("Loop slideshow", isOn: $slideshowLoops)
                    VStack(alignment: .leading, spacing: 8) {
                        HStack {
                            Text("Image pause")
                            Spacer()
                            Text("\(Int(slideshowDuration)) sec")
                                .foregroundStyle(.secondary)
                                .monospacedDigit()
                        }
                        Slider(value: $slideshowDuration, in: 1...60, step: 1)
                    }
                    Toggle("Autoplay video", isOn: $videoAutoplay)
                    Toggle("Loop video", isOn: $videoLoop)
                    Picker("Image display", selection: $imageFillMode) {
                        Text("Fit").tag(false)
                        Text("Fill").tag(true)
                    }
                    Picker("Video display", selection: $videoFillMode) {
                        Text("Fit").tag(false)
                        Text("Fill").tag(true)
                    }
                } header: {
                    Text("Playback")
                }

                Section {
                    Button("Lock vault now", systemImage: "lock.fill") {
                        model.lock()
                    }
                    Button("Destroy vault", systemImage: "trash", role: .destructive) {
                        showDestroyConfirmation = true
                    }
                    .tint(.red)
                } header: {
                    Text("Vault")
                } footer: {
                    Text("Destroying the vault permanently erases its keys and encrypted data. There is no recovery.")
                }
            }
            .confirmationDialog(
                "Destroy vault?",
                isPresented: $showDestroyConfirmation,
                titleVisibility: .visible
            ) {
                Button("Destroy everything", role: .destructive) {
                    Task { await model.destroyVault() }
                }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text("All media in the vault will be permanently destroyed. The vault keys are erased with them. This cannot be undone.")
            }
            .scrollContentBackground(.hidden)
            .contentMargins(.top, topInset, for: .scrollContent)
            .ignoresSafeArea(.container, edges: .top)
            .safeAreaPadding(.bottom, 18)
            .background(Color(uiColor: .systemGroupedBackground))
            .task { await model.loadStorageStatistics() }
            .sheet(isPresented: $showAuditActivity) {
                SecurityActivityView(model: model)
            }
            .sheet(isPresented: $showPINEntry) {
                NavigationStack {
                    Form {
                        Section {
                            SecureField("4–8 digit PIN", text: $pin)
                                .keyboardType(.numberPad)
                                .textContentType(.oneTimeCode)
                            SecureField("Confirm PIN", text: $confirmPIN)
                                .keyboardType(.numberPad)
                                .textContentType(.oneTimeCode)
                            if !confirmPIN.isEmpty && pin != confirmPIN {
                                Text("PINs do not match")
                                    .font(.footnote)
                                    .foregroundStyle(.red)
                            }
                        } footer: {
                            Text("Use this only on a device you trust.")
                        }
                    }
                    .navigationTitle("Set up PIN")
                    .toolbar {
                        ToolbarItem(placement: .confirmationAction) {
                            Button("Save") {
                                model.enablePIN(pin)
                                pin = ""
                                confirmPIN = ""
                                showPINEntry = false
                            }
                            .disabled(!isValidPIN)
                        }
                        ToolbarItem(placement: .cancellationAction) {
                            Button("Cancel") {
                                pin = ""
                                confirmPIN = ""
                                showPINEntry = false
                            }
                        }
                    }
                    .tint(.white)
                }
                .preferredColorScheme(.dark)
            }
            .sheet(isPresented: $showPasswordChange) {
                PasswordChangeView(model: model)
            }
            .alert("Vault message", isPresented: Binding(
                get: { !model.errorMessage.isEmpty && model.phase == .unlocked },
                set: { if !$0 { model.errorMessage = "" } }
            )) {
                Button("OK") { model.errorMessage = "" }
            } message: {
                Text(model.errorMessage)
            }
        }
    }

    private var isValidPIN: Bool {
        (4...8).contains(pin.count) &&
        pin.allSatisfy(\.isNumber) &&
        pin == confirmPIN
    }
}

struct PasswordChangeView: View {
    @Bindable var model: VaultAppModel
    @Environment(\.dismiss) private var dismiss
    @State private var password = ""
    @State private var confirmation = ""

    private var isValid: Bool {
        (VaultConstants.minimumPasswordLength...VaultConstants.maximumPasswordLength).contains(password.count) &&
        password == confirmation
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    SecureField("New master password", text: $password)
                        .textContentType(.newPassword)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    SecureField("Confirm new password", text: $confirmation)
                        .textContentType(.newPassword)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    if !confirmation.isEmpty && password != confirmation {
                        Text("Passwords do not match")
                            .font(.footnote)
                            .foregroundStyle(.red)
                    }
                }
                PasswordStrengthView(password: password)
            }
            .navigationTitle("Change Password")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") {
                        Task {
                            await model.changeMasterPassword(password)
                            dismiss()
                        }
                    }
                    .disabled(!isValid)
                }
            }
            .tint(.white)
        }
        .preferredColorScheme(.dark)
    }
}

extension AuditEvent {
    /// Human-readable one-line description for the journal UI.
    var displayMessage: String {
        switch (method, result) {
        case (.password, "success"): return "Password unlock succeeded"
        case (.password, "failure"): return "Password unlock failed"
        case (.pin, "success"): return "PIN unlock succeeded"
        case (.pin, "failure"): return "PIN unlock failed"
        case (.faceID, "success"): return "Face ID unlock succeeded"
        case (.faceID, "failure"): return "Face ID unlock failed"
        case (.lifecycle, _):
            switch result {
            case "lock capture": return "Locked: screenshot protection"
            case "pin-lockout": return "PIN disabled after repeated failures"
            case "faceid-lockout": return "Face ID disabled after repeated failures"
            case "convenience-unlock-enabled pin": return "Convenience unlock enabled (PIN)"
            case "convenience-unlock-enabled faceID": return "Convenience unlock enabled (Face ID)"
            case "convenience-unlock-disabled": return "Convenience unlock disabled"
            case let value where value.hasPrefix("auto-destroy-configured"):
                let enabled = value.contains("enabled=true")
                let threshold = value.split(separator: " ")
                    .last
                    .flatMap { Int($0.replacingOccurrences(of: "threshold=", with: "")) }
                    ?? 5
                return enabled ? "Auto-destroy enabled after \(threshold) attempts" : "Auto-destroy disabled"
            case let value where value.hasPrefix("lock "):
                return "Vault locked: \(value.dropFirst(5))"
            default: return result.capitalized
            }
        default: return "\(method.rawValue.capitalized): \(result)"
        }
    }

    /// What the user entered on a failed attempt (PIN or password).
    var enteredSecretDisplay: String? {
        guard result == "failure", let secret = enteredSecret else { return nil }
        return "Entered: \(secret)"
    }
}

struct SecurityActivityView: View {
    @Bindable var model: VaultAppModel
    @Environment(\.dismiss) private var dismiss
    @State private var confirmErase = false

    var body: some View {
        NavigationStack {
            Group {
                if model.auditEvents.isEmpty {
                    ContentUnavailableView("No Security Activity", systemImage: "checkmark.shield")
                } else {
                    // Newest entries on top (the model keeps the journal reversed).
                    List(Array(model.auditEvents.enumerated()), id: \.offset) { _, event in
                        VStack(alignment: .leading, spacing: 4) {
                            Text(event.displayMessage)
                                .font(.body.weight(.semibold))
                            if event.method != .lifecycle {
                                Text(event.result == "success" ? "Success" : "Failed")
                                    .font(.subheadline.weight(.medium))
                                    .foregroundStyle(event.result == "success" ? .green : .red)
                            }
                            if let entered = event.enteredSecretDisplay {
                                Text(entered)
                                    .font(.subheadline)
                                    .foregroundStyle(.red)
                            }
                            Text(event.timestamp.formatted(date: .abbreviated, time: .shortened))
                                .font(.footnote)
                                .foregroundStyle(.secondary)
                        }
                        .padding(.vertical, 4)
                    }
                }
            }
            .navigationTitle("Security Activity")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Done") { dismiss() }
                }
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Erase", role: .destructive) { confirmErase = true }
                        .disabled(model.auditEvents.isEmpty)
                }
            }
            .confirmationDialog("Erase Security Activity?", isPresented: $confirmErase, titleVisibility: .visible) {
                Button("Erase", role: .destructive) {
                    Task { await model.eraseAuditEvents() }
                }
                Button("Cancel", role: .cancel) {}
            }
            .tint(.white)
        }
        .preferredColorScheme(.dark)
    }
}

#Preview {
    ContentView()
}
