import Foundation
import BackgroundTasks

@MainActor
final class BackgroundOperationCoordinator {
    static let shared = BackgroundOperationCoordinator()
    private static let taskIdentifier = "io.sobaka.vaulthalla.continued"
    private var handler: (@MainActor () async -> Bool)?
    private var operationRunning = false
    private var activeOperation: Task<Void, Never>?
    private var pendingOperation: (@MainActor () async -> Bool)?

    private init() {}

    func register() {
        guard #available(iOS 26.0, *) else { return }
        BGTaskScheduler.shared.register(forTaskWithIdentifier: Self.taskIdentifier, using: nil) { [weak self] task in
            guard let task = task as? BGContinuedProcessingTask else {
                task.setTaskCompleted(success: false)
                return
            }
            task.expirationHandler = {
                task.setTaskCompleted(success: false)
            }
            Task { @MainActor [weak self] in
                guard let self, !self.operationRunning else {
                    task.setTaskCompleted(success: true)
                    return
                }
                self.operationRunning = true
                let operation = self.handler
                self.handler = nil
                let success = await operation?() ?? false
                self.operationRunning = false
                if let pending = self.pendingOperation {
                    self.pendingOperation = nil
                    self.runOperation(pending)
                }
                task.setTaskCompleted(success: success)
            }
        }
    }

    func submit(
        title: String,
        subtitle: String,
        operation: @escaping @MainActor () async -> Bool
    ) {
        handler = operation
        // Never silently drop an import: if an operation is already running
        // (e.g. a Wi‑Fi upload still finishing), the new one runs right after.
        if operationRunning {
            pendingOperation = operation
        } else {
            runOperation(operation)
        }

        guard #available(iOS 26.0, *) else { return }
        let request = BGContinuedProcessingTaskRequest(
            identifier: Self.taskIdentifier,
            title: title,
            subtitle: subtitle
        )
        request.strategy = .queue
        try? BGTaskScheduler.shared.submit(request)
    }

    private func runOperation(_ operation: @escaping @MainActor () async -> Bool) {
        operationRunning = true
        activeOperation = Task { @MainActor [weak self] in
            _ = await operation()
            guard let self else { return }
            self.operationRunning = false
            self.activeOperation = nil
            if let pending = self.pendingOperation {
                self.pendingOperation = nil
                self.runOperation(pending)
            }
        }
    }

    func cancelCurrentOperation() {
        activeOperation?.cancel()
        pendingOperation = nil
    }
}

/// Keeps the app alive in the background for the duration of a Web Import
/// session (uploads arrive over the local network while the user is in
/// Safari). Uses its own BG task identifier so it never occupies the import
/// operation slot.
@MainActor
final class WebImportBackgroundSession {
    static let shared = WebImportBackgroundSession()
    private static let taskIdentifier = "io.sobaka.vaulthalla.webimport"
    private var task: BGContinuedProcessingTask?

    private init() {}

    func register() {
        guard #available(iOS 26.0, *) else { return }
        BGTaskScheduler.shared.register(forTaskWithIdentifier: Self.taskIdentifier, using: nil) { task in
            guard let task = task as? BGContinuedProcessingTask else {
                task.setTaskCompleted(success: false)
                return
            }
            task.expirationHandler = {
                task.setTaskCompleted(success: false)
            }
            Task { @MainActor in
                Self.shared.task = task
            }
        }
    }

    /// Submit a continued-processing request for the web import session.
    /// The system invokes the registered handler; we keep the task alive until
    /// `end()` is called.
    func begin() {
        guard #available(iOS 26.0, *) else { return }
        end()
        let request = BGContinuedProcessingTaskRequest(
            identifier: Self.taskIdentifier,
            title: "Vaulthalla Web Import",
            subtitle: "Receiving files over Wi‑Fi"
        )
        request.strategy = .queue
        try? BGTaskScheduler.shared.submit(request)
    }

    func end() {
        task?.setTaskCompleted(success: true)
        task = nil
    }
}
