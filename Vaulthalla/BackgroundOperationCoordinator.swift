import Foundation
import BackgroundTasks

@MainActor
final class BackgroundOperationCoordinator {
    static let shared = BackgroundOperationCoordinator()
    private static let taskIdentifier = "io.sobaka.vaulthalla.continued"
    private var activeOperation: Task<Void, Never>?
    private var queued: [@MainActor () async -> Bool] = []
    private var generation = 0
    /// Injectable so tests can observe background requests without touching
    /// the real BGTaskScheduler (AUDIT #12).
    var requestSubmitter: @MainActor (BGContinuedProcessingTaskRequest) -> Void = {
        try? BGTaskScheduler.shared.submit($0)
    }

    init() {}

    func register() {
        guard #available(iOS 26.0, *) else { return }
        BGTaskScheduler.shared.register(forTaskWithIdentifier: Self.taskIdentifier, using: nil) { task in
            // Foreground submission owns the operation. A background request only
            // extends its lifetime; it must never invoke the same closure twice.
            task.expirationHandler = { [weak self] in
                Task { @MainActor in self?.cancelCurrentOperation() }
                task.setTaskCompleted(success: false)
            }
            Task { @MainActor [weak self] in
                await self?.waitUntilIdle()
                task.setTaskCompleted(success: true)
            }
        }
    }

    func submit(title: String, subtitle: String, operation: @escaping @MainActor () async -> Bool) {
        queued.append(operation)
        startNext()
        guard #available(iOS 26.0, *) else { return }
        let request = BGContinuedProcessingTaskRequest(
            identifier: Self.taskIdentifier, title: title, subtitle: subtitle
        )
        request.strategy = .queue
        requestSubmitter(request)
    }

    private func startNext() {
        guard activeOperation == nil, !queued.isEmpty else { return }
        let operation = queued.removeFirst()
        let currentGeneration = generation
        activeOperation = Task { @MainActor [weak self] in
            _ = await operation()
            guard let self else { return }
            self.activeOperation = nil
            if self.generation == currentGeneration { self.startNext() }
        }
    }

    func cancelCurrentOperation() {
        generation &+= 1
        queued.removeAll()
        activeOperation?.cancel()
    }

    /// Wait for cooperative cancellation before removing vault files.
    func cancelAndDrain() async {
        cancelCurrentOperation()
        await waitUntilIdle()
    }

    private func waitUntilIdle() async {
        while let activeOperation {
            await activeOperation.value
        }
    }

    #if DEBUG
    /// Test seam (AUDIT #12): true when no operation is active or queued.
    var isIdleForTests: Bool { activeOperation == nil && queued.isEmpty }
    func waitUntilIdleForTests() async { await waitUntilIdle() }
    #endif
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
