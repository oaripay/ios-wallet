#if os(iOS) && canImport(BackgroundTasks)
import BackgroundTasks
import Foundation
import OSLog

@MainActor
final class CredentialMaintenanceCoordinator {
    static let shared = CredentialMaintenanceCoordinator()
    static let taskIdentifier = "io.oari.wallet.credential-maintenance"

    typealias DeadlineProvider = @Sendable () async -> Date?
    typealias MaintenanceOperation = @Sendable () async throws -> Void

    private static let logger = Logger(subsystem: "io.oari.wallet", category: "credential-maintenance")
    private let scheduler: BGTaskScheduler
    private var deadlineProvider: DeadlineProvider = { nil }
    private var deferredIssuanceOperation: MaintenanceOperation = {}
    private var automaticRefreshDeadlineProvider: DeadlineProvider = { nil }
    private var automaticRefreshOperation: MaintenanceOperation = {}
    private var isRegistered = false

    init(scheduler: BGTaskScheduler = .shared) {
        self.scheduler = scheduler
    }

    /// Call during app initialization, before launch finishes.
    func register() {
        guard !isRegistered else { return }
        isRegistered = scheduler.register(
            forTaskWithIdentifier: Self.taskIdentifier,
            using: nil
        ) { [weak self] task in
            guard let refreshTask = task as? BGAppRefreshTask else {
                task.setTaskCompleted(success: false)
                return
            }
            Task { @MainActor [weak self] in
                self?.handle(refreshTask)
            }
        }
        if !isRegistered {
            Self.logger.error("Failed to register credential maintenance background task")
        }
    }

    func installDeferredIssuance(
        nextDeadline: @escaping DeadlineProvider,
        operation: @escaping MaintenanceOperation
    ) {
        deadlineProvider = nextDeadline
        deferredIssuanceOperation = operation
    }

    /// Integration point for automatic credential status/refresh work.
    func installAutomaticRefresh(
        nextDeadline: @escaping DeadlineProvider,
        operation: @escaping MaintenanceOperation
    ) {
        automaticRefreshDeadlineProvider = nextDeadline
        automaticRefreshOperation = operation
    }

    func schedule() async {
        guard isRegistered else { return }
        scheduler.cancel(taskRequestWithIdentifier: Self.taskIdentifier)
        async let deferredDeadline = deadlineProvider()
        async let automaticRefreshDeadline = automaticRefreshDeadlineProvider()
        let deadlines = await (deferredDeadline, automaticRefreshDeadline)
        guard let deadline = [deadlines.0, deadlines.1].compactMap({ $0 }).min() else {
            return
        }

        let request = BGAppRefreshTaskRequest(identifier: Self.taskIdentifier)
        request.earliestBeginDate = deadline
        do {
            try scheduler.submit(request)
        } catch {
            Self.logger.error("Failed to schedule credential maintenance: \(error.localizedDescription, privacy: .public)")
        }
    }

    private func handle(_ backgroundTask: BGAppRefreshTask) {
        let work = Task { [deferredIssuanceOperation, automaticRefreshOperation] in
            do {
                try await withThrowingTaskGroup(of: Void.self) { group in
                    group.addTask {
                        async let deferred: Void = deferredIssuanceOperation()
                        async let automaticRefresh: Void = automaticRefreshOperation()
                        _ = try await (deferred, automaticRefresh)
                    }
                    group.addTask {
                        try await Task.sleep(for: .seconds(25))
                        throw MaintenanceError.timedOut
                    }
                    try await group.next()
                    group.cancelAll()
                }
                guard !Task.isCancelled else {
                    backgroundTask.setTaskCompleted(success: false)
                    return
                }
                await schedule()
                backgroundTask.setTaskCompleted(success: true)
            } catch {
                await schedule()
                backgroundTask.setTaskCompleted(success: false)
            }
        }
        backgroundTask.expirationHandler = { work.cancel() }
    }

    private enum MaintenanceError: Error {
        case timedOut
    }
}
#endif
