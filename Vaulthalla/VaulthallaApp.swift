import SwiftUI
import UserNotifications

@main
struct VaulthallaApp: App {
    init() {
        BackgroundOperationCoordinator.shared.register()
        WebImportBackgroundSession.shared.register()
        VaultVideoPlayerModel.sweepStaleTempFiles()
        ThumbnailGenerator.sweepStaleTempFiles()
    }

    var body: some Scene {
        WindowGroup {
            ContentView()
                .task {
                    // Request notification permission at launch so the system
                    // prompt never appears mid-flow. A prompt covering the
                    // Web Import sheet briefly transitions the scene to
                    // .inactive, which stops the import server right after
                    // its first start (the "Web Import is off" on fresh
                    // installs).
                    UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .badge]) { _, _ in }
                }
        }
    }
}
