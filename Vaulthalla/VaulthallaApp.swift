import SwiftUI

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
        }
    }
}
