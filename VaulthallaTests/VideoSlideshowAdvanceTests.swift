import Testing
import Foundation
import AVFoundation
@testable import Vaulthalla

/// Regression: a video prepared BEFORE the slideshow started had its loop
/// preference baked into the end-of-time observer at prepare time, so once the
/// slideshow adopted it, it looped forever instead of calling `onFinished` and
/// advancing. The view now resets the live `loops` flag right before each
/// (re)start; these tests pin the end-of-time handler to the LIVE flag.
@MainActor
struct VideoSlideshowAdvanceTests {
    /// Builds a model around a real (never played) player item and returns it
    /// together with the item the observer is watching.
    private func modelWithPreparedItem(prepareLoops: Bool) -> (VaultVideoPlayerModel, AVPlayerItem) {
        let asset = AVURLAsset(url: URL(fileURLWithPath: "/nonexistent/vault-test.mp4"))
        let model = VaultVideoPlayerModel()
        model.setUpPlayer(asset: asset, loops: prepareLoops)
        guard let item = model.player?.currentItem else {
            fatalError("setUpPlayer should attach a player item")
        }
        return (model, item)
    }

    @Test func endOfTimeHonorsLiveLoopsFlagNotPrepareTimeValue() async {
        // Prepared with loops ON — exactly what the pre-slideshow prefetch did —
        // then the live flag is flipped OFF, as the view does once the
        // slideshow is running.
        let (model, item) = modelWithPreparedItem(prepareLoops: true)
        defer { model.stop() }
        model.loops = false
        var finished = false
        model.onFinished = { finished = true }
        NotificationCenter.default.post(
            name: .AVPlayerItemDidPlayToEndTime, object: item, userInfo: nil
        )
        try? await Task.sleep(for: .milliseconds(50))
        #expect(finished, "end of time must call onFinished when the live loops flag is off")
    }

    @Test func endOfTimeKeepsLoopingWhileLoopsFlagStaysOn() async {
        // Normal "loop this video" mode: loops ON at prepare time and kept ON.
        let (model, item) = modelWithPreparedItem(prepareLoops: true)
        defer { model.stop() }
        var finished = false
        model.onFinished = { finished = true }
        NotificationCenter.default.post(
            name: .AVPlayerItemDidPlayToEndTime, object: item, userInfo: nil
        )
        try? await Task.sleep(for: .milliseconds(50))
        #expect(!finished, "a looping video must not report finished")
    }
}
