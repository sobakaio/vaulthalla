import SwiftUI
import UIKit

struct WebImportView: View {
    @Bindable var model: VaultAppModel
    @Environment(\.dismiss) private var dismiss
    @State private var copied = false

    private var server: LocalWebImportServer {
        model.webImportServer
    }

    var body: some View {
        NavigationStack {
            ZStack {
                Color(uiColor: .systemGroupedBackground)
                    .ignoresSafeArea()

                ScrollView {
                    VStack(alignment: .leading, spacing: 22) {
                        VStack(alignment: .leading, spacing: 14) {
                            Image(systemName: "network")
                                .font(.system(size: 28, weight: .semibold))
                                .foregroundStyle(.white)
                                .frame(width: 64, height: 64)
                                .background(VaultUI.accentGradient, in: RoundedRectangle(cornerRadius: 20, style: .continuous))

                            Text("Send photos and videos from another device on the same Wi‑Fi network.")
                                .font(.body)
                                .foregroundStyle(.secondary)
                        }

                        VStack(alignment: .leading, spacing: 16) {
                            Label(server.state.title, systemImage: server.state == .running ? "checkmark.circle.fill" : "circle.dotted")
                                .font(.headline)
                                .foregroundStyle(server.state == .running ? .green : .primary)

                            if let url = server.importURL, server.state == .running {
                                Text("Open this address in the other device’s browser:")
                                    .font(.subheadline)
                                    .foregroundStyle(.secondary)

                                Text(url.absoluteString)
                                    .font(.footnote.monospaced())
                                    .textSelection(.enabled)
                                    .padding(14)
                                    .frame(maxWidth: .infinity, alignment: .leading)
                                    .background(.quaternary, in: RoundedRectangle(cornerRadius: 14, style: .continuous))

                                Button(copied ? "Copied" : "Copy address", systemImage: copied ? "checkmark" : "doc.on.doc") {
                                    UIPasteboard.general.string = url.absoluteString
                                    copied = true
                                    Task {
                                        try? await Task.sleep(for: .seconds(2))
                                        copied = false
                                    }
                                }
                                .buttonStyle(.borderedProminent)
                                .tint(VaultUI.accent)
                            } else if case .failed(let message) = server.state {
                                Label(message, systemImage: "exclamationmark.triangle.fill")
                                    .foregroundStyle(.red)
                            } else {
                                ProgressView()
                            }
                        }
                        .padding(20)
                        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: VaultUI.cardRadius, style: .continuous))

                        VStack(alignment: .leading, spacing: 12) {
                            Label("One-way and local only", systemImage: "lock.shield.fill")
                                .font(.headline)
                            Text("Files travel directly to this iPhone over your local network. They are encrypted as they arrive. This page cannot view, download, or browse anything already in your vault.")
                                .font(.subheadline)
                                .foregroundStyle(.secondary)
                            Divider()
                            Label("Session expires in 15 minutes", systemImage: "timer")
                                .font(.subheadline.weight(.medium))
                            if !server.activeFilename.isEmpty {
                                Label("Importing \(server.activeFilename)", systemImage: "arrow.down.circle")
                                    .font(.subheadline)
                                    .foregroundStyle(.secondary)
                            } else if server.uploadedCount > 0 {
                                Label("\(server.uploadedCount) file(s) imported", systemImage: "checkmark.circle")
                                    .font(.subheadline)
                                    .foregroundStyle(.secondary)
                            }
                        }
                        .padding(20)
                        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: VaultUI.cardRadius, style: .continuous))

                        Button("Stop Web Import", systemImage: "stop.fill", role: .destructive) {
                            dismiss()
                        }
                        .frame(maxWidth: .infinity)
                        .buttonStyle(.bordered)
                    }
                    .padding(24)
                }
            }
            .navigationTitle("Web Import")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Done") {
                        dismiss()
                    }
                    .foregroundStyle(.white)
                }
            }
            .toolbarColorScheme(.dark, for: .navigationBar)
            .tint(.white)
            .onAppear {
                model.startWebImport()
            }
            .onDisappear {
                // Stops the session and reloads the index so imported files
                // appear in the grid immediately after the dialog closes.
                Task { await model.stopWebImport() }
            }
        }
        .preferredColorScheme(.dark)
    }
}
