<p align="center">
  <img src="Vaulthalla/Assets.xcassets/VaultMark.imageset/VaultMark.png" width="160" alt="Vaulthalla vault mark">
</p>

<h1 align="center">Vaulthalla</h1>

<p align="center">
  <strong>A privacy-first, offline photo and video vault for iPhone.</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/platform-iOS%2026%2B-000000?style=flat-square&logo=apple&logoColor=white" alt="iOS 26+">
  <img src="https://img.shields.io/badge/Swift-SwiftUI-F05138?style=flat-square&logo=swift&logoColor=white" alt="Swift and SwiftUI">
  <img src="https://img.shields.io/badge/crypto-AES--GCM-5B21B6?style=flat-square&logo=letsencrypt&logoColor=white" alt="AES-GCM encryption">
  <img src="https://img.shields.io/badge/cloud-none-1F2937?style=flat-square&logo=icloud&logoColor=white" alt="No cloud">
</p>

<p align="center">
  An encrypted, device-bound vault—not a cloud service. No account, cloud sync, analytics, telemetry, or remote access is required for the normal vault experience.
</p>

---

## What it does

Vaulthalla imports photos and videos into an encrypted on-device library. Once unlocked, it provides separate Images and Videos libraries, automatic filename-based grouping, full-screen viewing, playback, slideshow controls, media information, multi-selection, and permanent deletion.

The vault is deliberately **one-way**: it does not offer export, sharing, Save to Photos, Save to Files, or drag-out access to vault media.

### Import media your way

Vaulthalla has three established import paths. A Local Web Import server implementation is also under security review while its transport design is decided:

- **Photos** — select images and videos from the iPhone photo library.
- **Files** — import media selected with the system Files picker.
- **USB / Finder File Sharing** — transfer media over a cable to Vaulthalla’s File Sharing inbox, then explicitly import the waiting files from inside the app.
- **Local Web Import (transport under review)** — a local browser-upload server implementation; its current plaintext HTTP transport is not safe for sensitive media.

An optional **Delete originals after successful import** choice is available for imports. An original may be deleted after a new encrypted copy commits or an existing duplicate copy is verified. Deletion can fail or require confirmation from Photos.

Imports stream data rather than loading a large video all at once. Original media bytes are retained unchanged, and SHA-256 duplicate detection avoids storing the same source twice—even when it has a different name. The app reports imported, duplicate, failed, and retained-source results after an import.

### Browse and view privately

- Image and video libraries are separate.
- Compatible filenames are automatically organized into deterministic groups; unmatched files remain available in **Ungrouped**.
- Group and item grids use encrypted thumbnails.
- Image viewing supports fit/fill, pinch zoom, pan, and double-tap zoom.
- Video playback supports native controls, autoplay and looping preferences, and fit/fill modes.
- Slideshows and video playlists stay within the open group.
- An item’s original filename, size, type, and import date are available only in its unlocked info view.
- Multi-select items or whole groups for immediate, confirmed deletion. There is no Trash or undo.

## Security by design

Vaulthalla’s primary unlock binds the master password to the original device. Optional on-device PIN or Face ID wrappers provide alternate convenience unlock after setup.

| Security property | How Vaulthalla applies it |
| --- | --- |
| **Offline by default** | No account, cloud sync, telemetry, analytics, or remote vault access. |
| **Device-bound primary unlock** | Master-password unlock combines the password with a device-only Keychain secret; optional PIN/Face ID wrappers are separate on-device unlock paths. |
| **Authenticated encryption** | AES-GCM protects encrypted media, metadata, thumbnails, and structural integrity. |
| **Independent media keys** | Every imported item has its own random 256-bit key. |
| **Minimal lock-screen leakage** | Vault contents, counts, storage, groups, and activity stay hidden until unlock. |
| **One-way vault** | No export, sharing, Save to Photos, or Save to Files from the vault. |
| **Debugger detection** | Unlock (password, PIN, Face ID) is refused while a debugger is attached; detection fails closed and re-checks on every foreground return, locking the vault with an audit record. |
| **Integrity response** | Chunk verification reports corruption without silently repairing media. Confirmed, unrecoverable vault/key mismatch triggers resumable destruction; transient I/O or Keychain errors block access without wiping. |

### Device-bound encryption

- A random 256-bit Vault Root Key encrypts the vault.
- The root key is wrapped with a key derived from the master password **and** a random device secret.
- The device secret lives in the iOS Keychain with `ThisDeviceOnly` protection and does not synchronize through iCloud Keychain.
- Copying the vault container to another device is not enough to unlock it, even with the password.

### Password protection

- Master passwords support Unicode and must be 8–128 characters long.
- Password keys use PBKDF2-HMAC-SHA256 with a random salt.
- The work factor is calibrated when the vault is created to make password derivation deliberately expensive on that device.
- The password is not used to encrypt every media file directly.

### Encrypted media storage

- Each imported item receives its own random 256-bit media key.
- Media is encrypted in 1 MiB chunks using AES-GCM authenticated encryption.
- Chunk keys are derived with HKDF and are domain-separated by item, chunk number, and vault format.
- Encrypted metadata holds item details, keys, hashes, and thumbnails. Exact item sizes remain inside encrypted metadata.
- Fixed-size padded chunks reduce leakage of an individual item’s exact size.
- Integrity authentication detects modified or corrupted encrypted content.

### Access and screen protection

- Before unlock, the app shows a neutral lock screen—not thumbnails, media counts, storage use, groups, or recent activity.
- Password unlock is always available. Optional PIN and Face ID convenience unlock can be enabled on the device.
- Failed unlocks are rate-limited with increasing delays.
- An optional auto-destroy policy can destroy vault keys and remove the vault after a configured number of failed password attempts.
- The app locks when it leaves the foreground. Optional screenshot and screen-recording protection obscures the interface and can lock on capture detection; it cannot guarantee prevention of OS or external-camera captures.
- An opaque privacy cover protects the App Switcher preview.
- A debugger-attached process can never unlock the vault: detection blocks password, PIN, and Face ID unlock, fails closed when the process query errors, and is re-checked every time the app returns to the foreground (a detection locks the vault with an audit record). Detection is defense-in-depth against a compromised device, not a claim of tamper-proofness.
- Security Activity is optional and **off by default**. When enabled, its encrypted history is visible only after unlock and records time, unlock method, and result—not entered passwords or PINs. Turning it off clears the current history and rotates its key.

## Local Web Import

Local Web Import is a browser-upload server implementation for devices on the same LAN. Its current plaintext HTTP transport does not authenticate the iPhone: an active LAN attacker could intercept the PIN, session token, and media. A token alone does not solve this. **Do not treat this transport as secure or use it for sensitive media.** The transport and pairing design are still undecided.

The server implementation has these limits:

- It accepts browser uploads only; it cannot list, browse, search, download, or otherwise expose vault content.
- Every session has a fresh cryptographically random token.
- Only the import page and token-gated upload route are accepted; the token does not protect against interception over HTTP.
- Uploads stream directly into encrypted storage rather than being staged as plaintext files.
- The listener stops when the user stops it, the vault locks, the app backgrounds, or the session expires.

## Vault maintenance

While the vault is unlocked, Vaulthalla can:

- **Verify Vault** — authenticate encrypted chunks, validate the encrypted index, recompute item hashes, and report corruption without silently repairing or deleting data.
- **Compact Vault** — reclaim physical space from reusable encrypted chunks after deletions, without creating plaintext vault media on disk.
- Show encrypted-storage statistics, integrity state, and the last successful verification time.

Long imports and maintenance tasks are transactional and can use best-effort continued processing where iOS permits. Sensitive UI still locks when the app backgrounds.

## Privacy boundaries

Vaulthalla has no password recovery, recovery phrase, reset path, or cloud recovery. Losing the master password, the device-binding secret, the app container, or the device can make the vault permanently inaccessible.

Current vault, audit, and app-managed staging files are marked to be excluded from device backups. This does not prove that older backups, snapshots, or physical flash copies were erased. Keychain vault material is device-only and does not migrate to another device.

Deleting an item removes its active key from the current encrypted index and removes it from the vault state. Vaulthalla does not claim guaranteed physical overwrite of historical bytes, snapshots, or backups.

Video playback never writes decrypted media to disk: the player streams decrypted byte ranges through an in-memory resource loader. On launch the app sweeps plaintext temporary files left behind by previous app versions that decrypted to disk; physical erasure of such legacy files is not guaranteed.

The USB/Finder inbox is an intentional plaintext staging area until the user imports or removes its files. Photos and Files imports may ask Apple’s system pickers to retrieve media the user explicitly selects, including from iCloud-backed libraries or drives. Those system-managed transfers are separate from Vaulthalla’s normal local-only vault behavior.

## Built with Apple frameworks

Vaulthalla is a native SwiftUI iOS app. It uses Apple frameworks including CryptoKit, Security/Keychain, LocalAuthentication, CommonCrypto, Photos/PhotosUI, AVFoundation, Network, and UniformTypeIdentifiers. It has no third-party SDK dependencies.

## Requirements

- Xcode with the iOS 26 SDK
- iPhone running iOS 26 or later

Open `Vaulthalla.xcodeproj` in Xcode, choose an iPhone destination, and run the **Vaulthalla** scheme.
