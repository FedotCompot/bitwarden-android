# Plan: Password-protected export/import for Bitwarden Authenticator

## 0. Scope (confirmed with requester)

| Question | Decision |
|----------|----------|
| Which new export options? | **One**: `.json (Password protected)`. See [§1.1](#11-why-not-encrypted-csv) for why encrypted CSV was dropped. |
| Import password UX | **Auto-detect + prompt.** Keep the single `Bitwarden (.json)` entry in the import picker; detect `encrypted: true` in the chosen file and prompt for the password in a dialog. |

**Change type:** New Feature — new crypto component in the data layer, a new export format, and a new
branch in the import flow. Multi-phase, new files plus modifications.

---

## 1. Findings that shape the design

### 1.1 Why not "encrypted CSV"

The original ask was for two options, `.json` and `.csv`, both encrypted. Bitwarden has exactly one
encrypted export format across every client: **password-protected JSON**. There is no encrypted CSV
anywhere in the ecosystem, and an "encrypted `.csv`" would be opaque ciphertext with a misleading
extension that no other Bitwarden client could read. Scope was reduced to encrypted JSON only, which
is byte-compatible with Password Manager and the web vault.

### 1.2 The Bitwarden SDK cannot do this for an account-less app

This is the single most important constraint and it drives the whole plan.

The main app produces its encrypted export via
`app/src/main/kotlin/com/x8bit/bitwarden/data/vault/datasource/sdk/VaultSdkSourceImpl.kt:537` →
`client.exporters().exportVault(folders, ciphers, ExportFormat.EncryptedJson(password))`. That path is
unusable here:

- `exportVault` takes **encrypted SDK `Cipher` objects** and requires a `Client` whose user crypto has
  been initialized with a real account key. See
  `app/src/main/kotlin/com/x8bit/bitwarden/data/vault/repository/VaultRepositoryImpl.kt:479` — it pulls
  ciphers from disk via `toEncryptedSdkCipher()` and passes `userId`. The Authenticator's client
  (`authenticator/src/main/kotlin/com/bitwarden/authenticator/data/platform/manager/SdkClientManagerImpl.kt`)
  is a bare `Client` with a null token provider and no crypto state.
- The SDK exposes **no decryption path at all** for password-protected exports. `ExporterClient`'s
  uniffi surface is `export_vault`, `export_organization_vault`, `export_cxf`, `import_cxf` — import of
  an encrypted JSON export is not among them, on any client.
- `bitwarden-crypto` exports only *custom types* over uniffi (`EncString`, `SymmetricCryptoKey`,
  `Kdf`, `PasswordProtectedKeyEnvelope`, …), not the derive/encrypt *functions*. There is no
  `PinKey::derive` or `encrypt_with_key` callable from Kotlin.

**Consequence:** the envelope has to be built and opened in Kotlin, inside this repo.

**Flag for the requester / PR reviewer:** hand-rolling Bitwarden-format crypto in a client is exactly
the kind of change Bitwarden maintainers push back on, and
<https://contributing.bitwarden.com/contributing/> asks that significant changes be discussed on the
Community Forums / GitHub Discussions *before* a PR. Two options:

- **(a) Ship the Kotlin implementation** (this plan). Isolated in one class, format-compatible,
  validated against SDK-produced test vectors. Actionable today, entirely within this repo.
- **(b) Upstream first**: add an account-less `encrypt_export(password, data, kdf)` /
  `decrypt_export(password, envelope)` pair to `bitwarden-exporters` in `sdk-internal`, release an SDK
  bump, then have the Authenticator call it. Correct long-term home for the crypto, but it blocks on
  another repo and a version bump of `bitwardenSdk` (currently `3.0.0-8427-16db8e99` in
  `gradle/libs.versions.toml:32`).

Recommendation: build (a) behind a narrow `ExportEncryptionManager` interface so that swapping in (b)
later is a one-file change, and open the forum discussion in parallel.

### 1.3 The envelope format (normative)

Mirror `crates/bitwarden-exporters/src/encrypted_json.rs` in `bitwarden/sdk-internal`:

```json
{
  "encrypted": true,
  "passwordProtected": true,
  "salt": "<base64 of 16 random bytes>",
  "kdfType": 0,
  "kdfIterations": 600000,
  "kdfMemory": null,
  "kdfParallelism": null,
  "encKeyValidation_DO_NOT_EDIT": "<EncString of a random UUIDv4>",
  "data": "<EncString of the cleartext export JSON>"
}
```

Key derivation and encryption:

1. `keyMaterial = PBKDF2-HMAC-SHA256(password, salt, iterations, 32 bytes)`.
   **The salt is the base64 *string* itself, UTF-8 encoded — not the decoded bytes.** The SDK source
   carries an explicit comment about this; getting it backwards silently produces files no other
   client can open.
2. `stretched = HKDF-Expand-SHA256(keyMaterial)` → `encKey = expand(info = "enc", 32)`,
   `macKey = expand(info = "mac", 32)`.
3. `EncString` type 2 (`AesCbc256_HmacSha256_B64`), encrypt-then-MAC:
   `"2." + b64(iv) + "|" + b64(ciphertext) + "|" + b64(mac)` where
   `iv` = 16 random bytes, `ciphertext` = AES-256-CBC/PKCS7 over the UTF-8 plaintext, and
   `mac` = HMAC-SHA256(macKey, iv ‖ ciphertext).
4. `kdfType` 0 = PBKDF2, 1 = Argon2id. Only PBKDF2 needs to be *written*; **both must be readable**
   on import, since a user may bring a file exported from the web vault with Argon2id settings.
   Argon2id is not in the JDK — see the risk table.

`encKeyValidation_DO_NOT_EDIT` is a random UUIDv4 encrypted with the same key. On import, decrypt it
first: if the MAC check fails, the password is wrong — report that specifically rather than a generic
parse error.

> The implementing session **must** verify steps 1–3 against the current
> `crates/bitwarden-crypto/src/keys/{pin_key.rs,utils.rs}` and `enc_string/` sources rather than
> trusting this summary, and must pin the result with a real cross-client test vector (§6).

### 1.4 What the cleartext payload is

Unchanged: the existing `ExportJsonData`
(`authenticator/.../data/authenticator/manager/model/ExportJsonData.kt`), serialized exactly as the
plaintext JSON export does today, with `encrypted = false` in the inner document. Only the wrapping
changes. This keeps the existing `BitwardenExportParser` usable verbatim on the decrypted bytes.

---

## 2. Pattern anchors

1. **`app/src/main/kotlin/com/x8bit/bitwarden/ui/platform/feature/settings/exportvault/ExportVaultViewModel.kt`
   + `ExportVaultScreen.kt:226-269`** — the file-password UX to mirror: password + confirm fields shown
   conditionally on `JSON_ENCRYPTED`, validation ordering (blank → blank confirm → mismatch), strings
   `file_password` / `confirm_file_password` / `password_used_to_export`, and
   `ExportVaultFormatExtensions.kt` for the `.json (Password Protected)` label.
2. **`authenticator/src/main/kotlin/com/bitwarden/authenticator/ui/platform/feature/settings/export/ExportViewModel.kt`**
   — the screen being extended; keep its simpler `ExportDataResult` shape and no-`SavedStateHandle`
   design (see §3 decision on password persistence).
3. **`authenticator/src/main/kotlin/com/bitwarden/authenticator/data/platform/manager/imports/`
   (`ImportManagerImpl.kt`, `parsers/BitwardenExportParser.kt`, `parsers/ExportParser.kt`)** — parser
   dispatch, and the `parseForResult` try/catch that maps exceptions to user-facing
   `ExportParseResult.Error` text. New failure modes plug in here.

**Integration points:** `PlatformManagerModule.kt:118` (Hilt binding for `ImportManager`, and where
the new manager gets provided), `AuthenticatorRepositoryModule.kt`, and
`ui/src/main/res/values/strings.xml` + `strings_non_localized.xml` for labels.

---

## 3. Architecture

```
  EXPORT                                    IMPORT
┌──────────────────────┐               ┌──────────────────────┐
│ ExportScreen         │               │ ImportingScreen      │
│  + file password     │               │  + password dialog   │
│  + confirm password  │               │    (shown on         │
└──────────┬───────────┘               │     PasswordRequired)│
           │                           └──────────┬───────────┘
┌──────────▼───────────┐               ┌──────────▼───────────┐
│ ExportViewModel      │               │ ImportingViewModel   │
└──────────┬───────────┘               └──────────┬───────────┘
           │                                      │
           └──────────────┬───────────────────────┘
                          │
             ┌────────────▼─────────────┐
             │ AuthenticatorRepository  │
             │  exportVaultData(fmt,    │
             │    uri, password?)       │
             │  importVaultData(fmt,    │
             │    fileData, password?)  │
             └──────┬────────────┬──────┘
                    │            │
        ┌───────────▼──┐   ┌─────▼──────────┐
        │ ImportManager│   │ FileManager    │
        └───────┬──────┘   └────────────────┘
                │
    ┌───────────▼──────────────┐
    │ ExportEncryptionManager  │ ← NEW. The only place crypto lives.
    │  encrypt(json, password) │   PBKDF2 → HKDF stretch → AES-CBC + HMAC
    │  decrypt(envelope, pwd)  │   Returns sealed results, never throws.
    └───────────┬──────────────┘
                │
    ┌───────────▼──────────────┐
    │ javax.crypto / java.security │  (swap target for a future SDK API)
    └──────────────────────────┘
```

### Design decisions

| Decision | Resolution | Rationale |
|----------|-----------|-----------|
| Where does crypto live? | New `ExportEncryptionManager` interface + `Impl` under `data/platform/manager/crypto/` | Single seam; swapping to an SDK-provided API later touches one file. Testable without Robolectric. |
| Encrypt before or after serializing? | Serialize `ExportJsonData` to a string, then encrypt that string | Reuses the existing plaintext path and `BitwardenExportParser` verbatim; matches SDK behaviour. |
| How does the repo signal "wrong password"? | New `ImportDataResult.PasswordRequired` and `ImportDataResult.IncorrectPassword` | Lets the ViewModel show the password dialog / re-prompt with an inline error instead of a generic failure dialog. |
| Import format picker entry | Unchanged — reuse `BITWARDEN_JSON` | Per §0. `BitwardenExportParser` peeks at `encrypted` and branches. |
| Persist the file password in `SavedStateHandle`? | **No** | The main app writes `filePasswordInput` into saved state (`ExportVaultViewModel.kt:87`); do not copy that here. `ExportState` in the Authenticator is not `@Parcelize`d today, so keep passwords in-memory only and clear them after use. |
| Password strength meter on export? | Optional, defer to a follow-up | `client.auth().passwordStrength(password, email, additionalInputs)` works on a bare `Client`, but requires an email the Authenticator does not have. Passing `""` is unvalidated. Not worth blocking on. |
| Confirm-password field on export? | **Yes** | An unrecoverable typo in an export password means permanent data loss; matches the main app. |
| KDF written on export | PBKDF2, 600 000 iterations | Matches `KdfParamsConstants.DEFAULT_PBKDF2_ITERATIONS` and current web-vault defaults. |

---

## 4. File inventory

### Create

| File | Type | Pattern reference |
|------|------|-------------------|
| `authenticator/src/main/kotlin/com/bitwarden/authenticator/data/platform/manager/crypto/ExportEncryptionManager.kt` | Manager interface | `imports/ImportManager.kt` |
| `.../data/platform/manager/crypto/ExportEncryptionManagerImpl.kt` | Manager impl | `imports/ImportManagerImpl.kt` |
| `.../data/platform/manager/crypto/model/EncryptExportResult.kt` | Sealed result | `repository/model/ExportDataResult.kt` |
| `.../data/platform/manager/crypto/model/DecryptExportResult.kt` | Sealed result | `imports/model/ExportParseResult.kt` |
| `.../data/authenticator/manager/model/EncryptedExportJsonData.kt` | `@Serializable` envelope | `manager/model/ExportJsonData.kt` |
| `authenticator/src/test/kotlin/.../crypto/ExportEncryptionManagerTest.kt` | Unit test | `imports/ImportManagerTest.kt` |
| `authenticator/src/test/kotlin/.../feature/settings/importing/ImportingViewModelTest.kt` | ViewModel test (none exists today) | `export/ExportViewModelTest.kt` |

### Modify

| File | Change | Risk |
|------|--------|------|
| `.../ui/platform/feature/settings/export/model/ExportVaultFormat.kt` | Add `JSON_ENCRYPTED` | Low |
| `.../ui/platform/util/ExportFormatExtensions.kt` | `displayLabel` → `json_extension_formatted(password_protected)`; `fileExtension` → `"json"` | Low |
| `.../data/authenticator/repository/AuthenticatorRepository.kt` + `Impl.kt` | `exportVaultData(format, fileUri, password: String?)`; `importVaultData(format, fileData, password: String?)`; new `encodeVaultDataToEncryptedJson` | Medium |
| `.../ui/platform/feature/settings/export/ExportViewModel.kt` | Password + confirm fields in state, validation, pass password through, clear on success | Medium |
| `.../ui/platform/feature/settings/export/ExportScreen.kt` | Conditional `BitwardenPasswordField` × 2 | Low |
| `.../data/platform/manager/imports/ImportManager.kt` + `Impl.kt` | `import(format, byteArray, password: String?)`; map new parse results | Medium |
| `.../data/platform/manager/imports/parsers/BitwardenExportParser.kt` | Peek `encrypted`; decrypt when true | **High** — shared by every Bitwarden JSON import; plaintext path must not regress |
| `.../data/platform/manager/imports/model/ImportDataResult.kt` | Add `PasswordRequired`, `IncorrectPassword` | Low |
| `.../data/platform/manager/imports/model/ExportParseResult.kt` | Add matching cases | Low |
| `.../ui/platform/feature/settings/importing/ImportingViewModel.kt` | Hold pending file bytes, handle `PasswordRequired`, retry with password | Medium |
| `.../ui/platform/feature/settings/importing/ImportingScreen.kt` | Password-prompt dialog | Low |
| `.../data/platform/manager/di/PlatformManagerModule.kt` | Provide `ExportEncryptionManager`; inject into `ImportManagerImpl` | Low |
| `ui/src/main/res/values/strings.xml` | New user-facing strings (§7) | Low |
| `authenticator/src/test/kotlin/.../export/ExportViewModelTest.kt` | Cover the new format + validation | Low |
| `authenticator/src/test/kotlin/.../imports/parsers/BitwardenExportParserTest.kt` | Encrypted round-trip + wrong password | Low |

---

## 5. Phases

### Phase 1 — Crypto core

**Goal:** A standalone, fully tested `ExportEncryptionManager` that round-trips with the SDK format.
No UI, no wiring.

**Files:** create `ExportEncryptionManager.kt`, `ExportEncryptionManagerImpl.kt`,
`EncryptExportResult.kt`, `DecryptExportResult.kt`, `EncryptedExportJsonData.kt`,
`ExportEncryptionManagerTest.kt`.

**Tasks:**
1. Model the envelope with `kotlinx.serialization`; `@SerialName("encKeyValidation_DO_NOT_EDIT")` for
   the validation field; nullable `kdfMemory` / `kdfParallelism`.
2. Implement PBKDF2 → HKDF-Expand stretch → AES-256-CBC + HMAC-SHA256 encrypt-then-MAC, and the
   `EncString` type-2 string codec. Verify MACs with a **constant-time** comparison
   (`MessageDigest.isEqual`), and check the MAC *before* attempting to decrypt.
3. Inject `SecureRandom` (or a small seam) for IV/salt/UUID so tests are deterministic; run the whole
   thing on the IO dispatcher via the injected `DispatcherManager` — 600k PBKDF2 iterations is
   ~0.5–2 s on mid-range hardware and must not touch the main thread.
4. Return sealed results (`Success`, `IncorrectPassword`, `UnsupportedKdf`, `Error`); never throw out
   of this class, per the repo's "no exceptions from the data layer" rule.
5. Reject `kdfType` values other than 0/1 and out-of-range iteration counts before doing any work.

**Verification:**
```bash
./gradlew authenticator:testDebugUnitTest --tests "*ExportEncryptionManagerTest*"
```
Round-trip tests, wrong-password test, tampered-ciphertext test, and **at least one fixed test vector
produced by a real Bitwarden client** (see §6) asserted byte-for-byte.

**Skills:** `implementing-android-code`, `testing-android-code`.

---

### Phase 2 — Export path

**Goal:** The new format is selectable and produces a correct file.

**Files:** modify `ExportVaultFormat.kt`, `ExportFormatExtensions.kt`, `AuthenticatorRepository.kt` +
`Impl.kt`, `ExportViewModel.kt`, `ExportScreen.kt`, `ExportViewModelTest.kt`; add strings.

**Tasks:**
1. Add `JSON_ENCRYPTED` to `ExportVaultFormat`, plus label and `"json"` extension.
2. Thread `password: String?` through `exportVaultData`; add
   `encodeVaultDataToEncryptedJson(fileUri, password)` beside the existing two private encoders in
   `AuthenticatorRepositoryImpl.kt:301-344`.
3. ViewModel: `filePasswordInput` / `confirmFilePasswordInput` in state; validate blank → blank
   confirm → mismatch in the same order as the main app; clear both after a successful export.
4. Screen: two `BitwardenPasswordField`s rendered only for `JSON_ENCRYPTED`, sharing one
   `showPassword` toggle (mirrors `ExportVaultScreen.kt:226-269`), with test tags
   `FilePasswordEntry` / `ConfirmFilePasswordEntry`.
5. Keep the existing export-confirmation dialog; validation runs before it.

**Verification:** `./gradlew authenticator:testDebugUnitTest --tests "*Export*"`; manually export and
confirm the resulting file **imports cleanly into the web vault** as a password-protected Bitwarden
JSON.

---

### Phase 3 — Import path

**Goal:** Choosing an encrypted file prompts for a password and imports.

**Files:** modify `BitwardenExportParser.kt`, `ImportManager.kt` + `Impl.kt`, `ImportDataResult.kt`,
`ExportParseResult.kt`, `AuthenticatorRepository`, `ImportingViewModel.kt`, `ImportingScreen.kt`;
create `ImportingViewModelTest.kt`; extend `BitwardenExportParserTest.kt`.

**Tasks:**
1. `BitwardenExportParser`: decode into a lenient probe of the `encrypted` field. `false`/absent →
   existing path unchanged. `true` + no password → `ExportParseResult.PasswordRequired`. `true` +
   password → decrypt, then feed the plaintext into the *existing* `importJsonFile` logic.
2. Map the new parse results through `ImportManagerImpl.processParseResult` to
   `ImportDataResult.PasswordRequired` / `IncorrectPassword`.
3. `ImportingViewModel`: on `PasswordRequired`, stash the already-read `FileData` in state (**not** in
   `SavedStateHandle`) and raise a `DialogState.PasswordPrompt`; on submit, re-invoke
   `importVaultData` with the password; on `IncorrectPassword`, re-show the prompt with an inline
   error rather than dropping the user back to file selection.
4. Screen: password dialog built on `BitwardenPasswordField` inside an `AlertDialog`
   (`BitwardenTextEntryDialog.kt` is the closest existing shape but is plaintext — do not reuse it as-is
   for a password; either add a `BitwardenPasswordEntryDialog` to `:ui` or build it locally).
5. Clear the stashed file bytes and the password from state on success, cancel, and navigation away.

**Verification:** `./gradlew authenticator:testDebugUnitTest --tests "*Import*"`; manual round-trip
export → import; manual import of a **web-vault-produced** password-protected file.

---

### Phase 4 — Polish and verify

**Tasks:**
1. Full check: `./gradlew authenticator:testDebugUnitTest detekt lint`.
2. Confirm the new strings use typographic apostrophes and are named from their own content
   (per `.claude/CLAUDE.md`), and that non-translatable labels went to `strings_non_localized.xml`.
3. Run `bitwarden-delivery-tools:perform-preflight` before committing.
4. Manual pass with **Don't keep activities** enabled: process death mid-import must not leave a stale
   password or file reference, and must not crash.

---

## 6. Test vectors (do not skip)

A format-compatibility bug here is invisible in unit tests that only check self-round-trip. Before
Phase 1 is considered done, obtain at least one **externally produced** password-protected export:

- Export a password-protected `.json` from the web vault or the Password Manager Android app with a
  known password, commit it as a test resource, and assert the Kotlin implementation decrypts it to
  the expected plaintext.
- Conversely, take a file produced by the Kotlin implementation and confirm the web vault imports it.

Without both directions, "compatible with the main app" is an unverified claim.

---

## 7. Strings

Add to `ui/src/main/res/values/strings.xml` (existing reusable ones: `file_password`,
`confirm_file_password`, `password_protected`, `password_used_to_export`,
`master_password_confirmation_val_message`, `validation_field_required`):

| Suggested name | Text |
|----------------|------|
| `enter_the_password_used_to_encrypt_this_file` | Enter the password used to encrypt this file. |
| `the_password_you_entered_is_incorrect` | The password you entered is incorrect. |
| `this_file_is_password_protected` | This file is password protected. |
| `the_file_uses_an_unsupported_encryption_setting` | The file uses an unsupported encryption setting. |

Names follow the project rule of deriving the resource name from the text itself, not generic
`_message` / `_title` suffixes.

---

## 8. Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Format mismatch with other clients (salt encoding, HKDF info strings, MAC input order) | **High** | **High** | §6 bidirectional test vectors; read the Rust source, not this document's summary |
| Hand-rolled crypto rejected in review | Medium | High | Isolated behind one interface; raise the SDK-side alternative (§1.2b) on the Community Forums before opening the PR |
| Argon2id (`kdfType: 1`) files unreadable — not in the JDK | **High** | Medium | Detect and fail with a clear message (`the_file_uses_an_unsupported_encryption_setting`) rather than a generic parse error. Adding an Argon2 dependency is a separate decision; flag it rather than silently pulling one in |
| 600k PBKDF2 iterations block the UI | Medium | Medium | Run on the injected IO dispatcher; loading dialog already exists on both screens |
| Password leaks into saved state or logs | Medium | High | No `SavedStateHandle` persistence for password fields; no password in any `Timber` call; clear state after use |
| `BitwardenExportParser` regression breaks plaintext Bitwarden import | Medium | High | Probe `encrypted` leniently and leave the existing code path untouched; keep all existing `BitwardenExportParserTest` cases green |
| Wrong password reported as a corrupt-file error | Medium | Low | Decrypt `encKeyValidation_DO_NOT_EDIT` first and branch on MAC failure |

---

## 9. Verification summary

**Automated**
```bash
./gradlew authenticator:testDebugUnitTest
```
```bash
./gradlew detekt lint
```

**Manual**
1. Export `.json` (Password protected) → file is a valid envelope with `encrypted: true`.
2. Re-import that file into the Authenticator → password prompt → items restored.
3. Wrong password → inline error, prompt stays open, no items imported.
4. Import an unencrypted Bitwarden `.json` → no prompt, behaviour unchanged.
5. Import a web-vault-produced password-protected file → succeeds.
6. Import an Argon2id file → clear "unsupported encryption setting" message, no crash.
7. "Don't keep activities" on, backgrounded mid-flow → no crash, no retained password.

---

## 10. Out of scope / noted in passing

- **Pre-existing bug** in `AuthenticatorRepositoryImpl.kt:319` — `toCsvFormat()` emits 9 fields against
  a 6-column header (`folder,favorite,type,name,login_uri,login_totp`), so the plaintext CSV export is
  malformed. Unrelated to this work; worth a separate fix.
- Encrypted CSV (§1.1).
- Password-strength indicator on the export screen (§3).
- Argon2id *writing* — PBKDF2 only on export.
