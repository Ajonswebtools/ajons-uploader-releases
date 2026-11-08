# Ajons Uploader

A small desktop tool that uploads your video file **directly from your computer to Google/YouTube**. The Ajons web service only starts the upload session and checks progress — your video file is never uploaded to Ajons servers.

## Download

Get the file for your computer from the **Releases** page:
- **Windows:** `ajons-uploader-windows-x64.exe`
- **macOS (Apple Silicon):** `ajons-uploader-macos-arm64`
- **macOS (Intel):** `ajons-uploader-macos-intel`
- **Linux:** `ajons-uploader-linux-x64`

Also download `SHA256SUMS` and verify the file before running it.

## Verify the download (recommended)

**Windows (PowerShell):**
```powershell
Get-FileHash .\ajons-uploader-windows-x64.exe -Algorithm SHA256
```
Compare the hash to the matching line in `SHA256SUMS`.

**macOS / Linux:**
```bash
shasum -a 256 ajons-uploader-<your-file>
# or: sha256sum -c SHA256SUMS  (in the folder with the files)
```

## Install (one time)

You can run the downloaded file directly, or install it to your user folder:

```text
ajons-uploader install
```

- **Windows:** installs to `%LOCALAPPDATA%\Ajons` and adds it to your user PATH (no admin required).
- **macOS / Linux:** installs to `~/.local/bin` and prints PATH guidance if needed.

Open a **new** terminal after install, then check:

```text
ajons-uploader status
```

## Pair your account (one time)

```text
ajons-uploader pair
```

1. A short code and a link are shown.
2. The link may open in your browser automatically. If not, open it yourself.
3. Sign in with the Google account connected to your YouTube channel and approve access.
4. The tool shows **“Paired successfully.”** when done.

Your sign-in is stored only on **your computer** (system keychain when available, or a protected local file).

## Upload a video

Uploads are usually started for you by the Ajons assistant/service with an upload session ID. For a detached (background) upload:

```text
ajons-uploader upload --session <SESSION_ID> --file "C:\path\to\video.mp4" --detach
```

Check progress:

```text
ajons-uploader status --session <SESSION_ID> --json
```

If an upload is interrupted, run the same upload command again — it resumes when possible.

## Uninstall

```text
ajons-uploader uninstall
```

## Safety notes

- Your video goes **directly to Google/YouTube**; it is not stored by Ajons.
- Verify `SHA256SUMS` before running a downloaded binary.
- If you did not request a pairing/upload, do not approve the code.

## License

See `LICENSE`. Source code for this distributed tool is provided under the terms stated there (proposal included in this repository).
