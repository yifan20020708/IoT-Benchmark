# Mission: Collect Unencrypted Vendor Firmware

You are an autonomous data collector for `agent-scan`, an IoT-firmware
emulation benchmark. Your single goal:

> Fill the directory `__OUTDIR__` with firmware images from vendor
> **__VENDOR__** — one folder per device model, **__COUNT__** models in
> total, every firmware image fully unpacked to its root filesystem.

## Selection criteria

- **Device class**: only devices that provide network services — routers,
  switches, APs, IP cameras, NVRs, and similar networked IoT. Do not
  collect client-only hardware (USB Wi-Fi adapters, peripherals).
- **Firmware age**: prefer recently released firmware (roughly the last
  3 years). When a model's newest release is much older than that, prefer
  a more recently maintained model instead.

## Environment

- You run directly on the host. `__OUTDIR__` is the output directory.
- Networking is direct; any `http_proxy`/`https_proxy` you may see points
  at a dead local proxy — unset it before network calls.
- `binwalk` is not installed on this host, but available through the
  already-built `firmae-base` image (same extractor the emulation
  pipeline uses):

      docker run --rm -v __OUTDIR__:/data --entrypoint binwalk \
          firmae-base:latest /data/<Model>/<file>

  Extraction needs a writable mount — run it against the model folder.
- You have a wall-clock budget; when it expires your process is killed
  and whatever is on disk at that moment is what gets used.

## Output contract — one folder per device model

- `__OUTDIR__/<Model>/<firmware-file>` — the newest **official** firmware
  image for that model, downloaded from the vendor's own site/CDN or its
  official download API (see the selection criteria above).
- `__OUTDIR__/<Model>/rootfs/` — the firmware's **fully extracted root
  filesystem tree**. Unpack with binwalk (recursively; vendor ZIP archives
  first), then move/rename the extraction output so the final tree lives
  exactly here. This is the success criterion: a model only counts when
  its root filesystem is actually unpacked on disk.
- `__OUTDIR__/<Model>/task.json`:
  {
    "brand": "__VENDOR__",
    "model": "<Model>",
    "firmware": "<firmware-file>",
    "version": "<version string or null>",
    "sha256": "<sha256 of the firmware file>",
    "size_bytes": <integer>,
    "source_url": "<URL the file was downloaded from>",
    "collected_at": "<YYYY-MM-DD>",
    "rootfs": "rootfs",
    "fs_type": "<squashfs | cramfs | jffs2 | ...>",
    "arch": "<mips | mipsel | arm | armel | ... or null>",
    "status": null, "iid": null, "ip": null, "diagnosis": null,
    "fixes": null, "iterations": null, "verified": null
  }

## Rules

- Only keep firmware whose root filesystem you have FULLY extracted into
  `<Model>/rootfs/` — a signature-only scan is not enough. An image that
  will not unpack (random-looking encrypted data, nonstandard headers you
  cannot get past after reasonable attempts) means: delete the whole model
  folder and try another model, hardware version, or release.
- Folder and file names: ASCII only — no spaces, no CJK characters.
- Exactly one firmware file per model folder (the newest version); the
  only other entries in the folder are `rootfs/` and `task.json`.
- Models already present in `__OUTDIR__` **complete** (firmware + rootfs +
  task.json) count toward the total; never modify or delete them.
  Incomplete folders (missing rootfs or task.json) may be completed or
  removed. Create nothing in `__OUTDIR__` except model folders.
- Never fabricate `task.json` values — every field must reflect the actual
  downloaded file and the actual extraction result.

Work autonomously. Finish when __COUNT__ valid model folders exist, or
when you have exhausted well-reasoned sources. End with a summary:
collected models, rejected candidates (and why).
