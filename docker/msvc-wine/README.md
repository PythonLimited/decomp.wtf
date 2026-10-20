# msvc-wine: the byte-exact MSVC 2015 U3 toolchain

`cl` 19.00.24210 (VS2015 Update 3, toolset 14.00) under wine in a `linux/amd64` container,
with the toolset's own headers. This is the driver that reproduces ORION-era MSVC output
byte for byte; clang-cl stays the approximate fallback for everything else.

Microsoft no longer hosts the 2015 packages anywhere scriptable (the `aka.ms/vs/14`
channel is dead, the old `download.microsoft.com` links 404, there is no VS2015 NuGet
toolset, and msvc-wine's own `vsdownload.py` never covered major 14). So the image is
built from an **ISO you already have or download yourself**:

* `my.visualstudio.com` (free account) → Downloads → *Visual Studio 2015 Update 3* → ISO, or
* the archive.org mirror of that DVD: item
  `en_visual_studio_community_2015_with_update_3_x86_x64_dvd_8923300`
  (7.6 GB, md5 `82a696bea06bac6c4a00bf59a8ae77d6`).

## Build

    ./build.sh /path/to/en_visual_studio_community_2015_with_update_3.iso

A throwaway ubuntu container unpacks the ISO's `vc_*` packages with msitools into
`staging/`, then the image copies the `VC/` tree in and self-tests `cl` at build time
(so a broken toolset fails the build, not the first match attempt). Delete `staging/`
afterwards to reclaim ~2 GB; the image itself is ~2.5 GB.

## Use

In a PE project's compiler card (or config):

    "compiler": {"image": "dcore-msvc-wine:2015u3", "command": "cl", "flags": ["/O2"]}

`command` may stay empty: with an MSVC build guess and an image set, dcore resolves the
driver to `cl` and picks `--platform linux/amd64` from the target (`docker_platform`).
The wrapper `cl` bridges the `/work` paths docker passes into wine's `Z:\work`.
