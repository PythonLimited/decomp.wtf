#!/usr/bin/env bash
# Builds dcore-msvc-wine:2015u3 from a Visual Studio 2015 Update 3 Community ISO.
#
#   ./build.sh /path/to/en_visual_studio_community_2015_with_update_3.iso
#
# Everything runs inside docker: a throwaway container unpacks the ISO's vc_* packages
# (msitools), the image build copies the toolset in and self-tests cl. No 7z/msitools
# needed on the host. The ISO itself is never copied — only the extracted VC tree sits
# in staging/ until the image is built (delete staging/ afterwards to reclaim space).
set -euo pipefail

ISO="${1:?usage: build.sh </path/to/vs2015-u3.iso>}"
ISO="$(cd "$(dirname "$ISO")" && pwd)/$(basename "$ISO")"
HERE="$(cd "$(dirname "$0")" && pwd)"
STAGING="$HERE/staging"
IMAGE="dcore-msvc-wine:2015u3"

[ -f "$ISO" ] || { echo "error: $ISO not found" >&2; exit 1; }
command -v docker >/dev/null || { echo "error: docker is not on PATH" >&2; exit 1; }

mkdir -p "$STAGING/iso" "$STAGING/tools"
rm -rf "$STAGING/iso"  # fresh extraction: stale package leftovers must not join the msiextract pass
mkdir -p "$STAGING/iso"

echo "==> unpacking the ISO's VisualC_D14 packages (a few minutes; reads ~1-2 GB)"
docker run --rm --platform linux/amd64 \
	-v "$(dirname "$ISO"):/iso:ro" -v "$STAGING:/out" \
	-e "ISO_NAME=$(basename "$ISO")" \
	ubuntu:22.04 bash -c '
		set -euo pipefail
		apt-get update -qq
		apt-get install -y -qq p7zip-full msitools >/dev/null
		mkdir -p /out/iso /out/tools
		# The VS2015 (Dev14) toolsets live in packages/VisualC_D14/; the plain packages/vc_*
		# at the root are the 12.0-era compatibility toolsets (cl 18.00) and must not mix in.
		# Each package is a folder with its .msi and sidecar .cab: take whole folders.
		7z l "/iso/$ISO_NAME" | awk "{print \$NF}" \
			| grep -E "^packages/VisualC_D14/(VC_Tools\.Core/|VC_Tools\.(X64|X86)\.(Nat|X86|X64|Base)/|VC_CRT\.Headers/|VC_Tools\.X64\.Nat\.Res/enu/)" > /tmp/d14.txt
		# The SDK header sets the product compiles against: the Windows 10 Universal CRT
		# (corecrt.h, which 2015s crtdefs.h includes) and the 8.1 um/shared trees (windows.h).
		# Without them every real game compile dies at <cstdint>. Extracted by direct 7z
		# filter - SDK file names carry spaces, so the awk listing above would cut them.
		echo "    extracting $(wc -l < /tmp/d14.txt) toolset package files + the SDK packages"
		7z x -y -o/out/iso "/iso/$ISO_NAME" @/tmp/d14.txt >/dev/null
		7z x -y -o/out/iso "/iso/$ISO_NAME" "packages/Win10_UniversalCRTSDK/*" "packages/Win81_SDK/*" >/dev/null
		find /out/iso/packages/VisualC_D14 /out/iso/packages/Win10_UniversalCRTSDK /out/iso/packages/Win81_SDK \
			-name "*.msi" 2>/dev/null | sort | while read -r msi; do
			echo "    unpacking $msi"
			msiextract -C /out/tools "$msi" >/dev/null || echo "    (could not unpack $msi)"
		done
	'

# Normalize the VS-internal layout ("Program Files/Microsoft Visual Studio 14.0/VC")
# into one stable path the image can copy: staging/VC14
VCROOT=$(find "$STAGING/tools" -maxdepth 4 -type d -path "*Microsoft Visual Studio 14.0/VC" | head -1)
if [ -z "$VCROOT" ]; then
	echo "error: no 'Microsoft Visual Studio 14.0/VC' tree came out of the D14 packages" >&2
	exit 1
fi
rm -rf "$STAGING/VC14"
cp -R "$VCROOT" "$STAGING/VC14"
echo "==> toolset normalized to staging/VC14:"
find "$STAGING/VC14" -maxdepth 3 -name "cl.exe" | sort
if ! [ -f "$STAGING/VC14/bin/amd64/cl.exe" ]; then
	echo "error: staging/VC14/bin/amd64/cl.exe is missing after normalization" >&2
	exit 1
fi

# The SDK headers the product compiled against, normalized like the toolset: the Universal
# CRT (10.0.10240.0 is 2015's default; the package also carries a beta 10150 tree) plus the
# 8.1 um/shared trees. The image's cl wrapper puts all three on INCLUDE.
UCRT=$(find "$STAGING/tools" -maxdepth 9 -type d -path "*Windows Kits/10/Include/10.0.10240.0/ucrt" | head -1)
UM=$(find "$STAGING/tools" -maxdepth 9 -type d -path "*Windows Kits/8.1/Include/um" | head -1)
SHARED=$(find "$STAGING/tools" -maxdepth 9 -type d -path "*Windows Kits/8.1/Include/shared" | head -1)
if [ -z "$UCRT" ] || [ -z "$UM" ] || [ -z "$SHARED" ]; then
	echo "error: SDK include trees missing (ucrt=$UCRT um=$UM shared=$SHARED)" >&2
	exit 1
fi
rm -rf "$STAGING/sdk"
mkdir -p "$STAGING/sdk"
cp -R "$UCRT" "$STAGING/sdk/ucrt"
cp -R "$UM" "$STAGING/sdk/um"
cp -R "$SHARED" "$STAGING/sdk/shared"
[ -f "$STAGING/sdk/ucrt/corecrt.h" ] || { echo "error: corecrt.h missing from staging/sdk" >&2; exit 1; }
echo "==> SDK headers normalized to staging/sdk:"
du -sh "$STAGING/sdk"

echo "==> building $IMAGE (wine + toolset; a few minutes)"
docker build --platform linux/amd64 -t "$IMAGE" "$HERE"

echo "==> done: $IMAGE"
echo "    dcore uses it with: compiler.image = $IMAGE, driver cl (platform is chosen automatically)"
