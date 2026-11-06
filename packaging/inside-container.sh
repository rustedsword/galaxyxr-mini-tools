#!/usr/bin/env bash
set -euo pipefail

say() {
    printf '\033[1;34m==>\033[0m %s\n' "$*"
}

die() {
    printf '\033[1;31merror:\033[0m %s\n' "$*" >&2
    exit 1
}

for variable_name in SOURCE SERIES VERSION PPA_REMOTE GPG_KEY UNSIGNED NO_UPLOAD TEST_BUILD; do
    [ -n "${!variable_name+x}" ] || die "missing environment variable: $variable_name"
done
[ -f /work/source.tar ] || die "no /work/source.tar"
[ -d /out ] || die "no /out"

WORK=$(mktemp -d "/tmp/$SOURCE-publish.XXXXXX")
trap 'rm -rf -- "$WORK"' EXIT

verify_sha256_manifest() {
    local checksums
    checksums=$(awk '/^Checksums-Sha256:/ { inside = 1; next }
        inside && /^[^ ]/ { exit }
        inside && NF == 3 { print $1 "  " $3 }' "$1")
    [ -n "$checksums" ] || die "no SHA-256 checksums in $1"
    (cd "$(dirname -- "$1")" && printf '%s\n' "$checksums" | sha256sum --check --strict --quiet -)
}

src=$WORK/$SOURCE-$VERSION
install -d "$src"
tar -C "$src" -xf /work/source.tar

sed -i -E "1s/^($SOURCE) \([^)]*\) [^;]*;/\1 ($VERSION) $SERIES;/" "$src/debian/changelog"
[ "$(dpkg-parsechangelog -l"$src/debian/changelog" -SVersion)" = "$VERSION" ] ||
    die "cannot set the changelog version to $VERSION"
[ "$(dpkg-parsechangelog -l"$src/debian/changelog" -SDistribution)" = "$SERIES" ] ||
    die "cannot set the changelog series to $SERIES"

args=(-S -sa -d)
if [ "$UNSIGNED" -eq 1 ]; then
    args+=(-us -uc)
else
    args+=("-k$GPG_KEY")
fi
say "Creating the $SERIES source package $VERSION"
(cd "$src" && dpkg-buildpackage "${args[@]}")
rm -rf -- "$src"

changes=$WORK/${SOURCE}_${VERSION}_source.changes
dsc=$WORK/${SOURCE}_${VERSION}.dsc
[ -f "$changes" ] && [ -f "$dsc" ] || die "dpkg-buildpackage left no $changes or $dsc"
say "Checking the checksums"
verify_sha256_manifest "$dsc"
verify_sha256_manifest "$changes"
if [ "$UNSIGNED" -eq 0 ]; then
    say "Checking the signatures"
    gpg --batch --verify "$dsc"
    gpg --batch --verify "$changes"
fi
say "Checking that the source package extracts"
dpkg-source --no-check -x "$dsc" "$WORK/extracted" > /dev/null
say "lintian"
lintian --display-info "$changes"

if [ "$TEST_BUILD" -eq 1 ]; then
    # The extracted package, not the tree: dpkg-source leaves files out of the tarball Launchpad builds
    say "Building the arm64 packages from the source package"
    (cd "$WORK/extracted" && dpkg-buildpackage -a arm64 -b -us -uc)
    say "lintian on the packages"
    lintian --fail-on none "$WORK/${SOURCE}_${VERSION}_arm64.changes"
fi
rm -rf -- "$WORK/extracted"

find "$WORK" -maxdepth 1 -type f -exec cp -a -t /out {} +
if [ "$NO_UPLOAD" -eq 1 ]; then
    say "Upload skipped"
else
    say "Uploading ${changes##*/} to $PPA_REMOTE"
    dput "$PPA_REMOTE" "$changes"
fi
