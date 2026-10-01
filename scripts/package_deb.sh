#!/usr/bin/env bash
# Build an amd64 .deb without installing it or granting runtime privileges.
set -euo pipefail
export LC_ALL=C
cd "$(dirname "$0")/.."
[[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || {
  echo 'Debian packaging requires native Linux x86-64.' >&2; exit 2;
}
for tool in cargo dpkg-deb dpkg-shlibdeps dpkg python3 gzip install git sha256sum; do
  command -v "$tool" >/dev/null || { echo "Missing packaging tool: $tool" >&2; exit 2; }
done
[[ $(dpkg --print-architecture) == amd64 ]] || { echo 'Packaging supports amd64 only.' >&2; exit 2; }
version=$(python3 - <<'PY'
import pathlib, re
text = pathlib.Path('Cargo.toml').read_text()
match = re.search(r'^version = "([^"]+)"', text, re.M)
if not match or not re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)', match.group(1)):
    raise SystemExit('Debian packaging expects a stable numeric Cargo version.')
print(match.group(1))
PY
)
revision=${DEB_REVISION:-1}
[[ $revision =~ ^[1-9][0-9]*$ ]] || { echo 'DEB_REVISION must be a positive integer.' >&2; exit 2; }
package_version="$version-$revision"
dpkg --validate-version "$package_version"
name=${DEBFULLNAME:-$(git config user.name || git log -1 --format=%an)}
email=${DEBEMAIL:-$(git config user.email || git log -1 --format=%ae)}
python3 - "$name" "$email" <<'PY'
import re, sys
name, email = sys.argv[1:]
if not name.strip() or any(ord(c) < 32 or ord(c) == 127 or c in '<>' for c in name):
    raise SystemExit('Set DEBFULLNAME to a real single-line maintainer name.')
if not re.fullmatch(r'[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}', email):
    raise SystemExit('Set DEBEMAIL to the actual maintainer contact; no invented default is used.')
PY
SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}
[[ $SOURCE_DATE_EPOCH =~ ^[0-9]{1,10}$ ]] || { echo 'SOURCE_DATE_EPOCH must be a nonnegative Unix timestamp.' >&2; exit 2; }
export SOURCE_DATE_EPOCH
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cargo build --release --locked --bin wraith --message-format=json > "$work/cargo-artifacts.jsonl"
binary=$(python3 - "$work/cargo-artifacts.jsonl" <<'PY'
import json, pathlib, sys
rows = [json.loads(line) for line in pathlib.Path(sys.argv[1]).read_text().splitlines()]
for row in rows:
    if row.get('reason') == 'compiler-message' and row.get('message', {}).get('rendered'):
        print(row['message']['rendered'], file=sys.stderr, end='')
paths = [row['executable'] for row in rows if row.get('reason') == 'compiler-artifact' and row.get('target', {}).get('name') == 'wraith' and 'bin' in row.get('target', {}).get('kind', []) and row.get('executable')]
if len(paths) != 1 or not pathlib.Path(paths[0]).is_file():
    raise SystemExit(f'Expected exactly one actual Cargo sensor executable, got: {paths}')
print(paths[0])
PY
)
[[ $("$binary" --version) == "wraith $version" ]] || { echo 'Built sensor version does not match Cargo.toml.' >&2; exit 1; }
stage="$work/package"
install -d -m 0755 "$stage/DEBIAN" "$stage/usr/bin" "$stage/usr/share/man/man1" "$stage/usr/share/doc/wraith" "$work/debian"
sensor_sha=$(sha256sum "$binary"); sensor_sha=${sensor_sha%% *}
install -m 0755 "$binary" "$stage/usr/bin/wraith"
staged_sha=$(sha256sum "$stage/usr/bin/wraith"); staged_sha=${staged_sha%% *}
[[ $sensor_sha == "$staged_sha" ]] || { echo 'Staged sensor differs from the actual Cargo artifact.' >&2; exit 1; }
install -m 0644 packaging/README.Debian packaging/copyright "$stage/usr/share/doc/wraith/"
gzip -n -9 -c packaging/wraith.1 > "$stage/usr/share/man/man1/wraith.1.gz"
chmod 0644 "$stage/usr/share/man/man1/wraith.1.gz"
# dpkg-shlibdeps reads system ELF/symbol metadata; it never installs packages.
cat > "$work/debian/control" <<EOF
Source: wraith
Section: utils
Priority: optional
Maintainer: $name <$email>

Package: wraith
Architecture: amd64
Depends: \${shlibs:Depends}
Description: Linux syscall provenance runtime sensor
 Inspect executable origins and correlate selected process runtime signals.
EOF
shlibs=$(cd "$work" && dpkg-shlibdeps -O -e"$stage/usr/bin/wraith")
[[ $shlibs == shlibs:Depends=* && $shlibs != *$'\n'* ]] || { echo 'Unexpected ELF dependency output.' >&2; exit 1; }
depends=${shlibs#shlibs:Depends=}
[[ -n $depends ]] || { echo 'ELF dependencies are empty; refusing an unvalidated package.' >&2; exit 1; }
installed_size=$(python3 - "$stage/usr" <<'PY'
import pathlib, sys
root = pathlib.Path(sys.argv[1])
print(sum(max(1, (p.stat().st_size + 1023) // 1024) for p in root.rglob('*') if p.is_file()))
PY
)
cat > "$stage/DEBIAN/control" <<EOF
Package: wraith
Version: $package_version
Architecture: amd64
Section: utils
Priority: optional
Maintainer: $name <$email>
Installed-Size: $installed_size
Depends: $depends
Homepage: https://github.com/grloper/Wraith
Description: Linux syscall provenance runtime sensor
 Dependency-light Rust sensor for native Linux amd64. Inspects executable
 syscall origins, protection requests and correlated runtime signals.
 .
 Observe-only by default, with optional enforcement after workload baselining.
 This package does not grant capabilities or modify ptrace/security policy.
EOF
{
  printf 'wraith (%s) unstable; urgency=medium\n\n' "$package_version"
  printf '  * Package the sensor, readiness diagnostics, manual and deployment guidance.\n'
  printf '  * Derive runtime dependencies from the actual ELF binary.\n\n'
  printf ' -- %s <%s>  %s\n' "$name" "$email" "$(date --utc --date="@$SOURCE_DATE_EPOCH" -R)"
} | gzip -n -9 > "$stage/usr/share/doc/wraith/changelog.Debian.gz"
chmod 0644 "$stage/usr/share/doc/wraith/changelog.Debian.gz" "$stage/DEBIAN/control"
python3 - "$stage" "$SOURCE_DATE_EPOCH" <<'PY'
import hashlib, os, pathlib, sys
stage = pathlib.Path(sys.argv[1])
epoch = int(sys.argv[2])
rows = []
for file in sorted((stage / 'usr').rglob('*')):
    if file.is_file():
        rows.append(f'{hashlib.md5(file.read_bytes()).hexdigest()}  {file.relative_to(stage).as_posix()}')
(stage / 'DEBIAN/md5sums').write_text('\n'.join(rows) + '\n')
os.chmod(stage / 'DEBIAN/md5sums', 0o644)
# Normalize every path, not just the archive header; gzip uses -n above.
for path in sorted(stage.rglob('*'), reverse=True):
    os.utime(path, (epoch, epoch))
os.utime(stage, (epoch, epoch))
PY
mkdir -p target/dist
artifact="wraith_${package_version}_amd64.deb"
dpkg-deb --root-owner-group --uniform-compression -Zxz -z9 --build "$stage" "target/dist/$artifact"
(cd target/dist && sha256sum "$artifact" > DebSHA256SUMS && sha256sum -c DebSHA256SUMS)
printf 'Built target/dist/%s\nCargo executable: %s\nSensor SHA256: %s\nELF Depends: %s\n' "$artifact" "$binary" "$sensor_sha" "$depends"
