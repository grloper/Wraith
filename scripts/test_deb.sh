#!/usr/bin/env bash
# Inspect/extract locally; never dpkg-install or alter security policy.
set -euo pipefail
cd "$(dirname "$0")/.."
[[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || {
  echo 'FAIL: Debian acceptance requires Linux x86-64.' >&2; exit 2;
}
for tool in dpkg-deb python3 timeout cargo; do
  command -v "$tool" >/dev/null || { echo "FAIL: missing test tool $tool" >&2; exit 2; }
done
[[ -f scripts/package_deb.sh ]] || {
  echo 'FAIL: expected Debian package builder scripts/package_deb.sh is not implemented.' >&2
  exit 1
}
version=$(python3 - <<'PY'
import pathlib, re
text = pathlib.Path('Cargo.toml').read_text()
print(re.search(r'^version = "([^"]+)"', text, re.M).group(1))
PY
)
if [[ $# -gt 1 ]]; then echo 'Usage: bash scripts/test_deb.sh [artifact.deb|--target-regression]' >&2; exit 2; fi
temporary=$(mktemp -d)
default_binary="$(pwd)/target/release/wraith"
restore_needed=0
had_default=0
restore_default() {
  if [[ $restore_needed == 1 ]]; then
    if [[ $had_default == 1 ]]; then
      cp -p "$temporary/default-before" "$default_binary"
      [[ $(sha256sum "$default_binary") == "${default_hash}  $default_binary" ]] || { echo 'FAIL: default binary restoration mismatch.' >&2; return 1; }
    else
      rm -f "$default_binary"
    fi
    restore_needed=0
  fi
}
cleanup() {
  restore_default
  rm -rf "$temporary"
}
trap cleanup EXIT
target_regression() {
  command -v cc >/dev/null || { echo 'FAIL: compiler required for local stale-ELF canary.' >&2; exit 2; }
  mkdir -p "$(dirname "$default_binary")"
  if [[ -e $default_binary ]]; then
    [[ -f $default_binary && ! -L $default_binary ]] || { echo 'FAIL: expected ordinary default Cargo binary for safe canary restoration.' >&2; exit 2; }
    cp -p "$default_binary" "$temporary/default-before"
    had_default=1
    default_hash=$(sha256sum "$default_binary")
    default_hash=${default_hash%% *}
  fi
  python3 - "$temporary/canary.c" "$version" <<'PY'
import json, pathlib, sys
version = json.dumps('wraith ' + sys.argv[2])
pathlib.Path(sys.argv[1]).write_text('#include <stdio.h>\n#include <string.h>\nint main(int argc, char **argv) { if (argc == 2 && strcmp(argv[1], "--version") == 0) { puts(' + version + '); return 0; } puts("STALE_DEFAULT_ELF_CANARY"); return 77; }\n')
PY
  cc "$temporary/canary.c" -o "$temporary/canary"
  restore_needed=1
  # install replaces the path rather than modifying a Cargo hardlink in place.
  install -m 0755 "$temporary/canary" "$default_binary"
  CARGO_TARGET_DIR="$temporary/alternate-target" cargo build --release --locked --bin wraith --message-format=json > "$temporary/fresh.jsonl"
  fresh=$(python3 - "$temporary/fresh.jsonl" <<'PY'
import json, pathlib, sys
rows = [json.loads(line) for line in pathlib.Path(sys.argv[1]).read_text().splitlines()]
paths = [row['executable'] for row in rows if row.get('reason') == 'compiler-artifact' and row.get('target', {}).get('name') == 'wraith' and 'bin' in row.get('target', {}).get('kind', []) and row.get('executable')]
assert len(paths) == 1, paths
print(paths[0])
PY
)
  CARGO_TARGET_DIR="$temporary/alternate-target" bash scripts/package_deb.sh
  regression_artifact="target/dist/wraith_${version}-${DEB_REVISION:-1}_amd64.deb"
  dpkg-deb --extract "$regression_artifact" "$temporary/regression-root"
  expected=$(sha256sum "$fresh"); expected=${expected%% *}
  actual=$(sha256sum "$temporary/regression-root/usr/bin/wraith"); actual=${actual%% *}
  restore_default
  [[ $actual == "$expected" ]] || {
    printf 'FAIL: packaged stale default ELF instead of actual alternate Cargo artifact. ExpectedSHA=%s packagedSHA=%s\n' "$expected" "$actual" >&2
    exit 1
  }
  printf 'PASS: alternate Cargo target package exactly matches actual executable SHA256=%s; default binary restored.\n' "$expected"
}
if [[ ${1:-} == --target-regression ]]; then
  target_regression
  exit 0
fi
if [[ $# -eq 0 ]]; then
  export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}
  target_regression
  bash scripts/package_deb.sh
  artifact="target/dist/wraith_${version}-${DEB_REVISION:-1}_amd64.deb"
else
  artifact=$1
fi
[[ -f $artifact ]] || { echo "FAIL: expected package not found: $artifact" >&2; exit 1; }
[[ $(dpkg-deb --field "$artifact" Package) == wraith ]]
[[ $(dpkg-deb --field "$artifact" Version) == "${version}-${DEB_REVISION:-1}" ]]
[[ $(dpkg-deb --field "$artifact" Architecture) == amd64 ]]
[[ $(dpkg-deb --field "$artifact" Section) == utils ]]
[[ $(dpkg-deb --field "$artifact" Priority) == optional ]]
depends=$(dpkg-deb --field "$artifact" Depends)
[[ $depends =~ (^|,[[:space:]]*)libc6[[:space:]] ]] || { echo "FAIL: ELF libc dependency absent: $depends" >&2; exit 1; }
[[ $depends =~ (^|,[[:space:]]*)libgcc-s1[[:space:]] ]] || { echo "FAIL: ELF libgcc dependency absent: $depends" >&2; exit 1; }
dpkg-deb --fsys-tarfile "$artifact" > "$temporary/payload.tar"
dpkg-deb --ctrl-tarfile "$artifact" > "$temporary/control.tar"
# Validate paths and entry types before extraction, including caller-supplied debs.
python3 - "$temporary" <<'PY'
import pathlib, sys, tarfile
root = pathlib.Path(sys.argv[1])
for archive_name in ('payload.tar', 'control.tar'):
    with tarfile.open(root / archive_name) as archive:
        for entry in archive:
            path = pathlib.PurePosixPath(entry.name)
            assert not path.is_absolute() and '..' not in path.parts, entry.name
            assert entry.uid == entry.gid == 0, entry.name
            assert entry.isfile() or entry.isdir(), f'special/link entry: {entry.name}'
            assert not entry.mode & 0o6000, entry.name
            assert not any('security.capability' in key for key in entry.pax_headers), entry.name
            assert '.board' not in path.parts and '.obsidian_vault' not in path.parts, entry.name
            if archive_name == 'control.tar' and entry.isfile():
                assert path.name in {'control', 'md5sums'} and len(path.parts) == 1, entry.name
            elif archive_name == 'payload.tar' and path.parts:
                assert path.parts[0] == 'usr', entry.name
PY
dpkg-deb --extract "$artifact" "$temporary/root"
dpkg-deb --control "$artifact" "$temporary/control"
python3 - "$temporary" "$version-${DEB_REVISION:-1}" <<'PY'
import gzip
import hashlib
import os
import pathlib
import re
import stat
import sys
import tarfile
root = pathlib.Path(sys.argv[1])
contents = root / 'root'
control = root / 'control'
assert {p.name for p in control.iterdir()} == {'control', 'md5sums'}, 'no lifecycle/privilege maintainer scripts permitted'
assert (contents / 'usr/bin/wraith').is_file()
assert stat.S_IMODE((contents / 'usr/bin/wraith').stat().st_mode) == 0o755, 'binary must be0755, not setuid'
assert 'security.capability' not in os.listxattr(contents / 'usr/bin/wraith'), 'no capabilities permitted'
for expected in ('usr/share/man/man1/wraith.1.gz', 'usr/share/doc/wraith/copyright', 'usr/share/doc/wraith/README.Debian', 'usr/share/doc/wraith/changelog.Debian.gz'):
    assert (contents / expected).is_file(), expected
manual = gzip.decompress((contents / 'usr/share/man/man1/wraith.1.gz').read_bytes()).decode()
assert manual.startswith('.TH WRAITH 1') and '.B doctor' in manual
changelog = gzip.decompress((contents / 'usr/share/doc/wraith/changelog.Debian.gz').read_bytes()).decode()
assert changelog.startswith(f'wraith ({sys.argv[2]}) unstable; urgency=medium')
copyright_text = (contents / 'usr/share/doc/wraith/copyright').read_text()
assert copyright_text.startswith('Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/')
assert 'License: Expat' in copyright_text and 'Copyright: 2026 grloper, pandaadir05' in copyright_text
assert {p.name for p in (contents / 'usr/bin').iterdir()} == {'wraith'}, 'do not package simulator binaries'
for entry in contents.rglob('*'):
    assert not entry.is_symlink(), f'unexpected symlink: {entry}'
    assert not entry.stat().st_mode & (stat.S_ISUID | stat.S_ISGID), f'privilege bits: {entry}'
    assert '.board' not in entry.parts and '.obsidian_vault' not in entry.parts
with tarfile.open(root / 'payload.tar') as archive:
    for entry in archive:
        assert entry.uid == entry.gid == 0, f'non-root package ownership: {entry.name}'
        assert not entry.name.startswith('/') and '..' not in pathlib.PurePosixPath(entry.name).parts
        assert entry.isfile() or entry.isdir(), f'unexpected special entry: {entry.name}'
        assert not entry.mode & 0o6000, f'privilege mode: {entry.name}'
metadata = (control / 'control').read_text()
assert re.search(r'^Maintainer: [^\n<>]+ <[^\n<>]+@[^\n<>]+>$', metadata, re.M), 'real maintainer contact required'
names = []
for line in (control / 'md5sums').read_text().splitlines():
    digest, name = line.split('  ', 1)
    assert re.fullmatch(r'[0-9a-f]{32}', digest) and name.startswith('usr/')
    assert '..' not in pathlib.PurePosixPath(name).parts
    assert hashlib.md5((contents / name).read_bytes()).hexdigest() == digest, name
    names.append(name)
assert len(names) == len(set(names)), 'duplicate checksum entries'
assert set(names) == {p.relative_to(contents).as_posix() for p in contents.rglob('*') if p.is_file()}, 'incomplete checksum manifest'
print('PASS: metadata, ELF dependencies, paths, root ownership, file modes, checksums and no lifecycle scripts/private artifacts.')
PY
installed="$temporary/root/usr/bin/wraith"
[[ $(timeout 20 "$installed" --version) == "wraith $version" ]]
doctor_status=0
timeout 20 "$installed" doctor --json > "$temporary/doctor.json" || doctor_status=$?
[[ $doctor_status == 0 ]] || { echo "FAIL: test environment is not ready: doctor status $doctor_status" >&2; cat "$temporary/doctor.json" >&2; exit 1; }
python3 - "$temporary/doctor.json" "$version" <<'PY'
import json, pathlib, sys
report = json.loads(pathlib.Path(sys.argv[1]).read_text())
assert isinstance(report, dict)
assert report.get('schema_version') == 1 and report.get('tool') == 'wraith'
assert report.get('version') == sys.argv[2], 'doctor version must match package'
assert report.get('ready') is True, 'strict package acceptance requires healthy environment'
assert isinstance(report.get('checks'), list) and report['checks'], 'doctor must report real checks'
print('PASS: extracted binary version and doctor JSON.')
PY
cargo build --release --locked --bin benign --bin shellcode-sim --message-format=json > "$temporary/fixture-artifacts.jsonl"
fixture_paths=$(python3 - "$temporary/fixture-artifacts.jsonl" <<'PY'
import json, pathlib, sys
rows = [json.loads(line) for line in pathlib.Path(sys.argv[1]).read_text().splitlines()]
for name in ('benign', 'shellcode-sim'):
    paths = [row['executable'] for row in rows if row.get('reason') == 'compiler-artifact' and row.get('target', {}).get('name') == name and 'bin' in row.get('target', {}).get('kind', []) and row.get('executable')]
    assert len(paths) == 1 and pathlib.Path(paths[0]).is_file(), (name, paths)
    print(paths[0])
PY
)
mapfile -t fixture_binaries <<< "$fixture_paths"
[[ ${#fixture_binaries[@]} == 2 ]] || { echo 'FAIL: expected actual Cargo fixture executable paths.' >&2; exit 1; }
benign_status=0
timeout 20 "$installed" run --quiet --json "$temporary/benign.jsonl" -- "${fixture_binaries[0]}" > "$temporary/benign.stdout" 2> "$temporary/benign.stderr" || benign_status=$?
[[ $benign_status == 0 && ! -s $temporary/benign.jsonl ]] || { echo 'FAIL: extracted sensor benign control' >&2; cat "$temporary/benign.stderr" >&2; exit 1; }
injected_status=0
timeout 20 "$installed" run --quiet --json "$temporary/injected.jsonl" -- "${fixture_binaries[1]}" > "$temporary/injected.stdout" 2> "$temporary/injected.stderr" || injected_status=$?
[[ $injected_status == 3 ]] || { echo "FAIL: expected detection exit3, got$injected_status" >&2; cat "$temporary/injected.stderr" >&2; exit 1; }
python3 - "$temporary/injected.jsonl" <<'PY'
import json, pathlib, sys
rows = [json.loads(line) for line in pathlib.Path(sys.argv[1]).read_text().splitlines()]
assert any(row['kind'] == 'foreign_origin_syscall' and row['severity'] == 'CRITICAL' for row in rows), f'missing critical origin evidence: {rows}'
assert any(row['kind'] == 'exploitation_chain' for row in rows), f'missing correlated chain evidence: {rows}'
print('PASS: extracted sensor benign control clean; simulated injected execution detected, exit3.')
PY
if [[ $# -eq 0 ]]; then
  first=$(sha256sum "$artifact")
  bash scripts/package_deb.sh
  [[ $(sha256sum "$artifact") == "$first" ]] || { echo 'FAIL: fixed-epoch rebuild is not byte-identical.' >&2; exit 1; }
  echo 'PASS: fresh staging with fixed SOURCE_DATE_EPOCH produced byte-identical packages.'
fi
rejected=0
DEBFULLNAME=$'grloper\nInjected: yes' bash scripts/package_deb.sh > "$temporary/rejected.log" 2>&1 || rejected=$?
[[ $rejected != 0 ]] || { echo 'FAIL: maintainer control-field injection accepted.' >&2; exit 1; }
python3 - "$temporary/rejected.log" <<'PY'
import pathlib, sys
assert 'Set DEBFULLNAME to a real single-line maintainer name.' in pathlib.Path(sys.argv[1]).read_text()
print('PASS: maintainer metadata control-field injection rejected before package build.')
PY
printf 'PASS: Debian artifact inspected/extracted/executed: %s (not host-installed or Kali-VM-tested).\n' "$artifact"
