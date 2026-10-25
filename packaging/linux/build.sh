#!/bin/sh
# 在 Linux 上建置 musl 靜態執行檔並產出 deb / rpm / tar.gz 與 .sha256 到 target/linux-release/
# 本機驗證可用 TARGET=x86_64-unknown-linux-gnu 覆寫（正式發佈一律用預設的 musl）
set -e
cd "$(dirname "$0")/../.."
TARGET="${TARGET:-x86_64-unknown-linux-musl}"
OUT=target/linux-release
VER=$(cargo metadata --no-deps --format-version 1 | sed -n 's/.*"name":"endpoint-agent","version":"\([^"]*\)".*/\1/p')
[ -n "$VER" ] || { echo "取不到版本" >&2; exit 1; }

cargo build --release -p endpoint-agent --target "$TARGET"
cargo deb -p endpoint-agent --no-build --target "$TARGET"
cargo generate-rpm -p crates/agent --target "$TARGET"

rm -rf "$OUT"
mkdir -p "$OUT"
cp target/"$TARGET"/debian/endpoint-agent_"${VER}"-1_amd64.deb "$OUT/endpoint-agent_${VER}_amd64.deb" 2>/dev/null ||
    cp target/"$TARGET"/debian/endpoint-agent_"${VER}"*_amd64.deb "$OUT/endpoint-agent_${VER}_amd64.deb"
cp target/"$TARGET"/generate-rpm/endpoint-agent-"${VER}"-1.x86_64.rpm "$OUT/"

TMP=$(mktemp -d)
cp target/"$TARGET"/release/endpoint-agent packaging/linux/endpoint-agent.service packaging/linux/INSTALL.txt "$TMP/"
tar -czf "$OUT/endpoint-agent-${VER}-x86_64-linux.tar.gz" -C "$TMP" endpoint-agent endpoint-agent.service INSTALL.txt
rm -rf "$TMP"

cd "$OUT"
for f in *.deb *.rpm *.tar.gz; do sha256sum "$f" > "$f.sha256"; done
ls -l
