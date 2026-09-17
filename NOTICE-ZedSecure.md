# ZedSecure patches

This branch is [XTLS/Xray-core](https://github.com/XTLS/Xray-core) at commit `fc1474e0` with the
changes ZedSecure needs. Compare it against `main` to see every one of them.

## What was changed

* `proxy/singbox/` — an outbound that carries a sing-box configuration fragment: one sing-box
  instance per handler, dialling back out through Xray (`zed-xray-dialer`) so routing, chains and
  the Android VpnService protect path still apply. `main/singbox.go` and `infra/conf/singbox.go`
  are its command and config sides.
* `proxy/autoselect/` — an outbound that picks between members by measured delay, with hysteresis,
  hedging and retry. `infra/conf/autoselect.go` is its config side.
* `proxy/wireguard/` — repointed at [amneziawg-go](https://github.com/amnezia-vpn/amneziawg-go) and
  extended with the AmneziaWG obfuscation parameters (`awg.go`); the `conn.Bind`, `tun.Device` and
  `device.NewDevice` shapes are byte-identical to wireguard-go, so this is a dependency swap.
* `app/metrics`, `app/proxyman/outbound`, `main`, `infra/conf/xray.go` — small changes in support of
  the above.

## Licensing

Xray-core's own files stay under the **Mozilla Public License 2.0**; `LICENSE` is unchanged and
applies to them exactly as before.

A binary built from this tree is a different matter. It links sing-box, sing and sing-shadowsocks,
all of which are **GPL-3.0-or-later**, so the combined work is distributed under the GPL-3.0-or-later
— which MPL-2.0 §3.3 expressly permits for a Larger Work. The full corresponding source for that
combined work, including every dependency the build resolves by path, is at
<https://github.com/CluvexStudio/zedcore>.

This is an independent fork. It is not affiliated with, endorsed by, or associated with the
sing-box project or its authors.
