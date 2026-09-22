# sing-box

The universal proxy platform.

This is the **udpflow testing branch**. Download its signed **Android 16+ ARM64** APK
from [Releases](https://github.com/shinokiri/sing-box/releases).
Exact core and Android pins are recorded in [`release/udpflow.json`](release/udpflow.json).
This branch follows newly published upstream **alpha/beta/rc releases** every six hours
when it is the repository default branch. Unreleased `testing` commits are not selected.
The Actions **Android ARM64** workflow also supports a manual update check.
Release selection queries only version metadata through GraphQL; transient API
read failures retry at most three times without accepting partial results.

Updates merge the released core snapshot, pin a matching Android client, and rebase
local `sing-mux`, `sing-tun`, and `sing-snell` changes onto their required versions.
Fork automation and Android patches are retained. A conflict, mismatched dependency,
or failed test stops publication and reports the reason in Actions; the existing
public release remains available. Core, race, Android unit, and signed APK checks
must all pass before the tested commit and prerelease are published.

Already published versions skip scheduled/manual builds. Use `force_build` for a
verification build without replacing the published APK. Pushing a reviewed fork
revision continues to use the pinned source and the normal release gates.

Install the first udpflow release manually; subsequent releases are checked
from this repository when the app starts. Previously disabled update checks
remain disabled and can be enabled in app settings.
See [UDP flow and build notes](SNELL_UDP_FLOW_ADAPTER.md) for changes and validation limits.

[![Packaging status](https://repology.org/badge/vertical-allrepos/sing-box.svg)](https://repology.org/project/sing-box/versions)

## Documentation

https://sing-box.sagernet.org

## License

```
Copyright (C) 2022 by nekohasekai <contact-sagernet@sekai.icu>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.

In addition, no derivative work may use the name or imply association
with this application without prior consent.
```
