# eos-redoxfs

**E-OS fork of [`redox-os/redoxfs`](https://gitlab.redox-os.org/redox-os/redoxfs).** Part of the [**E-OS**](https://github.com/Gh0s777tt/E-OS) ecosystem — a hardened, Crimson-branded downstream of [Redox OS](https://www.redox-os.org).

This repository is **RedoxFS**, the Redox filesystem (with optional full-disk encryption).

## E-OS changes vs upstream

- **Hardware AES-XTS** for full-disk encryption via **ARMv8 Crypto Extensions**, runtime-detected through `/scheme/sys/cpu` (R-502b).

## How it's pinned

The E-OS build pins this fork in [`recipes/core/redoxfs/recipe.toml`](https://github.com/Gh0s777tt/E-OS/blob/main/recipes/core/redoxfs/recipe.toml):

- branch **`master`** · rev **`ce461328b3c3`**
- up to date with upstream

## Build standalone

This fork is normally built by the E-OS cookbook (`make CI=1 …` in the [main repo](https://github.com/Gh0s777tt/E-OS)). To build it on its own you need the Redox toolchain; see the main repo's [build guide](https://github.com/Gh0s777tt/E-OS/blob/main/docs/building.md).

## Hosting

**GitLab (source of truth):** https://gitlab.com/e-os/eos-redoxfs  
**GitHub (read-only mirror):** https://github.com/Gh0s777tt/eos-redoxfs

## License

MIT (inherited from upstream Redox). The E-OS project as a whole is AGPL-3.0; see the [main repo](https://github.com/Gh0s777tt/E-OS/blob/main/LICENSE).

---
[E-OS main repo](https://github.com/Gh0s777tt/E-OS) · [Docs](https://github.com/Gh0s777tt/E-OS/tree/main/docs) · [Upstream](https://gitlab.redox-os.org/redox-os/redoxfs)
