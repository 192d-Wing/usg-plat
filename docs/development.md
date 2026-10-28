# Development

The toolchain is pinned in `rust-toolchain.toml`. Run `make check test` before
sending a change; CI runs the same targets plus `make security`.

--8<-- "CLAUDE.md:dev"

## Documentation site

This site is built with [Zensical](https://zensical.org) from `zensical.toml`
and the `docs/` directory. Architecture, changelog, quick start and performance
pages include the repository's root Markdown files, so edit those files rather
than the wrappers under `docs/`.

```bash
make docs-serve   # live preview on http://127.0.0.1:8000
make docs         # build into site/
```
