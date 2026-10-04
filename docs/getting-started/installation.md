# Installation

Requires Python 3.14+ and [`uv`](https://docs.astral.sh/uv/).

```bash
uv add builtbyelly-fastauth
```

SQLAlchemy and the redis client ship **in the default install** — no extras to pick. There are no `fastauth[sqlalchemy]` / `fastauth[redis]` variants today; optional dependencies for other ORMs will arrive over time as more backends land.

You only need to add an async DB driver for your database:

```bash
uv add aiosqlite   # SQLite, as used in examples/
```

For docs locally (this site builds with [zensical](https://zensical.org), configured in `zensical.toml`):

```bash
uvx zensical serve
```
