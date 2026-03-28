# firelift

HTTP client and CLI for Prometheus `/metrics` text, `/api/v1/query`, and related cluster exporter endpoints. Uses only the Python standard library.

Repository: [github.com/amagnosi-so/firelift](https://github.com/amagnosi-so/firelift)

## Install

**From the repo**

```bash
pip install .
# or editable:
pip install -e .
```

**Isolated (pipx)**

```bash
pipx install /path/to/firelift
# or from a built wheel:
python -m build && pipx install dist/firelift-*.whl
```

Requires **Python 3.10+**.

## Usage

```bash
firelift --help
python -m firelift --help
```

Global options: `--url`, `--timeout`, `--verify-ssl`. Subcommands include `metrics`, `query`, `dump-prometheus`, `raw`, and others—see `--help` on each.

**Library**

```python
from firelift import FireliftClient

c = FireliftClient(base_url="http://127.0.0.1:9090")
print(c.metrics_text())
```

## License

MIT—see [LICENSE](LICENSE). Copyright 2026 Alessandro Magnosi (aka KlezVirus).
