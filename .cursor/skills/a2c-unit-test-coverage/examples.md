# Examples

Patterns taken from existing suites. Prefer copying from a neighbor in the same area of `test/`.

## Numbering

```python
def test_001_generate_nonce_value(self):
    """test Nonce._generate_nonce_value() and check if we get something back"""
    self.assertIsNotNone(self.nonce._generate_nonce_value())


def test_002_generate_and_add(self):
    """test Nonce._generate_and_add() and check if we get something back"""
    self.assertIsNotNone(self.nonce.generate_and_add())
```

When appending, find the max `test_NNN_` in the file and continue (`test_009_…` after `test_008_…`).

## Typical setUp (unittest)

```python
def setUp(self):
    """setup unittest"""
    models_mock = MagicMock()
    modules = {"acme2certifier.acme_srv.db_handler": models_mock}
    patch.dict("sys.modules", modules).start()
    import logging

    logging.basicConfig(level=logging.CRITICAL)
    self.logger = logging.getLogger("test_a2c")
    from acme2certifier.acme_srv.nonce import Nonce

    self.nonce = Nonce(False, self.logger)
```

## assertLogs (INFO+)

```python
with self.assertLogs("test_a2c", level="INFO") as lcm:
    nonce.generate_and_add()
self.assertIn(
    "CRITICAL:test_a2c:Database error: failed to add new nonce: exc_nonce_add",
    lcm.output,
)
```

```python
with self.assertLogs("test_a2c", level="INFO") as lcm:
    self.cahandler._config_load()
self.assertIn(
    'ERROR:test_a2c:Configuration incomplete: "api_host" parameter is missing in config file',
    lcm.output,
)
```

Log records in `lcm.output` look like `"LEVEL:test_a2c:message"`.

## Mapping hints

| Source | Typical test file |
|--------|-------------------|
| `acme2certifier/acme_srv/nonce.py` | `test/test_nonce.py` |
| `acme2certifier/cahandlers/certifier_ca_handler.py` | `test/test_certifier_handler.py` |
| `acme2certifier/tools/a2c_wsgi2django.py` | `test/test_a2c_wsgi2django.py` |

Some features split across several suites (e.g. `challenge` → `test_challenge.py`, `test_challenge_business_logic.py`, …). Extend the closest existing suite before creating a new file.
