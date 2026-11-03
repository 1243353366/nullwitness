"""The trust chain: five properties, each with code that enforces or checks it.

Import from the submodules directly. The package is deliberately flat: `model` holds the
shared vocabulary, `keys` derives and audits, `envelope` protects the record, `seal` covers
what the envelope cannot, `boot` covers the machine, `flow` joins them so the joins can be
tested.
"""
