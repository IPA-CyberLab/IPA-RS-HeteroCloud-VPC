Vendored from https://github.com/spidernet-io/egressgateway at
`d2b1448d010a8000275b20647832a5d3de505793` (v0.6.9), Apache-2.0.

Local patch: preserve the YAML document separator before the cert-manager
Certificate in `templates/tls.yaml`. The upstream whitespace trimming joins
`sideEffects: None` with `---` and merges webhook fields into the Certificate.
Runtime images remain the pinned upstream images. Recheck this patch on upgrades.
