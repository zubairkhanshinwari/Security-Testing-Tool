# CIS Ubuntu Linux Benchmark content

This directory holds the **data-driven benchmark definitions** consumed by
`CISBenchmarkManager`. No proprietary CIS Benchmark text is committed here.

## Licensing

The official CIS Ubuntu Linux Benchmark is copyrighted content distributed by
the Center for Internet Security under its own terms
(https://www.cisecurity.org/cis-benchmarks). This repository does not
redistribute that text.

The `1.0.0/controls/*.json` files shipped in this repo are a small set of
**hand-written example controls**, used for tests and to demonstrate the data
shape. They are original text describing well-known, publicly documented
Linux hardening concepts (e.g. "SSH root login should be disabled") — they are
not verbatim CIS control language and do not carry official CIS control
numbering.

To run a real CIS Ubuntu Linux Benchmark assessment, an operator with a valid
license/entitlement should populate additional version directories here
(e.g. `2.0.0/`) using their own licensed export, following the schema in
`1.0.0/controls.schema.json`. Do not commit that content to a public
repository unless your CIS license permits redistribution.

## Directory shape

```
cis-ubuntu-linux/
  <version>/
    benchmark.meta.json     # id, name, version, platform, profile — metadata only
    controls.schema.json    # JSON Schema a control file must satisfy
    controls/
      *.json                 # one array of ComplianceControl objects per file
```
