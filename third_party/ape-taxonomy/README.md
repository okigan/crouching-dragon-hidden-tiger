# HiddenLayer APE Taxonomy (vendored, verbatim)

This directory contains the **HiddenLayer Adversarial Prompt Engineering (APE)
Taxonomy**, redistributed **unmodified** for use as a data input by this
project's red-team loop.

## Attribution

- **Work:** APE Taxonomy (`ape.json`)
- **Author:** © HiddenLayer
- **Source:** https://github.com/hiddenlayerai/ape-taxonomy · https://ape.hiddenlayer.com/
- **License:** Creative Commons Attribution-NoDerivatives 4.0 International
  (CC BY-ND 4.0) — see [`LICENSE`](LICENSE).
- **Changes:** none. `ape.json` is byte-for-byte identical to the upstream file
  (sha256 `24bb261017ee17504660fe919a6323daa6e9e972a5cf380e6cf32436fc27b356`).

## Why it's here

CC BY-ND permits redistribution of the **unmodified** work with attribution. The
red-team loop reads this taxonomy to ground attacks in APE techniques (how) and
objectives (what), and to feed a technique's description ("clause") to an LLM
generator that crafts evasion prompts. We do **not** distribute a modified or
transformed version of the taxonomy — the file stays verbatim; any per-technique
selection or prompt generation happens at runtime, not by editing this file.

To refresh from upstream, re-download `ape.json` and `LICENSE` from the source
repo above (do not hand-edit them).
