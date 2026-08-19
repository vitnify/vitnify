---
name: Feature request
about: Propose a new capability for the vitnify SDK (an adapter, an API, a check)
title: "[feature] "
labels: enhancement
---

## What do you want to be able to do

Describe the capability and the use case (e.g. a new framework adapter, a new receipt
query, a stricter verification mode).

## Compatibility & determinism

- Does this change how receipts or events are canonicalized, hashed, or signed? If yes,
  it needs a version bump — existing receipts must still verify. See CONTRIBUTING.md.
- Does it touch the model / digest path? If so, does the reference digest stay the same?
- Does it keep ungranted tools structurally unreachable (capability containment intact)?

## Proposed approach

Sketch the API or design.

## Alternatives considered

What else did you weigh, and why this?

## Additional context

Links, references, or prior art.
