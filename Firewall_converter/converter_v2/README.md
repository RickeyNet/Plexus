# Converter V2 Scaffold

This directory contains typed conversion scaffolding for gradual migration
away from legacy converter internals.

## Current state

- Address conversion has a typed v2 adapter (`addresses.py`) that preserves
  v1 output format while introducing typed models (`models.py`).
- Address-group conversion has a typed v2 adapter (`address_groups.py`).
- Service conversion has a typed v2 adapter (`services.py`) with the same
  parity-first approach.
- Service-group conversion has a typed v2 adapter (`service_groups.py`).
- Route conversion has a typed v2 adapter (`routes.py`) with parity-first
  behavior and typed static-route models.
- Policy conversion has a typed v2 adapter (`policies.py`).
- Interface conversion has a typed v2 adapter (`interfaces.py`).
- Runtime behavior is intentionally parity-first.

## Migration strategy

1. Keep v1 converter output as source of truth.
2. Add typed v2 adapters per object domain (addresses, services, routes, etc.).
3. Add parity tests for each domain before replacing internals.
4. Refactor implementation behind v2 adapters while preserving output contract.
