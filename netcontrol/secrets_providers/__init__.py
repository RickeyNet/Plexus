"""External secrets providers: HashiCorp Vault, AWS Secrets Manager and
Azure Key Vault (docs/secrets-providers.md).

A credential or secret variable may hold a reference (provider, path, key)
instead of a stored value. ``netcontrol.secrets_providers.service`` resolves
it at the points where Plexus decrypts secrets for use
(``routes.db.credentials.get_credential_raw`` and
``routes.secret_resolver``), so every consumer gets the external value
without code of its own.

Modules: ``base`` (the interface, errors, key selection and the TTL cache),
``vault``, ``aws`` and ``azure`` (one provider each), ``service`` (provider
settings, the resolution choke point and its audit trail).
"""
