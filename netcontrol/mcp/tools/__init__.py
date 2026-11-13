"""MCP tool handlers, one module per data category.

Each module registers its tools at import; ``registry.load_tools`` imports
them all. Handlers are read-only and return plain data: masking, the size
cap and the audit event are the dispatcher's job.
"""
