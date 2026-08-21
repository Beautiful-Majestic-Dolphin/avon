"""SCIM filter expression parser.

Supports a minimal subset of SCIM filtering (RFC 7644 Section 3.4.2.2):
- eq (equals): userName eq "john@example.com"
- co (contains): userName co "john"
- sw (starts with): userName sw "john"

No compound filters (and/or) initially.
"""

import re

# SCIM attribute -> database column mapping
SCIM_USER_ATTRIBUTES = {
    "userName": "email",
    "externalId": "external_id",
    "displayName": "full_name",
    "name.formatted": "full_name",
}

SCIM_GROUP_ATTRIBUTES = {
    "displayName": "name",
    "externalId": "external_id",
}

# Filter pattern: attribute operator "value"
FILTER_PATTERN = re.compile(r'^(\S+)\s+(eq|co|sw)\s+"([^"]*)"$', re.IGNORECASE)


class ScimFilter:
    """Parsed SCIM filter expression."""

    def __init__(self, column: str, operator: str, value: str):
        self.column = column
        self.operator = operator.lower()
        self.value = value


def parse_filter(
    filter_str: str | None,
    attribute_map: dict[str, str],
) -> ScimFilter | None:
    """Parse a SCIM filter string into a ScimFilter.

    Returns None if filter_str is None or empty.
    Raises ValueError if the filter is malformed or uses unsupported attributes.
    """
    if not filter_str:
        return None

    match = FILTER_PATTERN.match(filter_str.strip())
    if not match:
        raise ValueError(f"Unsupported filter expression: {filter_str}")

    scim_attr, operator, value = match.groups()

    column = attribute_map.get(scim_attr)
    if column is None:
        raise ValueError(f"Unknown SCIM attribute: {scim_attr}")

    return ScimFilter(column=column, operator=operator.lower(), value=value)
