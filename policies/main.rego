package stac.collections

import future.keywords.if

# ─── Identity extraction ────────────────────────────────────────────────────

user := input.payload.preferred_username
org  := input.payload.organisation

# ─── Top-level filter ───────────────────────────────────────────────────────

# Unauthenticated: public collections only
filter := public_filter if {
    not input.payload
}

# Authenticated: OR together whichever branches apply
filter := {"op": "or", "args": or_args} if {
    input.payload
}

# ─── Build OR args via comprehension ────────────────────────────────────────
# Each partial rule contributes to the set only when its condition holds.
# This avoids null-bearing branches reaching the cql2 evaluator.

or_args := [f | f := applicable[_]]

applicable[public_filter]

applicable[org_filter] if {
    org != null
}

applicable[user_filter] if {
    user != null
}

# ─── Filter fragments ───────────────────────────────────────────────────────

public_filter := {
    "op": "=",
    "args": [{"property": "access.visibility"}, "public"]
}

org_filter := {
    "op": "and",
    "args": [
        {
            "op": "=",
            "args": [{"property": "access.visibility"}, "organisation"]
        },
        {
            "op": "a_contains",
            "args": [{"property": "access.allowed_organisations"}, [org]]
        }
    ]
}

user_filter := {
    "op": "and",
    "args": [
        {
            "op": "=",
            "args": [{"property": "access.visibility"}, "user"]
        },
        {
            "op": "a_contains",
            "args": [{"property": "access.allowed_users"}, [user]]
        }
    ]
}
