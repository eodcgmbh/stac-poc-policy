package stac.collections

import future.keywords.contains
import future.keywords.if


user := input.payload.preferred_username
org  := input.payload.organisation


# Unauthenticated: public collections only
filter := public_filter if {
    not input.payload
}

# Authenticated: OR together whichever branches apply
filter := {"op": "or", "args": or_args} if {
    input.payload
}

# Each partial rule contributes to the set only when its condition holds.
# This avoids null-bearing branches reaching the cql2 evaluator.

or_args := [f | f := applicable[_]]

applicable contains public_filter

applicable contains org_filter if {
    org != null
}

applicable contains user_filter if {
    user != null
}

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
