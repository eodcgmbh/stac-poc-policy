package stac.collections

import future.keywords.if
import future.keywords.in

user := input.payload.preferred_username
org  := input.payload.organisation

filter := public_filter if {
    not input.payload
}

filter := authed_filter if {
    input.payload
}

authed_filter := {"op": "or", "args": or_args}

or_args := args if {
    org  != null
    user != null
    args := [public_filter, org_filter, user_filter]
} else := args if {
    org  != null
    user == null
    args := [public_filter, org_filter]
} else := args if {
    org  == null
    user != null
    args := [public_filter, user_filter]
} else := [public_filter]

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
