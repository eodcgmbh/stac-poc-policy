package stac.collections

import future.keywords.contains
import future.keywords.if


user := input.payload.preferred_username
org  := input.payload.organisation

# Take the last "@"-part so a local part containing "@" (quoted) can't
# spoof a domain; usernames without "@" yield no domain at all.
domain := parts[count(parts) - 1] if {
    user != null
    parts := split(user, "@")
    count(parts) > 1
}

# Public collections are always visible. The org/user branches only
# contribute when the request carries the relevant claim; for anonymous
# requests the proxy sends `payload: null`, so both are undefined here.
applicable contains public_filter

applicable contains org_filter if {
    org != null
}

applicable contains user_filter if {
    user != null
}

applicable contains domain_filter if {
    domain
}

or_args := [f | f := applicable[_]]

# A single applicable branch is emitted as-is. CQL2-JSON requires `or` to
# have >= 2 args, so a 1-arg `or` is rejected by the cql2 evaluator. This
# also covers anonymous requests (payload null/absent -> only public_filter).
filter := or_args[0] if {
    count(or_args) == 1
}

# Multiple applicable branches: OR them together.
filter := {"op": "or", "args": or_args} if {
    count(or_args) > 1
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

domain_filter := {
    "op": "and",
    "args": [
        {
            "op": "=",
            "args": [{"property": "access.visibility"}, "domain"]
        },
        {
            "op": "a_contains",
            "args": [{"property": "access.allowed_domains"}, [domain]]
        }
    ]
}
