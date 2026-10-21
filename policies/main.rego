package stac.collections

import future.keywords.contains
import future.keywords.if
import future.keywords.in


org := input.payload.organisation

email := input.payload.email if {
    input.payload.email_verified == true
}

# Take the last "@"-part so a local part containing "@" (quoted) can't
# spoof a domain; emails without "@" yield no domain at all.
domain := parts[count(parts) - 1] if {
    parts := split(email, "@")
    count(parts) > 1
}

group_prefix := "/services/data-access/"

groups := sort([name |
    some g in object.get(input, ["payload", "groups"], [])
    is_string(g)
    startswith(g, group_prefix)
    name := substring(g, count(group_prefix), -1)
    name != ""
])

is_write if {
    not upper(object.get(object.get(input, "req", {}), "method", "GET")) in {"GET", "HEAD", "OPTIONS"}
}

# Public collections are always visible. The org/user branches only
# contribute when the request carries the relevant claim; for anonymous
# requests the proxy sends `payload: null`, so both are undefined here.
applicable contains public_filter if {
    not is_write
}

applicable contains org_filter if {
    org != null
}

applicable contains user_filter if {
    email
}

applicable contains domain_filter if {
    domain
}

applicable contains group_filter if {
    count(groups) > 0
}

applicable contains public_group_owner_filter if {
    is_write
    count(groups) > 0
}

applicable contains public_owner_filter("allowed_organisations", org) if {
    is_write
    org != null
}

applicable contains public_owner_filter("allowed_users", email) if {
    is_write
    email
}

applicable contains public_owner_filter("allowed_domains", domain) if {
    is_write
    domain
}

or_args := [f | f := applicable[_]]

filter := deny_filter if {
    count(or_args) == 0
}

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

deny_filter := {"op": "=", "args": [1, 0]}

public_owner_filter(list, value) := {
    "op": "and",
    "args": [public_filter, contains_value(list, value)]
}

visibility_is(value) := {
    "op": "and",
    "args": [
        {"op": "not", "args": [{"op": "isNull", "args": [{"property": "access.visibility"}]}]},
        {"op": "=", "args": [{"property": "access.visibility"}, value]}
    ]
}

contains_value(list, value) := {
    "op": "and",
    "args": [
        {"op": "not", "args": [{"op": "isNull", "args": [{"property": sprintf("access.%s", [list])}]}]},
        {"op": "a_contains", "args": [{"property": sprintf("access.%s", [list])}, [value]]}
    ]
}

overlaps_values(list, values) := {
    "op": "and",
    "args": [
        {"op": "not", "args": [{"op": "isNull", "args": [{"property": sprintf("access.%s", [list])}]}]},
        {"op": "a_overlaps", "args": [{"property": sprintf("access.%s", [list])}, values]}
    ]
}

public_filter := visibility_is("public")

org_filter := {
    "op": "and",
    "args": [
        visibility_is("organisation"),
        contains_value("allowed_organisations", org)
    ]
}

user_filter := {
    "op": "and",
    "args": [
        visibility_is("user"),
        contains_value("allowed_users", email)
    ]
}

domain_filter := {
    "op": "and",
    "args": [
        visibility_is("domain"),
        contains_value("allowed_domains", domain)
    ]
}

group_filter := {
    "op": "and",
    "args": [
        visibility_is("group"),
        overlaps_values("allowed_groups", groups)
    ]
}

public_group_owner_filter := {
    "op": "and",
    "args": [public_filter, overlaps_values("allowed_groups", groups)]
}
