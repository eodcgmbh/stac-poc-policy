package stac.collections_test

import data.stac.collections
import future.keywords.if
import future.keywords.in

# Anonymous requests arrive with payload: null (sent by stac-auth-proxy) or
# no payload at all. Both must yield the bare public-visibility comparison,
# never a single-arg `or` (CQL2-JSON requires `or` to have >= 2 args, and the
# cql2 evaluator rejects a 1-arg `or`).
test_anonymous_null_payload if {
	collections.filter == collections.public_filter with input as {"payload": null}
}

test_anonymous_missing_payload if {
	collections.filter == collections.public_filter with input as {}
}

# Authenticated token without org/user claims still only sees public.
test_authenticated_without_claims if {
	collections.filter == collections.public_filter with input as {"payload": {"sub": "x"}}
}

# A single applicable branch is never wrapped in `or`.
test_single_branch_is_not_wrapped_in_or if {
	collections.filter.op == "=" with input as {"payload": null}
}

# Org claim -> OR of org + public (2 args).
test_org_claim_combines_with_public if {
	f := collections.filter with input as {"payload": {"organisation": "eodc"}}
	f.op == "or"
	count(f.args) == 2
}

# Full claims -> OR of org + user + public (3 args).
test_full_claims_combine_all_branches if {
	f := collections.filter with input as {"payload": {"preferred_username": "alice", "organisation": "eodc"}}
	f.op == "or"
	count(f.args) == 3
}

# Email-style username additionally enables the domain branch (4 args).
test_email_username_adds_domain_branch if {
	f := collections.filter with input as {"payload": {"preferred_username": "alice@eodc.eu", "organisation": "eodc"}}
	f.op == "or"
	count(f.args) == 4
	collections.domain == "eodc.eu" with input as {"payload": {"preferred_username": "alice@eodc.eu"}}
}

# Username without "@" must not produce a domain branch: public + user only.
test_non_email_username_has_no_domain_branch if {
	f := collections.filter with input as {"payload": {"preferred_username": "alice"}}
	count(f.args) == 2
	count([a | a := f.args[_]; {"op": "=", "args": [{"property": "access.visibility"}, "domain"]} in a.args]) == 0
}
