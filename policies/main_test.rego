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
	collections.filter.op != "or" with input as {"payload": null}
}

# Org claim -> OR of org + public (2 args).
test_org_claim_combines_with_public if {
	f := collections.filter with input as {"payload": {"organisation": "eodc"}}
	f.op == "or"
	count(f.args) == 2
}

# Full claims -> OR of org + user + domain + public (4 args).
test_full_claims_combine_all_branches if {
	f := collections.filter with input as {"payload": {"email": "alice@eodc.eu", "email_verified": true, "organisation": "eodc"}}
	f.op == "or"
	count(f.args) == 4
	collections.domain == "eodc.eu" with input as {"payload": {"email": "alice@eodc.eu", "email_verified": true}}
}

test_unverified_email_is_ignored if {
	collections.filter == collections.public_filter with input as {"payload": {"email": "alice@eodc.eu", "email_verified": false}}
}

test_username_does_not_grant_user_or_domain if {
	collections.filter == collections.public_filter with input as {"payload": {"preferred_username": "alice@eodc.eu"}}
}

test_get_with_req_is_read if {
	collections.filter == collections.public_filter with input as {"req": {"method": "GET"}, "payload": null}
}

test_write_without_claims_is_denied if {
	collections.filter == collections.deny_filter with input as {"req": {"method": "POST"}, "payload": {"sub": "x"}}
}

test_write_drops_unconditional_public if {
	f := collections.filter with input as {"req": {"method": "DELETE"}, "payload": {"organisation": "eodc"}}
	f.op == "or"
	count(f.args) == 2
	not collections.public_filter in f.args
}

test_write_domain_owner_branch if {
	f := collections.filter with input as {"req": {"method": "PUT"}, "payload": {"email": "christoph@geosphere.at", "email_verified": true}}
	collections.public_owner_filter("allowed_domains", "geosphere.at") in f.args
	collections.public_owner_filter("allowed_users", "christoph@geosphere.at") in f.args
}

test_data_access_groups_are_extracted if {
	collections.groups == ["bfw", "maap"] with input as {"payload": {"groups": ["/services/data-access/maap", "/openstack_projects/x", "/services/data-access/bfw", "/services/data-access/"]}}
}

test_group_member_sees_group_collections if {
	f := collections.filter with input as {"payload": {"groups": ["/services/data-access/bfw"]}}
	collections.group_filter in f.args with input as {"payload": {"groups": ["/services/data-access/bfw"]}}
	collections.public_filter in f.args
}

test_other_groups_are_ignored if {
	collections.filter == collections.public_filter with input as {"payload": {"groups": ["/openstack_projects/bfw", "/eodc"]}}
}

test_group_member_may_write_public_group_owned if {
	f := collections.filter with input as {"req": {"method": "PUT"}, "payload": {"groups": ["/services/data-access/bfw"]}}
	collections.public_group_owner_filter in f.args with input as {"req": {"method": "PUT"}, "payload": {"groups": ["/services/data-access/bfw"]}}
	not collections.public_filter in f.args
}
