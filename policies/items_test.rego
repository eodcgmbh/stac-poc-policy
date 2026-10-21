package stac.items_test

import data.stac.items
import rego.v1

ara := {"id": "ara", "access": {"visibility": "public", "allowed_users": [], "allowed_organisations": [], "allowed_domains": ["geosphere.at"]}}

bfw := {"id": "bfw", "access": {"visibility": "user", "allowed_users": ["a@tuwien.ac.at"], "allowed_organisations": []}}

noaa := {"id": "noaa"}

mock_send(request) := {"status_code": 200, "body": {"collections": [ara, bfw, noaa]}} if {
	contains(request.url, "/collections?")
}

mock_send(request) := {"status_code": 200, "body": ara} if endswith(request.url, "/collections/ara")

mock_send(request) := {"status_code": 200, "body": bfw} if endswith(request.url, "/collections/bfw")

mock_send(request) := {"status_code": 404, "body": {}} if endswith(request.url, "/collections/missing")

geo := {"email": "c@geosphere.at", "email_verified": true}

eodc := {"email": "x@eodc.eu", "email_verified": true, "organisation": "eodc"}

tuw := {"email": "a@tuwien.ac.at", "email_verified": true}

req(method, path, collection) := {"method": method, "path": path, "path_params": {"collection_id": collection}}

test_anonymous_reads_public_items if {
	items.filter == items.allow_filter with input as {"req": req("GET", "/collections/ara/items", "ara"), "payload": null}
		with http.send as mock_send
}

test_anonymous_cannot_read_restricted_items if {
	items.filter == {"op": "=", "args": [1, 0]} with input as {"req": req("GET", "/collections/bfw/items", "bfw"), "payload": null}
		with http.send as mock_send
}

test_listed_user_reads_restricted_items if {
	items.filter == items.allow_filter with input as {"req": req("GET", "/collections/bfw/items/x", "bfw"), "payload": tuw}
		with http.send as mock_send
}

test_owner_bulk_writes_public_collection if {
	items.filter == items.allow_filter with input as {"req": req("POST", "/collections/ara/bulk_items", "ara"), "payload": geo}
		with http.send as mock_send
}

test_non_owner_cannot_write_public_collection if {
	items.filter == {"op": "=", "args": [1, 0]} with input as {"req": req("POST", "/collections/ara/items", "ara"), "payload": eodc}
		with http.send as mock_send
}

test_non_member_cannot_delete_restricted_item if {
	items.filter == {"op": "=", "args": [1, 0]} with input as {"req": req("DELETE", "/collections/bfw/items/x", "bfw"), "payload": eodc}
		with http.send as mock_send
}

test_missing_collection_is_denied if {
	items.filter == {"op": "=", "args": [1, 0]} with input as {"req": req("POST", "/collections/missing/items", "missing"), "payload": geo}
		with http.send as mock_send
}

test_anonymous_search_limited_to_public if {
	items.filter == {"op": "in", "args": [{"property": "collection"}, ["ara"]]} with input as {"req": {"method": "GET", "path": "/search", "path_params": {}}, "payload": null}
		with http.send as mock_send
}

test_post_search_is_a_read if {
	f := items.filter with input as {"req": {"method": "POST", "path": "/search", "path_params": {}}, "payload": tuw}
		with http.send as mock_send
	f == {"op": "in", "args": [{"property": "collection"}, ["ara", "bfw"]]}
}

grp := {"id": "grp", "access": {"visibility": "group", "allowed_groups": ["bfw"]}}

owned := {"id": "owned", "access": {"visibility": "public", "allowed_groups": ["bfw"]}}

mock_send_groups(request) := {"status_code": 200, "body": {"collections": [ara, grp, owned]}} if {
	contains(request.url, "/collections?")
}

mock_send_groups(request) := {"status_code": 200, "body": grp} if endswith(request.url, "/collections/grp")

mock_send_groups(request) := {"status_code": 200, "body": owned} if endswith(request.url, "/collections/owned")

bfw_member := {"groups": ["/services/data-access/bfw"]}

test_group_member_reads_group_items if {
	items.filter == items.allow_filter with input as {"req": req("GET", "/collections/grp/items", "grp"), "payload": bfw_member}
		with http.send as mock_send_groups
}

test_non_member_cannot_read_group_items if {
	items.filter == {"op": "=", "args": [1, 0]} with input as {"req": req("GET", "/collections/grp/items", "grp"), "payload": eodc}
		with http.send as mock_send_groups
}

test_group_member_writes_group_owned_public if {
	items.filter == items.allow_filter with input as {"req": req("POST", "/collections/owned/bulk_items", "owned"), "payload": bfw_member}
		with http.send as mock_send_groups
}

test_group_search_includes_group_collections if {
	f := items.filter with input as {"req": {"method": "GET", "path": "/search", "path_params": {}}, "payload": bfw_member}
		with http.send as mock_send_groups
	f == {"op": "in", "args": [{"property": "collection"}, ["ara", "grp", "owned"]]}
}
