package stac.items

import data.stac.collections
import rego.v1

upstream := object.get(opa.runtime().env, "STAC_UPSTREAM_URL", "http://eoapi-stac:8080")

collection_id := input.req.path_params.collection_id

is_search if {
	endswith(input.req.path, "/search")
}

is_write if {
	collections.is_write
	not is_search
}

allow_filter := {"op": "=", "args": [1, 1]}

access_list(col, name) := object.get(col, ["access", name], [])

visibility(col) := object.get(col, ["access", "visibility"], null)

member(col) if {
	visibility(col) == "organisation"
	collections.org != null
	collections.org in access_list(col, "allowed_organisations")
}

member(col) if {
	visibility(col) == "user"
	collections.email in access_list(col, "allowed_users")
}

member(col) if {
	visibility(col) == "domain"
	collections.domain in access_list(col, "allowed_domains")
}

member(col) if {
	visibility(col) == "group"
	some g in access_list(col, "allowed_groups")
	g in collections.groups
}

can_read(col) if visibility(col) == "public"

can_read(col) if member(col)

can_write(col) if member(col)

can_write(col) if {
	visibility(col) == "public"
	collections.org != null
	collections.org in access_list(col, "allowed_organisations")
}

can_write(col) if {
	visibility(col) == "public"
	collections.email in access_list(col, "allowed_users")
}

can_write(col) if {
	visibility(col) == "public"
	collections.domain in access_list(col, "allowed_domains")
}

can_write(col) if {
	visibility(col) == "public"
	some g in access_list(col, "allowed_groups")
	g in collections.groups
}

target := response.body if {
	response := http.send({
		"method": "GET",
		"url": sprintf("%s/collections/%s", [upstream, urlquery.encode(collection_id)]),
		"raise_error": false,
	})
	response.status_code == 200
}

all_collections := response.body.collections if {
	response := http.send({
		"method": "GET",
		"url": sprintf("%s/collections?limit=10000", [upstream]),
		"force_cache": true,
		"force_cache_duration_seconds": 5,
		"raise_error": false,
	})
	response.status_code == 200
}

readable_ids := [col.id | some col in all_collections; can_read(col)]

default filter := {"op": "=", "args": [1, 0]}

filter := allow_filter if {
	collection_id
	not is_write
	can_read(target)
}

filter := allow_filter if {
	collection_id
	is_write
	can_write(target)
}

filter := {"op": "in", "args": [{"property": "collection"}, readable_ids]} if {
	not collection_id
	is_search
	count(readable_ids) > 0
}
