package stac.ingest

import rego.v1

default allow := false

valid_visibility := {"public", "organisation", "user"}

access_metadata_errors contains "access.visibility is required" if {
	not input.collection.access.visibility
}

access_metadata_errors contains msg if {
	vis := input.collection.access.visibility
	not vis in valid_visibility
	msg := sprintf("access.visibility %q is not valid; must be one of: public, organisation, user", [vis])
}

access_metadata_errors contains "access.allowed_organisations must be a non-empty array when visibility is 'organisation'" if {
	input.collection.access.visibility == "organisation"
	count(input.collection.access.allowed_organisations) == 0
}

access_metadata_errors contains "access.allowed_users must be a non-empty array when visibility is 'user'" if {
	input.collection.access.visibility == "user"
	count(input.collection.access.allowed_users) == 0
}

valid_access_metadata if {
	count(access_metadata_errors) == 0
}

# Self-access check

user_has_access if {
	input.collection.access.visibility == "public"
}

user_has_access if {
	input.collection.access.visibility == "organisation"
	input.context.organisation != null
	input.context.organisation in input.collection.access.allowed_organisations
}

user_has_access if {
	input.collection.access.visibility == "user"
	input.context.email != null
	input.context.email in input.collection.access.allowed_users
}


allow if {
	valid_access_metadata
	user_has_access
}

errors contains msg if {
	some msg in access_metadata_errors
}

errors contains "user does not have access to this collection" if {
	valid_access_metadata
	not user_has_access
}
