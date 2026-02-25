package stac.collections

import rego.v1

default allow := false

user_in_allowed_emails(allowed_emails) if {
	user_email := input.context.email
	user_email != null
	user_email in allowed_emails
}

org_in_allowed_orgs(allowed_orgs) if {
	user_org := input.context.organisation
	user_org != null
	user_org in allowed_orgs
}

# Public collections
allow if {
	input.collection.access.visibility == "public"
}

# Organisation-based access
allow if {
	input.collection.access.visibility == "organisation"
	org_in_allowed_orgs(input.collection.access.allowed_organisations)
}

# User-based access
allow if {
	input.collection.access.visibility == "user"
	user_in_allowed_emails(input.collection.access.allowed_users)
}

collections_cql2 := filter_expression if {
	filter_expression := concat(" OR ", [
		build_public_filter,
		build_org_filter,
		build_user_filter,
	])
}

build_public_filter := "access.visibility = 'public'" if {
	true
}

build_org_filter := cql_expr if {
	input.context.organisation != null
	cql_expr := sprintf("(access.visibility = 'organisation' AND access.allowed_organisations IN ('%s'))", [input.context.organisation])
}

build_user_filter := cql_expr if {
	input.context.email != null
	cql_expr := sprintf("(access.visibility = 'user' AND access.allowed_users IN ('%s'))", [input.context.email])
}