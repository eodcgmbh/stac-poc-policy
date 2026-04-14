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
    orgs := object.get(input.collection.access, "allowed_organisations", [])
    count(orgs) == 0
}

access_metadata_errors contains "access.allowed_users must be a non-empty array when visibility is 'user'" if {
    input.collection.access.visibility == "user"
    users := object.get(input.collection.access, "allowed_users", [])
    count(users) == 0
}

access_metadata_errors contains "public collections must specify at least one non-empty allowed_organisations or allowed_users" if {
    input.collection.access.visibility == "public"
    orgs := object.get(input.collection.access, "allowed_organisations", [])
    users := object.get(input.collection.access, "allowed_users", [])
    count(orgs) == 0
    count(users) == 0
}

access_metadata_errors contains "context is required" if {
    not input.context
}

valid_access_metadata if {
    count(access_metadata_errors) == 0
}

user_has_access if {
    input.collection.access.visibility == "public"
    org := object.get(input.context, "organisation", null)
    org != null
    org in input.collection.access.allowed_organisations
}

user_has_access if {
    input.collection.access.visibility == "public"
    email := object.get(input.context, "email", null)
    email != null
    email in input.collection.access.allowed_users
}

user_has_access if {
    input.collection.access.visibility == "organisation"
    org := object.get(input.context, "organisation", null)
    org != null
    org in input.collection.access.allowed_organisations
}

user_has_access if {
    input.collection.access.visibility == "user"
    email := object.get(input.context, "email", null)
    email != null
    email in input.collection.access.allowed_users
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
