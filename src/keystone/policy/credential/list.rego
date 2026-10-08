# METADATA
# title: List credentials
# description: Policy for listing credentials
package identity.credential.list

# List credentials.
#
# The `input.target.credential` contains query parameters:
#   type:    string (optional)  Filter by credential type.
#   user_id: string (optional)  Filter by owning user ID.
#
# The `input.existing` is null
#
# An ordinary caller may list only their *own* credentials, and has to say
# so explicitly: the request must carry a `user_id` filter naming the
# caller (issue #1117). Granting every `member` an unfiltered list is not a
# disclosure bug — the per-item re-check below drops the rows they may not
# read — but it turns one cheap request into a full-collection scan plus
# one OPA evaluation per row, a resource-exhaustion amplifier available to
# any authenticated user. Demanding the filter up front lets the driver
# narrow the query in SQL instead of materializing the whole table. This
# mirrors python keystone's `user_id:%(target.credential.user_id)s`, which
# likewise resolves against the query parameters and so denies an
# unfiltered list to an unprivileged caller.
#
# Ownership alone suffices; no role is required.
# `identity/credential/show` already grants a non-delegated caller their
# own credential on ownership alone, and python keystone's rule carries no
# role component either, so requiring `member` here would deny a
# reader-scoped caller their own credentials for no security gain.
#
# This remains only the first of the two policy checks required to list
# credentials safely (ADR 0019 §2, CVE-2019-19687): the API layer
# additionally re-enforces `identity/credential/show` against every
# individual record before returning it. That re-check still carries real
# weight for the privileged listers below, who legitimately see other
# users' rows.
#
# The delegation project boundary (OSSA-2026-015) is enforced entirely by
# that per-item `identity/credential/show` re-check, not here. There is no
# resource project to anchor on at this point — only query parameters — so
# I2's `bound_to_own_delegation_project` has nothing to compare against
# (see `doc/src/contributor/security-model.md` I2/I8). A delegated caller
# filtering to their own `user_id` passes this rule and then has every
# cross-project and unscoped record dropped by the re-check.
#
default allow := false

# METADATA
# description: "`Admin` is allowed by default"
allow if {
	"admin" in input.credentials.roles
}

allow if {
	input.credentials.is_admin
}

allow if {
	"reader" in input.credentials.roles
	input.credentials.system == "all"
}

# METADATA
# description: "Any caller may list their own credentials, provided the request is explicitly filtered to their own user ID. An omitted filter reaches OPA as JSON `null` (the handler serializes the absent `Option` rather than skipping the key) and is rejected, as is a filter naming anyone else."
allow if {
	user_id_filter := object.get(input.target.credential, "user_id", null)
	user_id_filter != null
	user_id_filter == input.credentials.user_id
}

violation contains {"field": "user_id", "msg": msg} if {
	not allow
	msg := "listing credentials requires filtering by your own `user_id`, unless you hold the `admin` role or the `reader` role on the system scope."
}
