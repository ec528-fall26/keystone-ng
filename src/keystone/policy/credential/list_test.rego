package test_credential_list

import data.identity.credential.list

test_allowed if {
	list.allow with input as {"credentials": {"roles": ["admin"]}}
	list.allow with input as {"credentials": {"is_admin": true, "roles": []}}
	list.allow with input as {"credentials": {"roles": ["reader"], "system": "all"}}
}

# A caller filtering to their own user ID may list, whatever roles they hold
# (issue #1117) -- ownership alone is the grant, matching
# `identity/credential/show` and python keystone.
test_allowed_own_user_id if {
	list.allow with input as {
		"credentials": {"roles": ["member"], "user_id": "u1"},
		"target": {"credential": {"user_id": "u1", "type": null}},
	}

	list.allow with input as {
		"credentials": {"roles": [], "user_id": "u1"},
		"target": {"credential": {"user_id": "u1", "type": null}},
	}

	list.allow with input as {
		"credentials": {"roles": ["reader"], "user_id": "u1"},
		"target": {"credential": {"user_id": "u1", "type": "totp"}},
	}
}

test_forbidden if {
	not list.allow with input as {"credentials": {"roles": []}}
	not list.allow with input as {"credentials": {"roles": ["reader"]}}
}

# The core of issue #1117: holding `member` is no longer enough to scan the
# whole collection. Every shape of "no usable own-user filter" must deny.
test_forbidden_unfiltered_list if {
	# `user_id` omitted entirely (key absent).
	not list.allow with input as {
		"credentials": {"roles": ["member"], "user_id": "u1"},
		"target": {"credential": {"type": null}},
	}

	# `user_id` present but null -- the shape the handler actually emits for
	# an absent `?user_id=`, since the `Option` is serialized, not skipped.
	not list.allow with input as {
		"credentials": {"roles": ["member"], "user_id": "u1"},
		"target": {"credential": {"user_id": null, "type": null}},
	}

	# `target.credential` missing altogether -- fail closed, never undefined.
	not list.allow with input as {
		"credentials": {"roles": ["member"], "user_id": "u1"},
		"target": {},
	}

	# A bare `?user_id=` deserializes to `Some("")`, which is not null and so
	# clears the first guard -- the equality has to be what rejects it.
	not list.allow with input as {
		"credentials": {"roles": ["member"], "user_id": "u1"},
		"target": {"credential": {"user_id": "", "type": null}},
	}

	# `input.target` null outright. This handler never emits that shape, but
	# the rule must not go undefined-and-therefore-permissive if one ever does.
	not list.allow with input as {
		"credentials": {"roles": ["member"], "user_id": "u1"},
		"target": null,
	}

	# No caller identity to compare against -- `Credentials.user_id` is
	# non-optional today, so this only fires if that ever regresses.
	not list.allow with input as {
		"credentials": {"roles": ["member"]},
		"target": {"credential": {"user_id": "u1", "type": null}},
	}
}

# Filtering to somebody else's user ID must not grant the scan either.
test_forbidden_other_user_id if {
	not list.allow with input as {
		"credentials": {"roles": ["member"], "user_id": "u1"},
		"target": {"credential": {"user_id": "u2", "type": null}},
	}

	# A non-system `reader` gets no exemption.
	not list.allow with input as {
		"credentials": {"roles": ["reader"], "user_id": "u1"},
		"target": {"credential": {"user_id": "u2", "type": null}},
	}

	# `system` scoped to something other than `all` is not a privileged
	# lister either.
	not list.allow with input as {
		"credentials": {"roles": ["reader"], "system": "other", "user_id": "u1"},
		"target": {"credential": {"user_id": "u2", "type": null}},
	}
}

# A privileged lister keeps the unfiltered collection view.
test_allowed_privileged_unfiltered if {
	list.allow with input as {
		"credentials": {"roles": ["admin"], "user_id": "u1"},
		"target": {"credential": {"user_id": null, "type": null}},
	}

	list.allow with input as {
		"credentials": {"roles": ["reader"], "system": "all", "user_id": "u1"},
		"target": {"credential": {"user_id": "u2", "type": null}},
	}
}

# The denial carries an actionable message; an allowed request carries none.
test_violation if {
	count(list.violation) == 1 with input as {
		"credentials": {"roles": ["member"], "user_id": "u1"},
		"target": {"credential": {"user_id": null, "type": null}},
	}

	count(list.violation) == 0 with input as {
		"credentials": {"roles": ["member"], "user_id": "u1"},
		"target": {"credential": {"user_id": "u1", "type": null}},
	}
}
