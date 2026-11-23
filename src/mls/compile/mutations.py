"""Deliberate compiler mutations, used only by tests to prove that each template's differential
test can fail (invariant 3).  Production compiles use the empty set."""
from __future__ import annotations

from enum import Enum


class Mutation(str, Enum):
    CHECK_NAIVE = "check_naive"                      # CHECK (p) instead of CHECK ((p) IS TRUE)
    TRANSITION_NAIVE = "transition_naive"            # IF NOT (p) instead of IF NOT ((p) IS TRUE)
    FK_MATCH_FULL = "fk_match_full"                  # MATCH FULL instead of MATCH SIMPLE
    POLICY_ALL_RESTRICTIVE = "policy_all_restrictive"  # emit every policy as restrictive
    POLICY_DROP_RESTRICTIVE = "policy_drop_restrictive"  # omit restrictive policies
    COLUMN_TABLE_GRANT = "column_table_grant"        # table-level grant instead of column list
    TIME_NULL_CLOSED = "time_null_closed"            # NULL bound closes the interval
    INDEX_NONE = "index_none"                        # emit no indexes
    HARDENING_NO_FORCE = "hardening_no_force"        # skip FORCE ROW LEVEL SECURITY
    OPAQUE_INVERT = "opaque_invert"                  # negate opaque SQL
    MIGRATE_SKIP_VALIDATE = "migrate_skip_validate"  # leave migrated constraints NOT VALID
    HIERARCHY_SHALLOW = "hierarchy_shallow"          # reach one level less than max_depth
    HIERARCHY_NO_DEPTH_CHECK = "hierarchy_no_depth_check"  # omit CHECK (depth <= max_depth)
    CARDINALITY_OFF_BY_ONE = "cardinality_off_by_one"  # n > max instead of n + 1 > max
    CARDINALITY_NO_LOCK = "cardinality_no_lock"      # skip the parent-row lock (concurrency)
    IN_DROP_LAST = "in_drop_last"                    # IN list without its last constant
    REPLACE_KEEPS_FOREIGN = "replace_keeps_foreign"  # drop only the declared names on an adopted table
    ADOPTED_KEEPS_CONSTRAINT = "adopted_keeps_constraint"  # keep an adopted table's same-named constraint unseen
    HOP_VISIBILITY_DROPPED = "hop_visibility_dropped"  # omit a composed relation's hop visibility policies
    RELATION_CONDITION_DROPPED = "relation_condition_dropped"  # a relation's subquery without its condition
    LOOKUP_KEY_DROPPED = "lookup_key_dropped"  # a lookup helper that returns the values of every key
    SET_HELPER_INVOKER = "set_helper_invoker"  # #63: a set relation's helper reads as the caller
    RELATION_NULL_KEY_MATCHES = "relation_null_key_matches"  # a relation's subquery also takes rows with a NULL key
    MEMBER_NULL_PASSES = "member_null_passes"  # a membership that holds when its value is NULL
    INCLUSION_NOT_DEFERRED = "inclusion_not_deferred"  # a deferred inclusion's foreign key checked per statement
    # #54: an inclusion into a relation with a condition, compiled to constraint triggers
    INCLUSION_CONDITION_DROPPED = "inclusion_condition_dropped"  # its triggers check the pair, not the condition
    INCLUSION_TARGET_UNCHECKED = "inclusion_target_unchecked"    # no trigger on the relation's table
    INCLUSION_NO_LOCK = "inclusion_no_lock"                      # the referenced row read without FOR SHARE
    CASCADE_AS_RESTRICT = "cascade_as_restrict"  # #60: an on_delete cascade inclusion compiled ON DELETE RESTRICT
    CARDINALITY_MIN_OFF_BY_ONE = "cardinality_min_off_by_one"  # #61: a minimum one row lower than the rule's
    CARDINALITY_WHERE_DROPPED = "cardinality_where_dropped"    # #61: every row counted, the condition ignored
    PAIR_KEY_DROPPED = "pair_key_dropped"  # #59: the unique key an inclusion's foreign key needs is not added
    SET_NULL_BOTH = "set_null_both"  # #62: an on_delete set_null inclusion that nulls both columns
    GUARD_ANY_ROW = "guard_any_row"                  # a column guard that limits every row, its condition ignored
    GUARD_SORTS_LAST = "guard_sorts_last"            # #58: a guard trigger named to fire after the table's own
    IDENT_UNQUOTED = "ident_unquoted"                # a predicate's column unquoted, so a mixed-case name folds
