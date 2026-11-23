"""The levels of a relation (D56).  A base relation is one level, its table's (key, value); a
composed relation adds one level per hop.  Every consumer that needs a relation's tables reads
them here, so a composed relation is never mistaken for one table.

The compiler also needs the prefixes of a chain (the D21 visibility policy of hop `i` reads the
relation up to hop `i - 1`): `name/i` is the relation `name` cut after its `i`-th hop.  A prefix
name never appears in a spec (relation names are identifiers); it is internal to the derived
policies and their encodings."""
from __future__ import annotations

from dataclasses import dataclass

from mls.spec.model import ComposedRelation, Relation, Spec


@dataclass(frozen=True)
class Level:
    table: str
    key: str | None   # None: the base level of a set relation (#63), no key column
    value: str


def is_set(spec: Spec, name: str) -> bool:
    """#63: the relation (or a prefix of one) starts from a set relation: its facts are values only
    (encoded with one fixed key, `logic/tvl.py:SET_KEY`), and a membership in it has no key."""
    rel = spec.relations.get(base_name(spec, name))
    return isinstance(rel, Relation) and rel.key is None


def split(name: str) -> tuple[str, int | None]:
    """`r/2` -> (`r`, 2); `r` -> (`r`, None)."""
    if "/" in name:
        base, _, i = name.partition("/")
        return base, int(i)
    return name, None


def prefix(name: str, hops: int) -> str:
    """The relation `name` cut after `hops` hops (0: its base relation)."""
    return name if hops is None else f"{name}/{hops}"


def levels(spec: Spec, name: str) -> list[Level]:
    rname, cut = split(name)
    rel = spec.relations[rname]
    if isinstance(rel, Relation):
        return [Level(rel.table, rel.key, rel.value)]
    assert isinstance(rel, ComposedRelation)
    base = spec.relations[rel.of]
    out = [Level(base.table, base.key, base.value)] + [Level(h.table, h.key, h.value) for h in rel.through]
    return out if cut is None else out[:cut + 1]


def single_keys(spec: Spec, table: str) -> set[str]:
    """The columns that are a key of `table` on their own (the primary key or a unique set)."""
    t = spec.tables[table]
    sets = ([t.primary_key] if t.primary_key else []) + list(t.unique or [])
    return {s[0] for s in sets if len(s) == 1}


def is_lookup(spec: Spec, lvl: Level) -> bool:
    """D56: a hop whose value is unique on its own, so that each value has one key and the step back
    from a value is a function.  Every other hop (up a foreign key, #43, or through a membership
    table whose pair alone is unique, #33) is read forwards only, as its own relation symbol."""
    return lvl.value in single_keys(spec, lvl.table)


def is_up(spec: Spec, lvl: Level) -> bool:
    """#43: a hop up a foreign key: its key is unique and its value is not (a project's
    organization), so a value may have many rows and the hop is no function from value to key."""
    keys = single_keys(spec, lvl.table)
    return lvl.value not in keys and lvl.key in keys


def up_name(spec: Spec, name: str, i: int) -> str:
    """The relation symbol of the chain `name` cut after its upward hop `i` (#43): named after its
    definition, the base relation's table, key, value and condition and then the hops, never a
    relation's name, so identical chains share it (in a spec, and across the two versions a diff
    compares, where an import and the loop name the same relation differently)."""
    import hashlib
    import json

    lv = levels(spec, name)
    cond = condition(spec, name)
    tag = "" if cond is None else "#" + hashlib.sha1(
        json.dumps(cond.model_dump(mode="json", by_alias=True, exclude_none=True), sort_keys=True).encode()).hexdigest()[:10]
    return ".".join(f"{h.table}.{h.key}.{h.value}" for h in lv[:i + 1]) + tag


def base_name(spec: Spec, name: str) -> str:
    """The base relation a relation (or a prefix of one) starts from."""
    rname, _ = split(name)
    rel = spec.relations[rname]
    return rel.of if isinstance(rel, ComposedRelation) else rname


def is_composed(spec: Spec, name: str) -> bool:
    return len(levels(spec, name)) > 1


def hop_prefix(spec: Spec, name: str, i: int) -> str:
    """The relation whose values are the keys of level `i` (i ≥ 1): the base relation for the
    first hop, else the prefix `name/(i-1)`."""
    return base_name(spec, name) if i == 1 else prefix(split(name)[0], i - 1)


def key_type(spec: Spec, name: str) -> str | None:
    lv = levels(spec, name)[0]
    return None if lv.key is None else spec.tables[lv.table].columns[lv.key].type


def value_type(spec: Spec, name: str) -> str:
    lv = levels(spec, name)[-1]
    return spec.tables[lv.table].columns[lv.value].type


def condition(spec: Spec, name: str):
    """The condition of the base relation a relation (or prefix) starts from (D61), or None."""
    rel = spec.relations[base_name(spec, name)]
    return rel.where if isinstance(rel, Relation) else None


def read_columns(spec: Spec, name: str) -> list[tuple[str, set[str]]]:
    """(table, columns) a membership in `name` reads at each level: the level's key and value,
    and at the base the columns of its condition (D61)."""
    from pydantic import BaseModel

    from mls.spec.model import ColRef

    def cols(obj, out: set[str]) -> set[str]:
        if isinstance(obj, ColRef):
            out.add(obj.col)
        elif isinstance(obj, BaseModel):
            for f in type(obj).model_fields:
                cols(getattr(obj, f), out)
        elif isinstance(obj, (list, tuple)):
            for x in obj:
                cols(x, out)
        return out

    out = [(lv.table, {c for c in (lv.key, lv.value) if c is not None}) for lv in levels(spec, name)]
    cond = condition(spec, name)
    if cond is not None:
        out[0][1].update(cols(cond, set()))
    return out
