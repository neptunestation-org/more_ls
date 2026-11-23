"""CREATE TABLE with primary key and unique constraints (greenfield, D8)."""
from __future__ import annotations

from mls.compile.sql import column_ddl, const_sql, q
from mls.spec.model import Spec, Table, pair_unique


def pk_name(table: str) -> str:
    return f"{table}_pkey"


def unique_name(table: str, cols: list[str]) -> str:
    return f"{table}_{'_'.join(cols)}_key"


def implied_keys(spec: Spec) -> dict[str, dict[str, tuple[str, str]]]:
    """#59: per table, the unique constraints MLS adds itself, `mls_key_<table>_<key>_<value>`:
    an inclusion's foreign key references exactly a key on its relation's (key, value), and when
    the table declares none, but a key of the table lies within the pair (`model.pair_unique`, the
    primary key `id` of `products(id, org_id)`), the pair is already unique on any data, so adding
    the constraint can never fail and changes no row's fate."""
    out: dict[str, dict[str, tuple[str, str]]] = {}
    for r in spec.inclusions():
        rel = spec.relations[r.relation]
        t = spec.tables[rel.table]
        keys = ([t.primary_key] if t.primary_key else []) + list(t.unique)
        pair = (rel.key, rel.value)
        if any(frozenset(k) == frozenset(pair) for k in keys) or not pair_unique(keys, *pair):
            continue
        out.setdefault(rel.table, {})[f"mls_key_{rel.table}_{rel.key}_{rel.value}"] = pair
    return out


def implied_key_ddl(table: str, name: str, cols: tuple[str, str], adopted: bool) -> str:
    """An adopted table may hold the key already, from an earlier deploy."""
    add = f"alter table {q(table)} add constraint {q(name)} unique ({', '.join(q(c) for c in cols)})"
    if not adopted:
        return add
    return (f"do $mls$ begin\n"
            f"  if not exists (select 1 from pg_constraint where conrelid = {const_sql(q(table), 'text')}::regclass "
            f"and conname = {const_sql(name, 'text')}) then\n"
            f"    {add};\n"
            f"  end if;\n"
            f"end $mls$")


def table_ddl(name: str, t: Table) -> list[str]:
    cols = [column_ddl(c, col) for c, col in t.columns.items()]
    if t.primary_key:
        cols.append(f"constraint {q(pk_name(name))} primary key ({', '.join(q(c) for c in t.primary_key)})")
    for u in t.unique:
        cols.append(f"constraint {q(unique_name(name, u))} unique ({', '.join(q(c) for c in u)})")
    return [f"create table {q(name)} (\n  " + ",\n  ".join(cols) + "\n)"]
