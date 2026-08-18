"""SQLite's rowid-alias autoincrement only kicks in for a column declared as exactly
`INTEGER PRIMARY KEY`, not `BIGINT` — so a bare BigInteger PK silently fails to
autoincrement under the SQLite dev/test database. BigIntPK renders as BIGINT on
Postgres (production) and INTEGER on SQLite (dev/test), autoincrementing on both.
"""
from sqlalchemy import BigInteger, Integer

BigIntPK = BigInteger().with_variant(Integer, "sqlite")
