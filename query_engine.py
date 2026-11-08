# query_engine.py - Search the threat data with KQL, SPL, or SQL.
#
# How it works:
#   1. Every feed is loaded into an in-memory SQLite database (one table per feed).
#   2. KQL (Microsoft Sentinel) and SPL (Splunk) queries are translated into SQL.
#   3. The SQL runs on a read-only, sandboxed copy of the database.

import re
import sqlite3
import time

import pandas as pd

MAX_ROWS = 10_000   # most rows a query can return
TIME_LIMIT = 10     # seconds before a query is cancelled


class QueryError(Exception):
    """A problem with the user's query, shown to them as a friendly message."""


# =============================================================================
# Database
# =============================================================================
def build_database(tables):
    """Load each DataFrame into an in-memory SQLite database, one table per feed."""
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    for name, df in tables.items():
        if df is None or df.empty:
            continue
        clean = df.copy()
        for col in clean.columns:
            series = clean[col]
            if pd.api.types.is_datetime64_any_dtype(series):
                if series.dt.tz is not None:
                    series = series.dt.tz_convert("UTC").dt.tz_localize(None)
                only_dates = (series.dropna() == series.dropna().dt.normalize()).all()
                clean[col] = series.dt.strftime("%Y-%m-%d" if only_dates else "%Y-%m-%d %H:%M:%S")
            elif series.dtype == object:
                clean[col] = series.apply(lambda v: ", ".join(map(str, v)) if isinstance(v, (list, tuple)) else v)
        clean.to_sql(name, conn, index=False)
    return conn


def get_schema(conn):
    """Return {table: [(column, type), ...]} for the schema browser."""
    schema = {}
    for (table,) in conn.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"):
        schema[table] = [(row[1], row[2]) for row in conn.execute(f'PRAGMA table_info("{table}")')]
    return schema


ALLOWED_ACTIONS = {sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ, sqlite3.SQLITE_FUNCTION,
                   getattr(sqlite3, "SQLITE_RECURSIVE", 33)}


def sandbox_copy(master):
    """Make a private, read-only copy of the database for one query.
    Anything other than reading data (DROP, UPDATE, ATTACH, PRAGMA...) is blocked."""
    conn = sqlite3.connect(":memory:")
    master.backup(conn)
    conn.set_authorizer(lambda action, *args: sqlite3.SQLITE_OK if action in ALLOWED_ACTIONS else sqlite3.SQLITE_DENY)
    deadline = time.time() + TIME_LIMIT
    conn.set_progress_handler(lambda: 1 if time.time() > deadline else 0, 10_000)
    return conn


def run_query(master, language, query):
    """Translate (if needed) and run a query. Returns (results, sql, milliseconds)."""
    if not query.strip():
        raise QueryError("Type a query first.")
    conn = sandbox_copy(master)
    try:
        def columns_of(sql):
            cursor = conn.execute(f"SELECT * FROM ({sql}) LIMIT 0")
            return [d[0] for d in cursor.description]

        if language == "KQL":
            sql = translate_kql(query, columns_of)
        elif language == "SPL":
            sql = translate_spl(query, columns_of)
        else:
            sql = query.strip().rstrip(";").strip()
            if not re.match(r"(select|with)\b", sql, re.I):
                raise QueryError("Only SELECT queries are allowed. This console is read-only.")

        start = time.perf_counter()
        results = pd.read_sql_query(f"SELECT * FROM ({sql}) LIMIT {MAX_ROWS}", conn)
        ms = (time.perf_counter() - start) * 1000
        return results, sql, ms
    except QueryError:
        raise
    except Exception as error:
        raise QueryError(friendly_error(error)) from error
    finally:
        conn.close()


def friendly_error(error):
    msg = re.sub(r"^Execution failed on sql .*?': ", "", str(error), flags=re.S)
    msg = msg[:1].upper() + msg[1:]
    low = msg.lower()
    if "interrupted" in low:
        return f"The query took longer than {TIME_LIMIT} seconds and was cancelled."
    if "not authorized" in low:
        return "Only searches are allowed. This console is read-only."
    if "no such table" in low:
        return f"{msg}. Check the table list on the right."
    if "no such column" in low:
        return f"{msg}. Column names are listed on the right."
    return msg


# =============================================================================
# Tokenizer: breaks a query into pieces (strings, numbers, words, operators)
# =============================================================================
TOKEN_RE = re.compile(r"""
    (?P<str>"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')
  | (?P<span>\d+(?:\.\d+)?(?:ms|d|h|m|s)\b)
  | (?P<num>\d+(?:\.\d+)?)
  | (?P<ident>\[\s*['"][^\]]+['"]\s*\])
  | (?P<word>!?[A-Za-z_][\w.]*~?)
  | (?P<op>==|!=|<>|>=|<=|=~|!~|\.\.|[=<>(),*+/%-])
  | (?P<space>\s+)
""", re.VERBOSE)


def tokenize(text):
    tokens, pos = [], 0
    while pos < len(text):
        match = TOKEN_RE.match(text, pos)
        if not match:
            raise QueryError(f"Couldn't understand the query near: {text[pos:pos + 20]!r}")
        kind = match.lastgroup
        if kind != "space":
            tokens.append((kind, match.group()))
        pos = match.end()
    return tokens


def split_top(tokens, separator=","):
    """Split tokens on a separator, ignoring separators inside parentheses."""
    parts, current, depth = [], [], 0
    for tok in tokens:
        if tok[1] == "(":
            depth += 1
        elif tok[1] == ")":
            depth -= 1
        if depth == 0 and tok[1].lower() == separator:
            parts.append(current)
            current = []
        else:
            current.append(tok)
    if current:
        parts.append(current)
    return parts


def split_pipes(query):
    """Split a query on | characters, ignoring any inside quotes. Removes // comments."""
    parts, current, quote, i = [], "", None, 0
    while i < len(query):
        ch = query[i]
        if quote:
            current += ch
            if ch == "\\" and i + 1 < len(query):
                current += query[i + 1]
                i += 1
            elif ch == quote:
                quote = None
        elif ch in "\"'":
            quote = ch
            current += ch
        elif query.startswith("//", i):
            while i < len(query) and query[i] != "\n":
                i += 1
            continue
        elif ch == "|":
            parts.append(current.strip())
            current = ""
        else:
            current += ch
        i += 1
    parts.append(current.strip())
    return [p for p in parts if p]


def q(name):
    """Quote a column or table name for SQL."""
    return '"' + str(name).replace('"', '""') + '"'


def sql_string(value):
    return "'" + value.replace("'", "''") + "'"


def unquote(token_value):
    body = token_value[1:-1]
    return re.sub(r"\\(.)", r"\1", body)


# =============================================================================
# Expressions: turns KQL/SPL conditions and functions into SQL
# =============================================================================
SPAN_UNITS = {"d": "days", "h": "hours", "m": "minutes", "s": "seconds"}


def span_parts(span):
    match = re.match(r"(\d+(?:\.\d+)?)(ms|d|h|m|s)$", span)
    if not match:
        raise QueryError(f"Expected a time span like 7d or 24h, got {span!r}")
    return match.group(1), match.group(2)


def fn_ago(args):
    amount, unit = span_parts(args[0].removeprefix("@span:"))
    return f"datetime('now', '-{amount} {SPAN_UNITS.get(unit, 'seconds')}')"


def fn_bin(args):
    col = args[0]
    _, unit = span_parts(args[1].removeprefix("@span:")) if len(args) > 1 else ("1", "d")
    formats = {"d": "%Y-%m-%d", "h": "%Y-%m-%d %H:00:00", "m": "%Y-%m-%d %H:%M:00"}
    return f"strftime('{formats.get(unit, '%Y-%m-%d')}', {col})"


FUNCTIONS = {
    "count": lambda a: f"COUNT({a[0]})" if a and a[0] else "COUNT(*)",
    "dcount": lambda a: f"COUNT(DISTINCT {a[0]})",
    "dc": lambda a: f"COUNT(DISTINCT {a[0]})",
    "distinct_count": lambda a: f"COUNT(DISTINCT {a[0]})",
    "countif": lambda a: f"SUM(CASE WHEN {a[0]} THEN 1 ELSE 0 END)",
    "sum": lambda a: f"SUM({a[0]})",
    "avg": lambda a: f"AVG({a[0]})",
    "mean": lambda a: f"AVG({a[0]})",
    "min": lambda a: f"MIN({a[0]})",
    "max": lambda a: f"MAX({a[0]})",
    "make_set": lambda a: f"GROUP_CONCAT(DISTINCT {a[0]})",
    "values": lambda a: f"GROUP_CONCAT(DISTINCT {a[0]})",
    "make_list": lambda a: f"GROUP_CONCAT({a[0]})",
    "list": lambda a: f"GROUP_CONCAT({a[0]})",
    "ago": fn_ago,
    "now": lambda a: "datetime('now')",
    "bin": fn_bin,
    "datetime": lambda a: a[0],
    "isempty": lambda a: f"({a[0]} IS NULL OR {a[0]} = '')",
    "isnotempty": lambda a: f"({a[0]} IS NOT NULL AND {a[0]} <> '')",
    "isnull": lambda a: f"({a[0]} IS NULL)",
    "isnotnull": lambda a: f"({a[0]} IS NOT NULL)",
    "tolower": lambda a: f"lower({a[0]})",
    "toupper": lambda a: f"upper({a[0]})",
    "strlen": lambda a: f"length({a[0]})",
    "len": lambda a: f"length({a[0]})",
    "tostring": lambda a: f"CAST({a[0]} AS TEXT)",
    "toint": lambda a: f"CAST({a[0]} AS INTEGER)",
    "tonumber": lambda a: f"CAST({a[0]} AS REAL)",
    "todouble": lambda a: f"CAST({a[0]} AS REAL)",
    "like": lambda a: f"{a[0]} LIKE {a[1]}",
}

LIKE_OPERATORS = {  # KQL string operator -> (NOT?, pattern template)
    "contains": ("", "%{}%"), "has": ("", "%{}%"), "contains_cs": ("", "%{}%"), "has_cs": ("", "%{}%"),
    "!contains": ("NOT ", "%{}%"), "!has": ("NOT ", "%{}%"),
    "startswith": ("", "{}%"), "!startswith": ("NOT ", "{}%"),
    "endswith": ("", "%{}"), "!endswith": ("NOT ", "%{}"),
}


NOT_FUNCTIONS = {"in", "!in", "in~", "!in~", "between", "!between", "and", "or"}
# Column names that are also SQL keywords get quoted, e.g. a column called "group"
SQL_RESERVED = {"group", "order", "select", "from", "where", "limit", "table", "index", "key", "values", "default",
                "check", "union", "join", "on", "having", "offset", "all", "exists", "primary", "references", "to",
                "into", "set", "update", "delete", "insert", "create", "drop", "transaction", "column", "row"}


def join_sql(parts):
    text = " ".join(parts)
    text = re.sub(r"\(\s+", "(", text)
    text = re.sub(r"\s+\)", ")", text)
    return re.sub(r"\s+,", ",", text)


def take_group(tokens, i):
    """tokens[i] is '('. Return (tokens inside the parentheses, index after ')')."""
    depth, j = 0, i
    while j < len(tokens):
        if tokens[j][1] == "(":
            depth += 1
        elif tokens[j][1] == ")":
            depth -= 1
            if depth == 0:
                return tokens[i + 1:j], j + 1
        j += 1
    raise QueryError("Missing a closing parenthesis.")


def convert(tokens):
    """Translate a KQL/SPL expression (as tokens) into a SQL expression."""
    out, i = [], 0
    while i < len(tokens):
        kind, value = tokens[i]
        low = value.lower()
        nxt = tokens[i + 1] if i + 1 < len(tokens) else None

        if kind == "word" and nxt and nxt[1] == "(" and low not in NOT_FUNCTIONS:   # function call
            inner, i = take_group(tokens, i + 1)
            args = [convert(arg) for arg in split_top(inner)] if inner else []
            if low in FUNCTIONS:
                out.append(FUNCTIONS[low](args))
            else:
                out.append(f"{value}({', '.join(args)})")
            continue
        if kind == "word" and low in LIKE_OPERATORS:                # contains, startswith...
            negate, pattern = LIKE_OPERATORS[low]
            if not nxt:
                raise QueryError(f"'{value}' needs a value after it.")
            if nxt[0] == "str":
                out.append(f"{negate}LIKE {sql_string(pattern.format(unquote(nxt[1])))}")
            else:
                pieces = pattern.split("{}")
                out.append(f"{negate}LIKE {sql_string(pieces[0])} || {convert([nxt])} || {sql_string(pieces[1])}")
            i += 2
            continue
        if kind == "word" and low in ("between", "!between") and nxt and nxt[1] == "(":
            inner, i = take_group(tokens, i + 1)
            bounds = split_top(inner, "..")
            if len(bounds) != 2:
                raise QueryError("Use between like this: score between (5 .. 10)")
            negate = "NOT " if low.startswith("!") else ""
            out.append(f"{negate}BETWEEN {convert(bounds[0])} AND {convert(bounds[1])}")
            continue

        if kind == "str":
            out.append(sql_string(unquote(value)))
        elif kind == "span":
            out.append(f"@span:{value}")
        elif kind == "ident":
            out.append(q(value.strip("[] ")[1:-1]))
        elif value == "==":
            out.append("=")
        elif value == "=~":
            out.append("LIKE")
        elif value == "!~":
            out.append("NOT LIKE")
        elif low in ("and", "or", "not", "in", "is", "null", "like"):
            out.append(low.upper())
        elif low in ("!in", "!in~"):
            out.append("NOT IN")
        elif low == "in~":
            out.append("IN")
        elif kind == "word" and low in SQL_RESERVED:
            out.append(q(value))
        elif low == "true":
            out.append("1")
        elif low == "false":
            out.append("0")
        else:
            out.append(value)
        i += 1
    return join_sql(out)


def split_alias(tokens, style):
    """KQL:  Name = expr     SPL:  expr as Name     Returns (expr_tokens, alias or None)."""
    if style == "kql" and len(tokens) > 2 and tokens[0][0] == "word" and tokens[1][1] == "=":
        return tokens[2:], tokens[0][1]
    if style == "spl" and len(tokens) > 2 and tokens[-2][1].lower() == "as":
        return tokens[:-2], tokens[-1][1].strip("\"'")
    return tokens, None


def default_name(tokens, style):
    """Column name KQL/SPL would give an unnamed aggregation, e.g. count() -> count_."""
    if len(tokens) == 1:
        return tokens[0][1]
    func = tokens[0][1].lower()
    inner = [t[1] for t in tokens[2:-1]] if len(tokens) > 2 else []
    if style == "spl":
        return func if not inner else f"{func}({''.join(inner)})"
    if func == "bin" and inner:
        return inner[0]
    return f"{func}_" + "".join(inner).replace(" ", "")


def wrap(prev, select="*", where="", group="", order="", limit=""):
    sql = f"SELECT {select} FROM ({prev})"
    for clause, keyword in ((where, "WHERE"), (group, "GROUP BY"), (order, "ORDER BY"), (limit, "LIMIT")):
        if clause:
            sql += f" {keyword} {clause}"
    return sql


def aggregate(prev, agg_items, by_items, style):
    """Shared by KQL summarize and SPL stats."""
    select, group = [], []
    for item in by_items:
        expr, alias = split_alias(item, style)
        sql = convert(expr)
        name = alias or default_name(expr, style)
        select.append(f"{sql} AS {q(name)}")
        group.append(sql)
    for item in agg_items:
        expr, alias = split_alias(item, style)
        if style == "spl" and len(expr) == 1 and expr[0][1].lower() == "count":
            expr = [("word", "count"), ("op", "("), ("op", ")")]
            alias = alias or "count"
        select.append(f"{convert(expr)} AS {q(alias or default_name(expr, style))}")
    return wrap(prev, ", ".join(select), group=", ".join(group))


# =============================================================================
# KQL (Microsoft Sentinel / Azure Data Explorer)
# =============================================================================
KQL_OPERATORS = "where, project, project-away, project-rename, extend, summarize, sort by, order by, top, take, limit, distinct, count"


def translate_kql(query, columns_of):
    stages = split_pipes(query)
    table = stages[0].strip()
    if not re.fullmatch(r"[A-Za-z_]\w*", table):
        raise QueryError("A KQL query starts with a table name, like: kev | take 10")
    sql = f"SELECT * FROM {q(table)}"

    for stage in stages[1:]:
        match = re.match(r"(project-away|project-rename|[a-z]+)\s*(.*)", stage, re.S | re.I)
        op, rest = match.group(1).lower(), match.group(2)
        tokens = tokenize(rest)

        if op in ("where", "filter"):
            sql = wrap(sql, where=convert(tokens))
        elif op == "project":
            cols = []
            for item in split_top(tokens):
                expr, alias = split_alias(item, "kql")
                cols.append(convert(expr) + (f" AS {q(alias)}" if alias else ""))
            sql = wrap(sql, ", ".join(cols))
        elif op == "project-away":
            drop = {t[1].lower() for t in tokens if t[0] == "word"}
            sql = wrap(sql, ", ".join(q(c) for c in columns_of(sql) if c.lower() not in drop))
        elif op == "project-rename":
            renames = {}
            for item in split_top(tokens):
                expr, alias = split_alias(item, "kql")
                renames[convert(expr).lower()] = alias
            sql = wrap(sql, ", ".join(f"{q(c)} AS {q(renames.get(c.lower(), c))}" for c in columns_of(sql)))
        elif op == "extend":
            cols = ["*"]
            for item in split_top(tokens):
                expr, alias = split_alias(item, "kql")
                cols.append(f"{convert(expr)} AS {q(alias or default_name(expr, 'kql'))}")
            sql = wrap(sql, ", ".join(cols))
        elif op == "summarize":
            parts = split_top(tokens, "by")
            agg_part = parts[0] if tokens and tokens[0][1].lower() != "by" else []
            by_part = parts[-1] if any(t[1].lower() == "by" for t in tokens) else []
            sql = aggregate(sql, split_top(agg_part), split_top(by_part), "kql")
        elif op in ("sort", "order"):
            if tokens and tokens[0][1].lower() == "by":
                tokens = tokens[1:]
            sql = wrap(sql, order=kql_order(tokens))
        elif op == "top":
            if len(tokens) < 3 or tokens[0][0] != "num" or tokens[1][1].lower() != "by":
                raise QueryError("Use top like this: top 10 by score desc")
            sql = wrap(sql, order=kql_order(tokens[2:]), limit=tokens[0][1])
        elif op in ("take", "limit"):
            if not tokens or tokens[0][0] != "num":
                raise QueryError(f"Use {op} like this: {op} 10")
            sql = wrap(sql, limit=tokens[0][1])
        elif op == "distinct":
            sql = wrap(sql, "DISTINCT " + ", ".join(convert(item) for item in split_top(tokens)))
        elif op == "count":
            sql = wrap(sql, "COUNT(*) AS Count")
        else:
            raise QueryError(f"'{op}' isn't supported yet. Supported KQL operators: {KQL_OPERATORS}.")
    return sql


def kql_order(tokens):
    parts = []
    for item in split_top(tokens):
        direction = "DESC"  # KQL sorts descending by default
        if item and item[-1][1].lower() in ("asc", "desc"):
            direction = item[-1][1].upper()
            item = item[:-1]
        parts.append(f"{convert(item)} {direction}")
    return ", ".join(parts)


# =============================================================================
# SPL (Splunk)
# =============================================================================
SPL_COMMANDS = "search, where, stats, table, fields, rename, eval, sort, head, dedup, top, rare"

SPL_TERM = re.compile(r"""\s*(
    \(|\)
  | (?:NOT|OR|AND)(?=[\s(]|$)
  | [\w.]+\s*(?:!=|>=|<=|=|>|<)\s*(?:"(?:[^"\\]|\\.)*"|[^\s()]+)
  | "(?:[^"\\]|\\.)*"
  | [^\s()]+
)""", re.VERBOSE)
SPL_FIELD = re.compile(r"""([\w.]+)\s*(!=|>=|<=|=|>|<)\s*(.+)""", re.S)


def spl_value(op, raw):
    is_quoted = raw.startswith('"')
    value = unquote(raw) if is_quoted else raw
    if not is_quoted and re.fullmatch(r"-?\d+(?:\.\d+)?", value):
        return f"{'=' if op == '=' else op} {value}"
    if "*" in value and op in ("=", "!="):
        return f"{'NOT ' if op == '!=' else ''}LIKE {sql_string(value.replace('*', '%'))}"
    return f"{op} {sql_string(value)} COLLATE NOCASE"


def spl_search(text, all_columns):
    """Translate Splunk search terms. Returns (index_name or None, SQL condition or '')."""
    index, parts, need_join = None, [], False
    for match in SPL_TERM.finditer(text):
        term = match.group(1)
        upper = term.upper()
        if term == "(":
            parts.append(("AND " if need_join else "") + "(")
            need_join = False
            continue
        if term == ")":
            parts.append(")")
            need_join = True
            continue
        if upper in ("OR", "AND"):
            parts.append(upper)
            need_join = False
            continue
        if upper == "NOT":
            parts.append(("AND " if need_join else "") + "NOT")
            need_join = False
            continue

        field = SPL_FIELD.fullmatch(term) if not term.startswith('"') else None
        if field and field.group(1).lower() in ("index", "sourcetype", "source"):
            index = unquote(field.group(3)) if field.group(3).startswith('"') else field.group(3)
            continue
        if field:
            name = q(field.group(1)) if field.group(1).lower() in SQL_RESERVED else field.group(1)
            condition = f"{name} {spl_value(field.group(2), field.group(3))}"
        else:                                  # free text: search every column
            word = unquote(term) if term.startswith('"') else term
            if word == "*":
                continue
            haystack = " || ' ' || ".join(f"COALESCE(CAST({q(c)} AS TEXT), '')" for c in all_columns) or "''"
            condition = f"({haystack}) LIKE {sql_string('%' + word.replace('*', '%') + '%')}"
        parts.append(("AND " if need_join else "") + condition)
        need_join = True
    return index, " ".join(parts)


def spl_field_list(tokens):
    return [t[1].strip("\"'") for t in tokens if t[0] in ("word", "str")]


def translate_spl(query, columns_of):
    stages = split_pipes(query)
    first = re.sub(r"^search\s+", "", stages[0], flags=re.I)
    index, _ = spl_search(first, [])
    if not index or not re.fullmatch(r"[A-Za-z_]\w*", index):
        raise QueryError("An SPL query starts with an index, like: index=kev | head 10")
    sql = f"SELECT * FROM {q(index)}"
    _, condition = spl_search(first, columns_of(sql))
    if condition:
        sql = wrap(sql, where=condition)

    for stage in stages[1:]:
        match = re.match(r"([a-z]+)\s*(.*)", stage, re.S | re.I)
        cmd, rest = match.group(1).lower(), match.group(2)

        if cmd == "search":
            _, condition = spl_search(rest, columns_of(sql))
            if condition:
                sql = wrap(sql, where=condition)
            continue

        tokens = tokenize(rest)
        if cmd == "where":
            sql = wrap(sql, where=convert(tokens))
        elif cmd == "stats":
            if any(t[1].lower() == "by" for t in tokens):
                cut = next(i for i, t in enumerate(tokens) if t[1].lower() == "by")
                agg_tokens, by_tokens = tokens[:cut], tokens[cut + 1:]
            else:
                agg_tokens, by_tokens = tokens, []
            aggs = spl_agg_items(agg_tokens)
            by_items = [[t] for t in by_tokens if t[1] != ","]
            sql = aggregate(sql, aggs, by_items, "spl")
        elif cmd in ("table", "fields"):
            if tokens and tokens[0][1] == "-":
                drop = {f.lower() for f in spl_field_list(tokens[1:])}
                sql = wrap(sql, ", ".join(q(c) for c in columns_of(sql) if c.lower() not in drop))
            else:
                sql = wrap(sql, ", ".join(q(f) for f in spl_field_list(tokens)))
        elif cmd == "rename":
            renames, items = {}, split_top(tokens)
            for item in items:
                if len(item) == 3 and item[1][1].lower() == "as":
                    renames[item[0][1].lower()] = item[2][1].strip("\"'")
            sql = wrap(sql, ", ".join(f"{q(c)} AS {q(renames.get(c.lower(), c))}" for c in columns_of(sql)))
        elif cmd == "eval":
            cols = ["*"]
            for item in split_top(tokens):
                expr, alias = split_alias(item, "kql")  # eval uses name = expr, like KQL
                cols.append(f"{convert(expr)} AS {q(alias or 'eval')}")
            sql = wrap(sql, ", ".join(cols))
        elif cmd == "sort":
            limit = ""
            if tokens and tokens[0][0] == "num":
                limit, tokens = tokens[0][1], tokens[1:]
            order, direction = [], "ASC"
            for tok in tokens:
                if tok[1] in ("-", "+"):
                    direction = "DESC" if tok[1] == "-" else "ASC"
                elif tok[1] != ",":
                    order.append(f"{q(tok[1].strip(chr(34)))} {direction}")
                    direction = "ASC"
            sql = wrap(sql, order=", ".join(order), limit=limit)
        elif cmd == "head":
            sql = wrap(sql, limit=tokens[0][1] if tokens and tokens[0][0] == "num" else "10")
        elif cmd == "dedup":
            fields = spl_field_list(tokens)
            sql = wrap(sql, group=", ".join(q(f) for f in fields))
        elif cmd in ("top", "rare"):
            limit = "10"
            if len(tokens) >= 3 and tokens[0][1].lower() == "limit" and tokens[1][1] == "=":
                limit, tokens = tokens[2][1], tokens[3:]
            fields = ", ".join(q(f) for f in spl_field_list(tokens))
            total = f"(SELECT COUNT(*) FROM ({sql}))"
            sql = wrap(sql, f"{fields}, COUNT(*) AS count, ROUND(100.0 * COUNT(*) / {total}, 2) AS percent",
                       group=fields, order=f"count {'DESC' if cmd == 'top' else 'ASC'}", limit=limit)
        else:
            raise QueryError(f"'{cmd}' isn't supported yet. Supported SPL commands: {SPL_COMMANDS}.")
    return sql


def spl_agg_items(tokens):
    """Split 'count dc(ip) as unique, avg(score)' into separate aggregation items."""
    items, i = [], 0
    while i < len(tokens):
        if tokens[i][1] == ",":
            i += 1
            continue
        item = [tokens[i]]
        i += 1
        if i < len(tokens) and tokens[i][1] == "(":
            inner, end = take_group(tokens, i)
            item += [("op", "(")] + inner + [("op", ")")]
            i = end
        if i + 1 < len(tokens) and tokens[i][1].lower() == "as":
            item += tokens[i:i + 2]
            i += 2
        items.append(item)
    return items


# =============================================================================
# Example queries for the search page
# =============================================================================
EXAMPLES = {
    "KQL": {
        "Ransomware CVEs by vendor": 'kev\n| where knownRansomwareCampaignUse == "Known"\n| summarize CVEs = count() by vendorProject\n| top 10 by CVEs',
        "CVEs added in the last 30 days": "kev\n| where dateAdded > ago(30d)\n| project cveID, vendorProject, product, dateAdded\n| sort by dateAdded desc",
        "Worst malicious IPs": "malicious_ips\n| where score >= 8\n| top 20 by score desc",
        "SSH brute-forcers also on other lists": 'ip_intel\n| where tags contains "SSH" and score >= 3\n| project ip, tags, score, risk\n| top 25 by risk',
        "Malicious IPs by type": "ip_intel\n| summarize IPs = count() by group\n| sort by IPs desc",
        "Malicious IPs by country": "ip_intel\n| where group != \"Tor exit\"\n| summarize IPs = count() by country\n| top 20 by IPs",
        "What Russian IPs are doing": 'ip_intel\n| where country == "RU"\n| summarize IPs = count() by group\n| sort by IPs desc',
        "Attackers from Africa": 'ip_intel\n| where country in ("NG", "ZA", "EG", "KE", "MA", "GH", "DZ", "TN", "SC", "MU")\n| summarize IPs = count() by country, group\n| sort by IPs desc',
        "Ransomware gangs this week": "ransomware_victims\n| where discovered > ago(7d)\n| summarize Victims = count() by gang\n| top 10 by Victims",
        "Exploited CVEs most likely to be used next": "kev\n| where epss >= 0.9\n| project cveID, vendorProject, product, epss, dateAdded\n| top 25 by epss desc",
        "Botnet servers by malware": "botnet_c2\n| summarize Servers = count() by malware\n| sort by Servers desc",
        "Microsoft CVEs mentioning remote code": 'kev\n| where vendorProject == "Microsoft" and vulnerabilityName contains "remote code"\n| project cveID, product, dateAdded',
        "Honeypot: top attackers": "honeypot\n| summarize Attempts = count() by ip\n| top 10 by Attempts",
        "Honeypot: attempts per hour": "honeypot\n| summarize Attempts = count() by bin(time, 1h)\n| sort by time asc",
    },
    "SPL": {
        "Ransomware CVEs by vendor": 'index=kev knownRansomwareCampaignUse="Known"\n| stats count by vendorProject\n| sort -count\n| head 10',
        "Microsoft CVEs": 'index=kev vendorProject="Microsoft"\n| table cveID product vulnerabilityName dateAdded\n| sort -dateAdded',
        "Worst malicious IPs": "index=malicious_ips score>=8\n| sort -score\n| head 20",
        "Top botnet malware": "index=botnet_c2\n| top limit=5 malware",
        "Attack types from blocklist.de": "index=attack_reports\n| stats count by attack_type\n| sort -count",
        "Tor exits with abuse reports": "index=ip_intel tags=*Tor* score>=3\n| table ip tags score\n| sort -score",
        "Ransomware victims by sector": "index=ransomware_victims\n| stats count by sector\n| sort -count\n| head 10",
        "Biggest breaches with passwords": "index=data_breaches data_exposed=*Passwords*\n| sort -accounts\n| table breach domain accounts breach_date\n| head 15",
        "Free-text search": 'index=kev "remote code execution"\n| table cveID vendorProject product',
        "Honeypot: top attackers": "index=honeypot\n| stats count as attempts by ip\n| sort -attempts\n| head 10",
    },
    "SQL": {
        "Ransomware CVEs by vendor": "SELECT vendorProject, COUNT(*) AS cves\nFROM kev\nWHERE knownRansomwareCampaignUse = 'Known'\nGROUP BY vendorProject\nORDER BY cves DESC\nLIMIT 10;",
        "IPs by blocklist score": "SELECT score, COUNT(*) AS ips\nFROM malicious_ips\nGROUP BY score\nORDER BY score DESC;",
        "US ransomware victims in healthcare or education": "SELECT victim, gang, sector, discovered\nFROM ransomware_victims\nWHERE country = 'US' AND (sector LIKE '%health%' OR sector LIKE '%educat%')\nORDER BY discovered DESC;",
        "IPs seen doing several kinds of attacks": "SELECT ip, attack_types, tags, score\nFROM ip_intel\nWHERE attack_types >= 3\nORDER BY risk DESC\nLIMIT 25;",
        "Botnet servers that are also on blocklists": "SELECT b.ip_address, b.malware, b.country, m.score\nFROM botnet_c2 b\nJOIN malicious_ips m ON m.ip = b.ip_address\nORDER BY m.score DESC;",
        "Honeypot attackers already on blocklists": "SELECT h.ip, COUNT(*) AS attempts, MAX(m.score) AS blocklist_score\nFROM honeypot h\nLEFT JOIN malicious_ips m ON m.ip = h.ip\nGROUP BY h.ip\nORDER BY attempts DESC\nLIMIT 20;",
    },
}
