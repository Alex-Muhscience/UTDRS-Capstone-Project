"""
Turns a detection rule's logic, as written in the dashboard, into conditions the core
engine runs.

The language is a list of comparisons joined by `and`, or by `or` (not both):

    process_name == 'powershell.exe' and command_line matches '(?i)-enc(odedcommand)?'
    event_type == 'authentication' and status in ['failed', 'locked'] and attempts >= 5

Comparisons: `==`, `!=`, `>`, `>=`, `<`, `<=`, `in [...]`, `not in [...]`,
`matches '<regex>'` (anywhere in the value), `contains`, `startswith`, `endswith`, and
`<field> exists`. Values are quoted strings, numbers, true, false, or lists of those.
A field is an event's `event_type`, `source` or `timestamp`, or anything in its data
(`process_name`, `user.name`, ...). A field that is missing never matches.

Logic the engine cannot run yet, such as counting events over a time window
(`| count by source_ip > 10 in 5m`), is kept in the catalogue but not run: compile()
raises RuleNotSupported saying why. Logic that is simply malformed raises
RuleSyntaxError, so it can be refused when it is saved.
"""
import re
from typing import Any, Dict, List, Tuple

TOP_LEVEL_FIELDS = {"event_type", "source", "timestamp"}

COMPARISONS = {
    "==": "eq", "!=": "ne", ">": "gt", ">=": "gte", "<": "lt", "<=": "lte",
    "in": "in", "not in": "not_in", "matches": "search", "contains": "contains",
    "startswith": "starts_with", "endswith": "ends_with",
}

TOKEN = re.compile(
    r"""\s*(?:
        (?P<string>'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*")
      | (?P<number>-?\d+(?:\.\d+)?(?![\w.]))
      | (?P<op>==|!=|>=|<=|>|<)
      | (?P<punct>[\[\],()|])
      | (?P<word>[A-Za-z_][\w.]*)
    )""",
    re.VERBOSE,
)


QUOTED = re.compile(r"'(?:[^'\\]|\\.)*'" + r'|"(?:[^"\\]|\\.)*"')
FUNCTION_CALL = re.compile(r"\b(?!(?i:and|or|not|in)\b)([A-Za-z_]\w*)\s*\(")


class RuleSyntaxError(ValueError):
    """The logic is malformed."""


class RuleNotSupported(ValueError):
    """The logic is valid but uses something the engine cannot run yet."""


def _tokens(logic: str) -> List[Tuple[str, Any]]:
    tokens, position = [], 0
    logic = logic.strip()
    while position < len(logic):
        match = TOKEN.match(logic, position)
        if not match or match.end() == position:
            raise RuleSyntaxError(f"Unexpected text at '{logic[position:position + 20]}'")
        position = match.end()
        kind = match.lastgroup
        text = match.group(kind)
        if kind == "string":
            tokens.append(("value", re.sub(r"\\(.)", r"\1", text[1:-1])))
        elif kind == "number":
            tokens.append(("value", float(text) if "." in text else int(text)))
        elif kind == "word" and text.lower() in ("true", "false"):
            tokens.append(("value", text.lower() == "true"))
        else:
            tokens.append((kind, text))
    return tokens


class _Parser:
    def __init__(self, tokens):
        self.tokens, self.i = tokens, 0

    def peek(self, offset=0):
        j = self.i + offset
        return self.tokens[j] if j < len(self.tokens) else (None, None)

    def take(self):
        token = self.peek()
        self.i += 1
        return token

    def value(self):
        kind, text = self.take()
        if kind == "value":
            return text
        if kind == "punct" and text == "[":
            items = []
            while self.peek() != ("punct", "]"):
                if items:
                    if self.take() != ("punct", ","):
                        raise RuleSyntaxError("Expected ',' between list items")
                kind, item = self.take()
                if kind != "value":
                    raise RuleSyntaxError("Lists may only hold quoted strings, numbers, true or false")
                items.append(item)
            self.take()
            return items
        if kind == "word":
            raise RuleNotSupported(
                f"Comparing with '{text}' is not supported yet; compare with quoted values or lists"
            )
        raise RuleSyntaxError(f"Expected a value, found '{text}'" if text else "Expected a value at the end")

    def comparison(self):
        kind, field = self.take()
        if kind != "word":
            if kind == "punct" and field == "(":
                raise RuleNotSupported("Parentheses are not supported yet; join comparisons with only 'and' or only 'or'")
            raise RuleSyntaxError(f"Expected a field name, found '{field}'" if field else "Expected a field name at the end")
        if self.peek() == ("punct", "("):
            raise RuleNotSupported(f"Functions such as '{field}(...)' are not supported yet")

        kind, op = self.take()
        if kind == "word" and op.lower() == "not" and self.peek()[1] == "in":
            self.take()
            op = "not in"
        elif kind == "word" and op.lower() == "exists":
            return field, "exists", True
        elif kind == "word":
            op = op.lower()
        if op not in COMPARISONS:
            raise RuleSyntaxError(f"Unknown comparison '{op}' after '{field}'" if op else f"Missing a comparison after '{field}'")

        value = self.value()
        if op in ("in", "not in") and not isinstance(value, list):
            raise RuleSyntaxError(f"'{op}' needs a list, such as ['a', 'b']")
        if op in (">", ">=", "<", "<=") and (isinstance(value, bool) or not isinstance(value, (int, float))):
            raise RuleSyntaxError(f"'{op}' needs a number")
        if op in ("matches", "contains", "startswith", "endswith") and not isinstance(value, str):
            raise RuleSyntaxError(f"'{op}' needs a quoted string")
        if op == "matches":
            try:
                re.compile(value)
            except re.error as e:
                raise RuleSyntaxError(f"Invalid regular expression '{value}': {e}")
        return field, COMPARISONS[op], value


def _engine_field(field: str) -> str:
    if field in TOP_LEVEL_FIELDS or field.startswith("data."):
        return field
    return f"data.{field}"


def compile_logic(logic: str) -> Dict[str, Any]:
    """The engine's `detection` for this logic. Raises RuleSyntaxError or RuleNotSupported."""
    # Features the engine does not have yet are recognised before parsing, outside
    # quoted strings (a regex may well contain '|' or '('), so such rules are kept.
    unquoted = QUOTED.sub("''", logic)
    if "|" in unquoted:
        raise RuleNotSupported(
            "Aggregations ('| count by ...', '| distinct ...') are not run by the engine yet"
        )
    function = FUNCTION_CALL.search(unquoted)
    if function:
        raise RuleNotSupported(f"Functions such as '{function.group(1)}(...)' are not supported yet")
    tokens = _tokens(logic)
    if not tokens:
        raise RuleSyntaxError("The logic is empty")

    parser = _Parser(tokens)
    conditions: Dict[str, Dict[str, Any]] = {}
    joiner = None
    while True:
        field, op, value = parser.comparison()
        engine_field = _engine_field(field)
        if op in conditions.setdefault(engine_field, {}):
            raise RuleNotSupported(f"'{field}' is compared the same way twice; combine the comparisons")
        conditions[engine_field][op] = value

        kind, word = parser.take()
        if kind is None:
            break
        if kind != "word" or word.lower() not in ("and", "or"):
            raise RuleSyntaxError(f"Expected 'and' or 'or', found '{word}'")
        if joiner and joiner != word.lower():
            raise RuleNotSupported("Mixing 'and' with 'or' is not supported yet")
        joiner = word.lower()

    if joiner == "or" and len(conditions) < len(_fields(tokens)):
        raise RuleNotSupported("Comparing one field several times with 'or' is not supported yet; use 'in [...]'")
    return {"condition_type": "OR" if joiner == "or" else "AND", "conditions": conditions}


def _fields(tokens) -> List[str]:
    """The field of every comparison, in order (used to spot a field repeated across 'or')."""
    fields, expect_field = [], True
    for kind, text in tokens:
        if expect_field and kind == "word":
            fields.append(text)
            expect_field = False
        elif kind == "word" and text.lower() in ("and", "or"):
            expect_field = True
    return fields


def engine_status(logic: str) -> Tuple[bool, str | None]:
    """Whether the engine can run this logic, and if not, why."""
    try:
        compile_logic(logic)
        return True, None
    except (RuleSyntaxError, RuleNotSupported) as e:
        return False, str(e)
