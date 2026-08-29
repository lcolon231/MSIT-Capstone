"""Named predicate registry — the vetted, pure functions policy YAML may reference by name.

This is how the monitor stays argument-aware while keeping policy as *data* (D2): the YAML
names a predicate; the code that decides is here, version-controlled and red-teamable, never
authored by the agent or inlined in policy. The loader validates that every `Check.predicate`
resolves in `REGISTRY` (fail-closed at load time).

Matchers must be anchored / canonicalizing to resist the parameter-abuse classes in
qa-redteam-plan.md T3.2 (encoding evasion, path traversal, look-alike domains).
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from typing import Any, Callable, Mapping

from src.monitor.types import ToolCall

# A predicate takes the enriched call plus its YAML params and returns a plain bool. Pure.
Predicate = Callable[[ToolCall, Mapping[str, Any]], bool]

REGISTRY: dict[str, Predicate] = {}


def register(name: str) -> Callable[[Predicate], Predicate]:
    """Decorator to add a predicate to REGISTRY under `name`.

    Minimal real infrastructure (not verdict logic): it must run at import so the registry is
    populated and the loader can validate `Check.predicate` references. The predicate *bodies*
    remain NotImplementedError until Phase 2.
    """

    def _decorator(fn: Predicate) -> Predicate:
        REGISTRY[name] = fn
        return fn

    return _decorator


def resolve(name: str) -> Predicate:
    """Return the predicate registered under `name`, or raise KeyError (the loader turns this
    into a clear, fail-closed load error)."""
    return REGISTRY[name]


# --- Per-call argument-aware predicates (criterion #3) -----------------------------------


@register("arg_equals")
def arg_equals(call: ToolCall, params: Mapping[str, Any]) -> bool:
    """True iff the named argument equals an expected value.

    params: ``{"arg": <name>, "value": <expected>}``. A missing argument compares unequal.
    """
    return bool(call.args.get(params["arg"]) == params["value"])


@register("arg_matches")
def arg_matches(call: ToolCall, params: Mapping[str, Any]) -> bool:
    """True iff the named string argument FULL-matches ``params['pattern']``.

    ``re.fullmatch`` anchors both ends implicitly, so even a pattern that forgets ``^``/``$``
    cannot be satisfied by a look-alike trailing domain such as
    ``attacker@example.com.evil.com`` (qa-redteam-plan.md T3.2). A non-string argument is
    never a match (fail closed).
    """
    value = call.args.get(params["arg"])
    if not isinstance(value, str):
        return False
    return re.fullmatch(params["pattern"], value) is not None


# Common Cyrillic/Greek homoglyphs mapped to their Latin look-alikes so that, e.g., a Cyrillic
# "м" cannot smuggle "rm" past the denylist. NFKC handles compatibility forms; this handles
# cross-script confusables NFKC leaves alone.
_CONFUSABLES = str.maketrans(
    {
        "а": "a",
        "в": "b",
        "с": "c",
        "ԁ": "d",
        "е": "e",
        "ɡ": "g",
        "н": "h",
        "і": "i",
        "ј": "j",
        "к": "k",
        "м": "m",
        "о": "o",
        "р": "p",
        "ѕ": "s",
        "т": "t",
        "у": "y",
        "х": "x",
        "α": "a",
        "ϲ": "c",
        "ο": "o",
        "ρ": "p",
        "τ": "t",
        "ν": "v",
    }
)

# Non-``rm`` destructive command shapes, matched against the canonical form.
_DESTRUCTIVE_PATTERNS = (
    re.compile(r"\bmkfs\b"),
    re.compile(r"\bdd\b[^|]*\bof=/dev/"),
    re.compile(r":\s*\(\s*\)\s*\{.*:\s*\|\s*:.*\}\s*;\s*:"),  # fork bomb :(){ :|:& };:
    re.compile(r"\bchmod\b[^|]*-[a-z]*r[a-z]*\s+777\s+/"),
    re.compile(r"\b(?:curl|wget|base64)\b[^|]*\|\s*(?:sh|bash)\b"),  # pipe-to-shell
    re.compile(r">\s*/dev/sd"),
)

_DANGEROUS_RM_TARGETS = {"/", "~", "*", "/*", "$home", "."}


def _decode_base64_fragments(text: str) -> str:
    """Return `text` plus the decoded content of any embedded base64 blobs, so a payload like
    ``echo cm0gLXJmIC8= | base64 -d | sh`` is scanned in its decoded form too."""
    extra: list[str] = []
    for token in re.findall(r"[A-Za-z0-9+/]{8,}={0,2}", text):
        try:
            decoded = base64.b64decode(token, validate=True).decode("utf-8", "ignore")
        except (binascii.Error, ValueError):
            continue
        if decoded.isprintable():
            extra.append(decoded)
    return text + " " + " ".join(extra) if extra else text


def _canonicalize(command: str) -> str:
    """Collapse the encoding-evasion classes (T3.2) into one comparable form: NFKC + confusables
    + base64 decode + ${IFS}/quote/backslash token-splitting + whitespace + case folding."""
    s = unicodedata.normalize("NFKC", command)
    s = s.translate(_CONFUSABLES)
    s = _decode_base64_fragments(s)
    s = s.lower()
    s = re.sub(r"\$\{ifs[^}]*\}", " ", s)  # ${IFS}, ${IFS%??}
    s = s.replace("$ifs", " ")
    s = s.replace('""', "").replace("''", "")  # empty-quote splitting: r''m -> rm
    s = s.replace("\\", "")  # backslash splitting: r\m -> rm
    s = s.replace('"', "").replace("'", "")
    return re.sub(r"\s+", " ", s).strip()


def _rm_is_destructive(tokens: list[str]) -> bool:
    """True iff an ``rm`` invocation combines recursive AND force with a dangerous target."""
    if "rm" not in tokens:
        return False
    short: set[str] = set()
    longflags: set[str] = set()
    targets: list[str] = []
    for token in tokens:
        if token == "rm":
            continue
        if token.startswith("--"):
            longflags.add(token[2:])
        elif token.startswith("-") and len(token) > 1:
            short.update(token[1:])
        else:
            targets.append(token)
    recursive = "r" in short or "recursive" in longflags
    force = "f" in short or "force" in longflags
    if not (recursive and force):
        return False
    return any(t in _DANGEROUS_RM_TARGETS or re.fullmatch(r"/[a-z]*", t) for t in targets)


@register("is_destructive_cmd")
def is_destructive_cmd(call: ToolCall, params: Mapping[str, Any]) -> bool:
    """True for a destructive shell command after canonicalization (decode ${IFS}, base64,
    unicode homoglyphs) — e.g. `rm -rf /`. `shell("ls")` is False.

    params: ``{"arg": <name>}`` (defaults to ``"command"``).
    """
    raw = call.args.get(params.get("arg", "command"))
    if not isinstance(raw, str):
        return False
    canonical = _canonicalize(raw)
    tokens = canonical.split(" ")
    if _rm_is_destructive(tokens):
        return True
    return any(pattern.search(canonical) for pattern in _DESTRUCTIVE_PATTERNS)


@register("target_is_bound_value")
def target_is_bound_value(call: ToolCall, params: Mapping[str, Any]) -> bool:
    """Sequence predicate: True iff a named argument's canonical digest equals a value bound
    earlier in the chain (e.g. `export_records.to` == the just-registered destination — the
    terminal kill-chain transition, docs/design/sequence-engine.md §5). The binding-aware
    evaluation lives in the sequence engine, which supplies the captured digests."""
    raise NotImplementedError
