"""Language-agnostic public contract extraction via tree-sitter.

Parses the *new* version of each changed file and reports public declarations
(functions, methods, classes, types, properties...) whose signature touches a
line added in the diff. Multi-line signatures, class methods and Go receivers
are handled by the parser instead of line regexes.

When a parser or grammar is unavailable the caller falls back to the legacy
regex and must flag the result as partial: nothing is dropped silently.
"""
from __future__ import annotations

import os
import re

# Extension -> tree-sitter-language-pack grammar name.
EXT_LANG: dict[str, str] = {
    ".py": "python", ".pyi": "python",
    ".gd": "gdscript",
    ".ts": "typescript", ".mts": "typescript", ".cts": "typescript",
    ".tsx": "tsx",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".go": "go",
    ".java": "java",
    ".kt": "kotlin", ".kts": "kotlin",
    ".cs": "csharp",
    ".rs": "rust",
    ".php": "php",
    ".rb": "ruby",
    ".swift": "swift",
    ".c": "c", ".h": "c",
    ".cpp": "cpp", ".cc": "cpp", ".cxx": "cpp", ".hpp": "cpp", ".hh": "cpp",
}

CODE_EXTS: tuple[str, ...] = tuple(EXT_LANG)

_JS_LIKE = ("typescript", "tsx", "javascript")

# Declaration node types reported as contracts, per grammar.
_DECLS: dict[str, set[str]] = {
    "python": {"function_definition", "class_definition"},
    "gdscript": {"function_definition", "signal_statement", "const_statement", "variable_statement", "class_definition"},
    "typescript": {"function_declaration", "class_declaration", "abstract_class_declaration", "interface_declaration",
                   "type_alias_declaration", "enum_declaration", "method_definition", "abstract_method_signature",
                   "variable_declarator", "public_field_definition"},
    "go": {"function_declaration", "method_declaration", "type_spec"},
    "java": {"class_declaration", "interface_declaration", "enum_declaration", "record_declaration",
             "method_declaration", "constructor_declaration"},
    "kotlin": {"class_declaration", "object_declaration", "function_declaration"},
    "csharp": {"class_declaration", "interface_declaration", "struct_declaration", "record_declaration",
               "enum_declaration", "method_declaration", "constructor_declaration", "property_declaration"},
    "rust": {"function_item", "struct_item", "enum_item", "trait_item", "type_item", "function_signature_item"},
    "php": {"function_definition", "class_declaration", "interface_declaration", "trait_declaration", "method_declaration"},
    "ruby": {"method", "singleton_method", "class", "module"},
    "swift": {"function_declaration", "class_declaration", "protocol_declaration", "protocol_function_declaration"},
    "c": {"function_definition", "struct_specifier"},
    "cpp": {"function_definition", "class_specifier", "struct_specifier"},
}
_DECLS["tsx"] = _DECLS["typescript"]
_DECLS["javascript"] = _DECLS["typescript"]

# Nodes whose name qualifies the methods inside them.
_CONTAINERS = {
    "class_definition", "class_declaration", "abstract_class_declaration", "interface_declaration",
    "struct_declaration", "record_declaration", "object_declaration", "trait_declaration", "protocol_declaration",
    "class_specifier", "struct_specifier", "impl_item", "trait_item", "class", "module", "enum_declaration",
}

# Child fields/types that mark where the body starts (signature ends there).
_BODY_FIELDS = ("body",)
_BODY_TYPES = {
    "block", "statement_block", "class_body", "declaration_list", "field_declaration_list", "function_body",
    "interface_body", "enum_body", "compound_statement", "body_statement", "body", "arrow_function",
    "enum_member_declaration_list", "protocol_body", "class_declaration_list",
}

_SIG_MAX = 110

# Type-level declarations: their members already carry them as qualifier, so they
# are listed after members to keep the 3 inline `api=` slots for callable contracts.
_TYPE_KINDS = {
    "class_definition", "class_declaration", "abstract_class_declaration", "interface_declaration",
    "struct_declaration", "record_declaration", "enum_declaration", "object_declaration", "type_spec",
    "struct_item", "enum_item", "trait_item", "type_item", "trait_declaration", "protocol_declaration",
    "class_specifier", "struct_specifier", "class", "module", "type_alias_declaration",
}

_PARSERS: dict[str, object] = {}
_UNAVAILABLE: set[str] = set()


def lang_for_path(path: str) -> str:
    return EXT_LANG.get(os.path.splitext(path or "")[1].lower(), "")


def _get_parser(lang: str):
    if lang in _UNAVAILABLE:
        return None
    if lang in _PARSERS:
        return _PARSERS[lang]
    try:
        from tree_sitter_language_pack import get_parser  # optional dependency
        parser = get_parser(lang)
    except Exception:
        _UNAVAILABLE.add(lang)
        return None
    _PARSERS[lang] = parser
    return parser


def parser_available(lang: str) -> bool:
    return bool(lang) and _get_parser(lang) is not None


def _text(node, src: bytes) -> str:
    return src[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def _decl_name(node, src: bytes) -> str:
    n = node.child_by_field_name("name")
    if n is not None:
        return _text(n, src)
    # Kotlin / Swift / C(++) keep the identifier as a plain child.
    for c in node.named_children:
        if c.type in ("simple_identifier", "type_identifier", "identifier", "field_identifier", "constant"):
            return _text(c, src)
        if c.type in ("function_declarator", "pointer_declarator", "reference_declarator"):
            return _decl_name(c, src)
    decl = node.child_by_field_name("declarator")
    if decl is not None:
        return _decl_name(decl, src)
    return ""


def _signature(node, src: bytes) -> str:
    end = node.end_byte
    body = None
    for f in _BODY_FIELDS:
        body = node.child_by_field_name(f)
        if body is not None:
            break
    if body is None:
        for c in node.children:
            if c.type in _BODY_TYPES:
                body = c
                break
    if node.type == "variable_declarator":
        val = node.child_by_field_name("value")
        if val is not None and val.type == "arrow_function":
            body = val.child_by_field_name("body")
    if body is not None and body.start_byte > node.start_byte and node.type != "property_declaration":
        end = body.start_byte
    sig = src[node.start_byte:end].decode("utf-8", errors="replace")
    sig = re.sub(r"\s+", " ", sig).strip()
    sig = re.sub(r"\(\s+", "(", sig)
    sig = re.sub(r",?\s+\)", ")", sig)
    sig = re.sub(r"(?:\s*(?:=>|\{|:|=|;|\bend))+$", "", sig).strip()
    if node.type == "variable_declarator":
        sig = "const " + sig
    elif node.type == "type_spec":
        sig = "type " + sig
    return sig[:_SIG_MAX] + ("…" if len(sig) > _SIG_MAX else "")


def _sig_end_line(node, src: bytes) -> int:
    """Last line (1-based) of the signature: the line of the last token before the body."""
    body = node.child_by_field_name("body")
    if body is None:
        for c in node.children:
            if c.type in _BODY_TYPES:
                body = c
                break
    if body is None or body.start_byte <= node.start_byte:
        return node.end_point[0] + 1
    head = src[node.start_byte:body.start_byte].rstrip()
    return node.start_point[0] + 1 + head.count(b"\n")


def _modifier_words(node, src: bytes) -> set[str]:
    words: set[str] = set()
    for c in node.children:
        if c.type in ("modifiers", "modifier", "visibility_modifier", "accessibility_modifier", "visibility"):
            words.update(re.findall(r"[a-z]+", _text(c, src)))
    return words


def _ancestor(node, types: set[str]):
    p = node.parent
    while p is not None:
        if p.type in types:
            return p
        p = p.parent
    return None


def _is_public(node, lang: str, name: str, src: bytes) -> bool:
    if not name:
        return False
    if lang in ("python", "gdscript", "ruby"):
        if name.startswith("_"):
            return False
        if lang == "gdscript" and node.type == "variable_statement":
            return "@export" in _text(node, src).split("var", 1)[0]
        return True
    if lang == "go":
        return name[:1].isupper()
    if lang in ("java", "csharp"):
        mods = _modifier_words(node, src)
        if "public" in mods:
            return True
        if not mods & {"private", "protected", "internal"} and _ancestor(node, {"interface_declaration"}) is not None:
            return True
        return False
    if lang == "kotlin":
        return not _modifier_words(node, src) & {"private", "internal", "protected"}
    if lang == "swift":
        return not _modifier_words(node, src) & {"private", "fileprivate"}
    if lang == "rust":
        if any(c.type == "visibility_modifier" and _text(c, src).startswith("pub") for c in node.children):
            return True
        return node.type == "function_signature_item"  # trait members are public with the trait
    if lang == "php":
        mods = _modifier_words(node, src)
        return not mods & {"private", "protected"}
    if lang in ("c", "cpp"):
        return not name.startswith("_") and "static" not in _text(node, src).split("(", 1)[0].split()
    if lang in _JS_LIKE:
        if name.startswith(("_", "#")):
            return False
        if node.type in ("method_definition", "public_field_definition", "abstract_method_signature"):
            if _modifier_words(node, src) & {"private", "protected"}:
                return False
            cls = _ancestor(node, {"class_declaration", "abstract_class_declaration", "class"})
            return cls is not None and _ancestor(cls, {"export_statement"}) is not None
        if node.type == "variable_declarator":
            decl = node.parent
            return decl is not None and decl.parent is not None and decl.parent.type == "export_statement"
        return _ancestor(node, {"export_statement"}) is not None
    return True


def _qualifier(node, src: bytes) -> str:
    p = node.parent
    while p is not None:
        if p.type in _CONTAINERS:
            nm = _decl_name(p, src)
            if not nm and p.type == "impl_item":
                t = p.child_by_field_name("type")
                nm = _text(t, src) if t is not None else ""
            return nm
        p = p.parent
    return ""


def _gd_class_name(root, src: bytes) -> str:
    for c in root.named_children:
        if c.type == "class_name_statement":
            return _decl_name(c, src)
    return ""


def extract_declarations(src: bytes, lang: str) -> list[dict] | None:
    """All declarations in `src` (public or not). Returns None if no parser."""
    parser = _get_parser(lang)
    if parser is None:
        return None
    tree = parser.parse(src)
    kinds = _DECLS.get(lang, set())
    out: list[dict] = []
    gd_cls = _gd_class_name(tree.root_node, src) if lang == "gdscript" else ""

    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        if node.type in kinds:
            name = _decl_name(node, src)
            out.append({
                "name": name,
                "kind": node.type,
                "line": node.start_point[0] + 1,
                "sig_end": _sig_end_line(node, src),
                "public": _is_public(node, lang, name, src),
                "qualifier": _qualifier(node, src) or gd_cls,
                "signature": _signature(node, src),
            })
        stack.extend(reversed(node.children))
    out.sort(key=lambda d: d["line"])
    return out


def extract_public_contracts(src: bytes, lang: str, added_lines: set[int] | None) -> list[dict] | None:
    """Public declarations whose signature intersects `added_lines` (None = whole file is new)."""
    decls = extract_declarations(src, lang)
    if decls is None:
        return None
    out = []
    for d in decls:
        if not d["public"]:
            continue
        if added_lines is not None and not any(ln in added_lines for ln in range(d["line"], d["sig_end"] + 1)):
            continue
        out.append(d)
    return out


def rank_contracts(items: list[tuple[str, dict]]) -> list[tuple[str, dict]]:
    """Members first, type declarations last; stable within each group (file order, then line)."""
    return sorted(items, key=lambda it: 1 if it[1]["kind"] in _TYPE_KINDS else 0)


def parse_added_lines(diff_text: str) -> dict[str, set[int]]:
    """Maps `b/` path -> set of new-side line numbers added in a `git diff -U0` output."""
    added: dict[str, set[int]] = {}
    cur = ""
    for line in (diff_text or "").splitlines():
        if line.startswith("+++ "):
            p = line[4:].strip()
            cur = p[2:] if p.startswith("b/") else ("" if p == "/dev/null" else p)
            if cur:
                added.setdefault(cur, set())
            continue
        if cur and line.startswith("@@"):
            m = re.match(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@", line)
            if m:
                start, count = int(m.group(1)), int(m.group(2) if m.group(2) is not None else 1)
                added[cur].update(range(start, start + count))
    return added


def format_contract(rel_path: str, decl: dict, lang: str) -> str:
    base = os.path.basename(rel_path)
    qual = decl.get("qualifier") or ""
    if lang == "gdscript" and qual:
        prefix = f"{base}(class_name {qual})"
    elif qual and qual != decl.get("name"):
        prefix = f"{base}({qual})"
    else:
        prefix = base
    return f"{prefix}: `{decl['signature']}`"
