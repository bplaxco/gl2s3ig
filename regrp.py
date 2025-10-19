#!.venv/bin/python3
import sys

from lark import Lark
from lark import Token
from lark import Tree

_parser = Lark(r"""
    pattern: (NON_GROUP_SEGMENT | ESCAPE_SEQUENCE | group)*
    group: GROUP_START [NON_CAP_MOD] [pattern] GROUP_END

    NON_CAP_MOD: "?" /[imsxUJnx\-:]+/
    NON_GROUP_SEGMENT: /[^\(\\\)]+/
    ESCAPE_SEQUENCE: "\\" /./
    NON_CAPTURE_MOD: "?:"
    GROUP_START: "("
    GROUP_END: ")"
""", start="pattern", parser="lalr")


def _is_capture_group(group_node: Tree) -> bool:
    return group_node.children[1] is None

def _find_group(group: int, root: Tree) -> (int, int, int):
    if root is None:
        return 0, 0, 0

    seen = 0
    for child in root.children:
        # We only care about groups and sub-groups
        if not isinstance(child, Tree):
            continue

        # Got a group
        if child.data.type == 'RULE' and child.data.value == 'group':
            if _is_capture_group(child):
                seen += 1

            token = child.data

            # mirror gitleak's behavior that if there's a capture group and
            # the group isn't set, then assume the first capture group
            if seen == (group or 1):
                # Found it!
                start_pos = child.children[0].start_pos
                end_pos = child.children[-1].end_pos
                return start_pos, end_pos, seen

            # Check to see if the target group is a sub group. If it is
            # we don't support that.
            _, sub_end, sub_seen = _find_group(group - seen, child.children[2])
            if sub_end != 0:
                raise ValueError("cannot split appart inner groups")

            # Count all the groups passed as sub groups
            seen += sub_seen

    return 0, 0, seen


def split_regexp(group: int, regexp: str) -> (str, str, str):
    root = _parser.parse(regexp)
    start_pos, end_pos, _ = _find_group(group, root)
    if end_pos == 0:
        if group == 0:
            return "", regexp, ""

        raise ValueError("could not find group")

    return regexp[:start_pos], regexp[start_pos:end_pos], regexp[end_pos:]


if __name__ == "__main__":
    p, t, s = split_regexp(int(sys.argv[1]), sys.argv[2])
    print("prefix:", p)
    print("target:", t)
    print("suffix:", s)
