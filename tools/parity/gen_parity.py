#!/usr/bin/env python3
"""
gen_parity builds testdata/parity.json: synthetic HTTP responses together with
the WAFs that the *upstream Python* wafw00f detects in them. The Go test
suite (parity_test.go) replays every case and requires identical results,
which proves the generated Go plugins behave exactly like the originals.

For every matcher call in every plugin a response is synthesised that
satisfies it (a sample string is generated from the regex), and applied to
the normal response, the attack response, or both. A merged case per plugin
combines all of its signals so that multi-condition rules are exercised.

Usage (needs the `requests` package, which wafw00f imports):
    python3 -I tools/parity/gen_parity.py <path-to-wafw00f-checkout> testdata/parity.json
"""

import ast
import json
import os
import re
import sys

try:
    from re import _parser as sre_parse, _constants as C
except ImportError:  # Python < 3.11
    import sre_parse
    import sre_constants as C

UPSTREAM = sys.argv[1] if len(sys.argv) > 1 else sys.exit(__doc__)
OUT = sys.argv[2]
sys.path.insert(0, os.path.abspath(UPSTREAM))

from requests.structures import CaseInsensitiveDict  # noqa: E402
from wafw00f.main import WAFW00F  # noqa: E402
from wafw00f.manager import load_plugins  # noqa: E402

CATEGORY = {
    C.CATEGORY_DIGIT: '0', C.CATEGORY_NOT_DIGIT: 'a',
    C.CATEGORY_WORD: 'a', C.CATEGORY_NOT_WORD: ' ',
    C.CATEGORY_SPACE: ' ', C.CATEGORY_NOT_SPACE: 'a',
}


def gen(tree, variant):
    out = []
    for op, av in tree:
        if op is C.LITERAL:
            out.append(chr(av))
        elif op is C.NOT_LITERAL:
            out.append('x' if chr(av) != 'x' else 'y')
        elif op is C.ANY:
            out.append('a')
        elif op is C.IN:
            out.append(gen_in(av, variant))
        elif op in (C.MAX_REPEAT, C.MIN_REPEAT):
            lo, hi, sub = av
            n = lo
            if variant and hi != C.MAXREPEAT:
                n = min(hi, lo + 2)
            elif variant:
                n = lo + 1
            out.append(''.join(gen(sub, variant) for _ in range(n)))
        elif op is C.SUBPATTERN:
            out.append(gen(av[-1], variant))
        elif op is C.BRANCH:
            alts = av[1]
            out.append(gen(alts[-1] if variant else alts[0], variant))
        elif op in (C.AT, C.ASSERT, C.ASSERT_NOT):
            continue
        else:
            raise ValueError('unsupported regex op %s' % op)
    return ''.join(out)


def gen_in(items, variant):
    if items and items[0][0] is C.NEGATE:
        for cand in 'qZ7_ ~':
            if not any(match_item(i, cand) for i in items[1:]):
                return cand
        raise ValueError('cannot satisfy negated class')
    pick = items[-1] if variant else items[0]
    return item_char(pick)


def item_char(item):
    op, av = item
    if op is C.LITERAL:
        return chr(av)
    if op is C.RANGE:
        return chr(av[0])
    if op is C.CATEGORY:
        return CATEGORY[av]
    raise ValueError('unsupported class item %s' % op)


def match_item(item, ch):
    op, av = item
    if op is C.LITERAL:
        return ch.lower() == chr(av).lower()
    if op is C.RANGE:
        return av[0] <= ord(ch.lower()) <= av[1] or av[0] <= ord(ch.upper()) <= av[1]
    if op is C.CATEGORY:
        return re.fullmatch(r'\d' if av is C.CATEGORY_DIGIT else r'\D' if av is C.CATEGORY_NOT_DIGIT else
                            r'\w' if av is C.CATEGORY_WORD else r'\W' if av is C.CATEGORY_NOT_WORD else
                            r'\s' if av is C.CATEGORY_SPACE else r'\S', ch) is not None
    return False


def sample(pattern, variant):
    try:
        s = gen(sre_parse.parse(pattern), variant)
    except ValueError:
        return None
    return s if re.search(pattern, s, re.I) else None


class FakeResponse:
    def __init__(self, d):
        self.status_code = d['status']
        self.reason = d['reason']
        self.headers = CaseInsensitiveDict(d['headers'])
        self.text = d['body']


def blank():
    return {'status': 200, 'reason': 'OK', 'headers': {}, 'body': ''}


def signals_of(path):
    """Yield (kind, arg, attack) for every matcher call in a plugin file."""
    defaults = {'matchHeader': False, 'matchCookie': False,
                'matchContent': True, 'matchStatus': True, 'matchReason': True}
    tree = ast.parse(open(path, encoding='utf-8').read())
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                and node.func.attr in defaults:
            attack = defaults[node.func.attr]
            for kw in node.keywords:
                attack = kw.value.value
            if len(node.args) == 2:
                attack = node.args[1].value
            a = node.args[0]
            arg = (a.elts[0].value, a.elts[1].value) if isinstance(a, ast.Tuple) else a.value
            yield node.func.attr, arg, attack


def apply(resp, kind, arg, variant):
    if kind == 'matchHeader':
        s = sample(arg[1], variant)
        if s is None:
            return False
        name = arg[0]
        if name.lower() == 'set-cookie' and resp['headers'].get('Set-Cookie'):
            resp['headers']['Set-Cookie'] += ', ' + s
        else:
            resp['headers'][name] = s
    elif kind == 'matchCookie':
        s = sample(arg, variant)
        if s is None:
            return False
        old = resp['headers'].get('Set-Cookie')
        resp['headers']['Set-Cookie'] = old + ', ' + s if old else s
    elif kind == 'matchContent':
        s = sample(arg, variant)
        if s is None:
            return False
        resp['body'] = resp['body'] + '\n' + s if resp['body'] else s
    elif kind == 'matchStatus':
        resp['status'] = arg
    elif kind == 'matchReason':
        resp['reason'] = arg
    return True


def main():
    plugdir = os.path.join(UPSTREAM, 'wafw00f', 'plugins')
    plugins = load_plugins()
    detectors = sorted((m.NAME, m.is_waf) for m in plugins.values())
    inst = object.__new__(WAFW00F)

    cases, skipped = [], 0

    def add(name, normal, attack):
        inst.rq = FakeResponse(normal) if normal is not None else None
        inst.attackres = FakeResponse(attack) if attack is not None else None
        expected = [n for n, fn in detectors if fn(inst)]
        cases.append({'name': name, 'normal': normal, 'attack': attack, 'expected': expected})

    add('blank', blank(), blank())
    add('no-attack-response', blank(), None)
    add('no-responses', None, None)

    for fn in sorted(os.listdir(plugdir)):
        if not fn.endswith('.py') or fn == '__init__.py':
            continue
        pid = fn[:-3]
        sigs = list(signals_of(os.path.join(plugdir, fn)))
        for i, (kind, arg, attack) in enumerate(sigs):
            for variant in (False, True):
                for where in ('both', 'normal', 'attack'):
                    normal, att = blank(), blank()
                    targets = {'both': (normal, att), 'normal': (normal,), 'attack': (att,)}[where]
                    if not all(apply(t, kind, arg, variant) for t in targets):
                        skipped += 1
                        break
                    add('%s/%d/%s/%s' % (pid, i, 'v' if variant else 'b', where), normal, att)
        statuses = sorted({a for k, a, _ in sigs if k == 'matchStatus'}) or [None]
        reasons = sorted({a for k, a, _ in sigs if k == 'matchReason'}) or [None]
        for st in statuses:
            for rs in reasons:
                for variant in (False, True):
                    normal, att = blank(), blank()
                    for kind, arg, _ in sigs:
                        if kind in ('matchStatus', 'matchReason'):
                            continue
                        apply(normal, kind, arg, variant)
                        apply(att, kind, arg, variant)
                    for r in (normal, att):
                        if st is not None:
                            r['status'] = st
                        if rs is not None:
                            r['reason'] = rs
                    add('%s/merged/%s/%s/%s' % (pid, st, rs, 'v' if variant else 'b'), normal, att)

    with open(OUT, 'w', encoding='utf-8') as f:
        json.dump({'upstream_plugins': len(detectors), 'cases': cases}, f, ensure_ascii=False,
                  separators=(',', ':'))
        f.write('\n')
    positives = sum(1 for c in cases if c['expected'])
    print('wrote %d cases (%d with detections), skipped %d unsatisfiable signals'
          % (len(cases), positives, skipped))


if __name__ == '__main__':
    main()
