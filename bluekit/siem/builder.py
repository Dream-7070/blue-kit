"""Hunt shart daraxtini (IR) har bir SIEM ning o'z tiliga render qiladi.

Har bir syntax klass uchun bitta Renderer sinfi bor. Hunt lar bu yerda ham, katalogda
ham matn sifatida yozilmaydi — faqat `{'field': ..., 'op': ..., 'value': ...}` daraxti
aylanib chiqiladi. Shuning uchun yangi SIEM qo'shish 32 ta so'rovni qayta yozishni
talab qilmaydi.
"""

from .dialects import (DIALECTS, FIELD_MAPS, SOURCE_MAPS, EVENT_ID_TRANSLATION,
                       FIELD_OVERRIDES, source_for)
from .catalog import HUNTS, CATEGORIES

PRIVATE_CIDRS = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']

_CMP = {'eq': '=', 'ne': '!=', 'gt': '>', 'gte': '>=', 'lt': '<', 'lte': '<='}


class Renderer(object):
    """Umumiy mantiq: maydonlarni yechish, shart daraxtini aylanib chiqish."""

    syntax = 'base'
    supports_agg = True
    supports_time = True
    supports_cidr = True
    supports_regex = True
    event_id_as_string = False

    def __init__(self, siem, hunt, params):
        self.siem = siem
        self.dialect = DIALECTS[siem]
        base = dict(FIELD_MAPS.get(siem, {}))
        base.update(FIELD_OVERRIDES.get(siem, {}).get(hunt.get('logsource', 'any'), {}))
        self.fmap = base
        self.hunt = hunt
        self.params = params
        self.notes = []
        self._seen = set()

    # ------------------------------------------------------------- eslatmalar
    def note(self, text):
        if text not in self._seen:
            self._seen.add(text)
            self.notes.append(text)

    # ---------------------------------------------------------------- maydon
    def raw_field(self):
        return self.fmap.get('message')

    def field(self, canon):
        """(native_nom, fallback_mi). Maydon yo'q bo'lsa xom matnga tushadi."""
        native = self.fmap.get(canon)
        if native:
            return native, False
        raw = self.raw_field()
        if raw:
            self.note("%s da '%s' alohida maydon emas — xom log matni (%s) bo'yicha "
                      "qidirilmoqda, noto'g'ri mos kelish ehtimoli bor."
                      % (self.dialect['name'], canon, raw))
            return raw, True
        self.note("%s da '%s' maydoni yo'q va xom matn maydoni ham aniqlanmagan — "
                  "shart tushirib qoldirildi." % (self.dialect['name'], canon))
        return None, True

    def value_of(self, v):
        if isinstance(v, dict) and 'param' in v:
            return self.params.get(v['param'])
        return v

    def coerce(self, canon, v):
        if canon == 'event_id':
            tr = EVENT_ID_TRANSLATION.get(self.siem)
            if tr is not None:
                if v in tr:
                    return tr[v]
                self.note("DIQQAT: %s Windows EventID ishlatmaydi va %s uchun mos "
                          "ActionType topilmadi — so'rov shu holicha NATIJA BERMAYDI, "
                          "shartni qo'lda mos ActionType ga almashtiring."
                          % (self.dialect['name'], v))
                return str(v)
            if self.event_id_as_string:
                return str(v)
        return v

    # ------------------------------------------------------------ shart daraxti
    def cond(self, node):
        if not node:
            return None
        op = node.get('op')
        if op in ('all', 'any', 'none'):
            parts = [self.cond(x) for x in node.get('items', [])]
            parts = [p for p in parts if p]
            if not parts:
                return None
            if op == 'all':
                return self.join_and(parts)
            if op == 'any':
                return self.group(self.join_or(parts)) if len(parts) > 1 else parts[0]
            return self.negate(self.group(self.join_and(parts)))

        canon = node['field']
        native, is_fallback = self.field(canon)
        if native is None:
            return None
        value = self.value_of(node.get('value'))
        return self.render_op(canon, native, is_fallback, op, value)

    def render_op(self, canon, native, is_fallback, op, value):
        values = value if isinstance(value, list) else [value]
        values = [self.coerce(canon, v) for v in values]
        # bir xil qiymatlar (masalan Defender da 4728/4732 -> bitta ActionType)
        seen, uniq = set(), []
        for v in values:
            if v not in seen:
                seen.add(v)
                uniq.append(v)
        values = uniq

        if is_fallback:
            if op in ('is_public', 'is_private', 'exists'):
                self.note("'%s' xom matn bo'yicha qidirilgani uchun '%s' sharti "
                          "tushirib qoldirildi — natijani qo'lda filtrlang."
                          % (canon, op))
                return None
            for v in values:
                if len(str(v)) <= 3:
                    self.note("'%s' xom matn bo'yicha qidirilmoqda, qiymati esa juda "
                              "qisqa ('%s') — juda ko'p noto'g'ri natija beradi. Bu "
                              "shartni qo'lda aniqlashtiring yoki natijani filtrlang."
                              % (canon, v))
            parts = [self.contains(native, str(v)) for v in values]
            return self.group(self.join_or(parts)) if len(parts) > 1 else parts[0]

        if op in ('eq', 'ne', 'gt', 'gte', 'lt', 'lte'):
            return self.cmp(native, _CMP[op], values[0])
        if op == 'in':
            return self.cmp(native, '=', values[0]) if len(values) == 1 \
                else self.in_(native, values)
        if op == 'not_in':
            if len(values) == 1:
                return self.cmp(native, '!=', values[0])
            return self.negate(self.group(self.in_(native, values)))
        if op in ('contains', 'contains_any'):
            parts = [self.contains(native, str(v)) for v in values]
            return self.group(self.join_or(parts)) if len(parts) > 1 else parts[0]
        if op == 'not_contains':
            parts = [self.contains(native, str(v)) for v in values]
            inner = self.group(self.join_or(parts)) if len(parts) > 1 else parts[0]
            return self.negate(inner)
        if op == 'startswith_any':
            parts = [self.startswith(native, str(v)) for v in values]
            return self.group(self.join_or(parts)) if len(parts) > 1 else parts[0]
        if op == 'endswith_any':
            parts = [self.endswith(native, str(v)) for v in values]
            return self.group(self.join_or(parts)) if len(parts) > 1 else parts[0]
        if op == 'regex':
            if not self.supports_regex:
                self.note("%s regex ni qo'llab-quvvatlamaydi — shart oddiy matn "
                          "qidiruviga tushirildi." % self.dialect['name'])
                return self.contains(native, str(values[0]))
            return self.regex(native, str(values[0]))
        if op == 'exists':
            return self.exists(native)
        if op in ('is_public', 'is_private'):
            if not self.supports_cidr:
                self.note("%s qidiruvida CIDR funksiyasi yo'q — ichki/tashqi IP "
                          "filtri tushirib qoldirildi, natijani qo'lda ajrating "
                          "(ichki: 10.x, 172.16-31.x, 192.168.x)." % self.dialect['name'])
                return None
            return self.public_ip(native) if op == 'is_public' else self.private_ip(native)
        raise ValueError("Noma'lum operator: %s" % op)

    # ------------------------------------------------------- sintaksis primitivlari
    def escape_inner(self, s):
        return s.replace('\\', '\\\\').replace('"', '\\"')

    def lit(self, v):
        if isinstance(v, bool):
            return 'true' if v else 'false'
        if isinstance(v, (int, float)):
            return str(v)
        return '"%s"' % self.escape_inner(str(v))

    def group(self, expr):
        return '(%s)' % expr

    def join_and(self, parts):
        return ' AND '.join(parts)

    def join_or(self, parts):
        return ' OR '.join(parts)

    def negate(self, expr):
        return 'NOT %s' % expr

    def cmp(self, native, op, v):
        return '%s %s %s' % (native, op, self.lit(v))

    def in_(self, native, values):
        return '%s IN (%s)' % (native, ', '.join(self.lit(v) for v in values))

    def contains(self, native, v):
        return '%s LIKE %s' % (native, self.lit('%' + v + '%'))

    def startswith(self, native, v):
        return '%s LIKE %s' % (native, self.lit(v + '%'))

    def endswith(self, native, v):
        return '%s LIKE %s' % (native, self.lit('%' + v))

    def regex(self, native, v):
        return '%s MATCHES %s' % (native, self.lit(v))

    def exists(self, native):
        return '%s IS NOT NULL' % native

    def public_ip(self, native):
        return self.group(self.join_and(
            [self.negate(self.cidr(native, c)) for c in PRIVATE_CIDRS]))

    def private_ip(self, native):
        return self.group(self.join_or(
            [self.cidr(native, c) for c in PRIVATE_CIDRS]))

    def cidr(self, native, block):
        return '%s IN %s' % (native, self.lit(block))

    # -------------------------------------------------------------- yordamchi
    def source(self):
        return source_for(self.siem, self.hunt.get('logsource', 'any'))

    def days(self):
        return int(self.params.get('days', 7))

    def limit(self):
        return int(self.params.get('limit', 200))

    def agg(self):
        return self.hunt.get('aggregate')

    def metric_native(self, fld):
        """Agregatsiya maydoni: xaritada yo'q bo'lsa kanonik nom qoladi + ogohlantirish."""
        native = self.fmap.get(fld)
        if native:
            return native
        self.note("%s maydonlar xaritasida '%s' yo'q — so'rovda kanonik nom qoldirildi, "
                  "uni o'z muhitingizdagi haqiqiy maydon nomiga almashtiring."
                  % (self.dialect['name'], fld))
        return fld

    def metric_parts(self):
        """(kind, canonical_field yoki None, alias)"""
        metric = self.agg()['metric']
        if metric == 'count':
            return 'count', None, 'event_count'
        kind, fld = metric.split(':', 1)
        alias = '%s_%s' % (fld, 'count' if kind == 'distinct_count' else 'sum')
        return kind, fld, alias

    def having_value(self):
        having = self.agg().get('having') or {}
        if 'param' in having:
            return self.params.get(having['param'], 1)
        return having.get('value', 1)

    def having_op(self):
        return _CMP.get((self.agg().get('having') or {}).get('op', 'gte'), '>=')

    def group_natives(self):
        out = []
        for canon in self.agg()['group_by']:
            native, _ = self.field(canon)
            if native:
                out.append((canon, native))
        return out

    def select_natives(self):
        out = []
        for canon in self.hunt.get('select', []):
            native = self.fmap.get(canon)
            if native and native not in [n for _, n in out]:
                out.append((canon, native))
        return out

    def user_filters(self):
        """--host / --user / --ip parametrlari uchun qo'shimcha shartlar."""
        parts = []
        for param, canon in (('host', 'host'), ('user', 'user')):
            val = self.params.get(param)
            if val:
                native, fb = self.field(canon)
                if native:
                    parts.append(self.contains(native, str(val)) if fb
                                 else self.cmp(native, '=', str(val)))
        ip = self.params.get('ip')
        if ip:
            ip_parts = []
            for canon in ('src_ip', 'dest_ip'):
                native = self.fmap.get(canon)
                if native:
                    ip_parts.append(self.cmp(native, '=', str(ip)))
            if ip_parts:
                parts.append(self.group(self.join_or(ip_parts))
                             if len(ip_parts) > 1 else ip_parts[0])
            else:
                native, fb = self.field('src_ip')
                if native:
                    parts.append(self.contains(native, str(ip)))
        return parts

    def where_expr(self):
        parts = []
        base = self.cond(self.hunt.get('where'))
        if base:
            parts.append(base)
        parts.extend(self.user_filters())
        if not parts:
            return None
        return self.join_and(parts)

    def agg_note(self):
        a = self.agg()
        kind, fld, alias = self.metric_parts()
        metric_uz = {'count': 'qatorlar soni',
                     'distinct_count': "noyob '%s' soni" % fld,
                     'sum': "'%s' yig'indisi" % fld}[kind]
        self.note("%s ning qidiruv qatori agregatsiya qilmaydi — natijani agregatsiya "
                  "paneliga o'ting: guruhlash %s bo'yicha, metrika %s, shart %s %s."
                  % (self.dialect['name'], ', '.join(a['group_by']), metric_uz,
                     self.having_op(), self.having_value()))

    def time_note(self):
        self.note("Vaqt oralig'ini %s ning time picker ida tanlang: oxirgi %d kun."
                  % (self.dialect['name'], self.days()))

    def render(self):
        raise NotImplementedError


# --------------------------------------------------------------------- AQL
class AqlRenderer(Renderer):
    syntax = 'aql'

    def escape_inner(self, s):
        return s.replace("'", "''")

    def lit(self, v):
        if isinstance(v, bool):
            return 'true' if v else 'false'
        if isinstance(v, (int, float)):
            return str(v)
        return "'%s'" % self.escape_inner(str(v))

    def text_expr(self, native):
        return 'UTF8(payload)' if native == 'payload' else native

    def contains(self, native, v):
        return "%s LIKE %s" % (self.text_expr(native), self.lit('%' + v + '%'))

    def startswith(self, native, v):
        return "%s LIKE %s" % (self.text_expr(native), self.lit(v + '%'))

    def endswith(self, native, v):
        return "%s LIKE %s" % (self.text_expr(native), self.lit('%' + v))

    def regex(self, native, v):
        return "%s MATCHES %s" % (self.text_expr(native), self.lit(v))

    def cidr(self, native, block):
        return "INCIDR(%s, %s)" % (self.lit(block), native)

    def metric_sql(self):
        kind, fld, alias = self.metric_parts()
        if kind == 'count':
            return 'COUNT(*)', alias
        native = self.metric_native(fld)
        return ('COUNT(DISTINCT %s)' % native if kind == 'distinct_count'
                else 'SUM(%s)' % native), alias

    def render(self):
        lines = []
        where = self.where_expr()
        if self.agg():
            groups = self.group_natives()
            expr, alias = self.metric_sql()
            cols = ['%s AS %s' % (n, c) for c, n in groups] + ['%s AS %s' % (expr, alias)]
            lines.append('SELECT ' + ', '.join(cols))
            lines.append('FROM events')
            if where:
                lines.append('WHERE ' + where)
            lines.append('GROUP BY ' + ', '.join(n for _, n in groups))
            lines.append('HAVING %s %s %s' % (expr, self.having_op(), self.having_value()))
            lines.append('ORDER BY %s DESC' % alias)
        else:
            cols = ['%s AS %s' % (n, c) for c, n in self.select_natives()] or ['*']
            lines.append('SELECT ' + ', '.join(cols))
            lines.append('FROM events')
            if where:
                lines.append('WHERE ' + where)
            ts = self.fmap.get('ts')
            if ts:
                lines.append('ORDER BY %s DESC' % ts)
        lines.append('LIMIT %d' % self.limit())
        lines.append('LAST %d DAYS' % self.days())
        return '\n'.join(lines)


# --------------------------------------------------------------------- SPL
class SplRenderer(Renderer):
    syntax = 'spl'

    def contains(self, native, v):
        return '%s=%s' % (native, self.lit('*' + v + '*'))

    def startswith(self, native, v):
        return '%s=%s' % (native, self.lit(v + '*'))

    def endswith(self, native, v):
        return '%s=%s' % (native, self.lit('*' + v))

    def cmp(self, native, op, v):
        return '%s%s%s' % (native, op, self.lit(v))

    def regex(self, native, v):
        self.note("SPL da regex alohida `| regex` bosqichini talab qiladi — "
                  "shart matn qidiruviga tushirildi.")
        return self.contains(native, v)

    def exists(self, native):
        return '%s=*' % native

    def cidr(self, native, block):
        return '%s=%s' % (native, self.lit(block))

    def metric_spl(self):
        kind, fld, alias = self.metric_parts()
        if kind == 'count':
            return 'count AS %s' % alias, alias
        native = self.metric_native(fld)
        fn = 'dc' if kind == 'distinct_count' else 'sum'
        return '%s(%s) AS %s' % (fn, native, alias), alias

    def render(self):
        lines = ['%s earliest=-%dd' % (self.source(), self.days())]
        where = self.where_expr()
        if where:
            lines.append('| search ' + where)
        if self.agg():
            groups = self.group_natives()
            expr, alias = self.metric_spl()
            lines.append('| stats %s by %s' % (expr, ', '.join(n for _, n in groups)))
            lines.append('| where %s %s %s' % (alias, self.having_op(), self.having_value()))
            lines.append('| sort - %s' % alias)
        else:
            cols = [n for _, n in self.select_natives()]
            if cols:
                lines.append('| table ' + ', '.join(cols))
        lines.append('| head %d' % self.limit())
        return '\n'.join(lines)


# --------------------------------------------------------------------- KQL
class KqlRenderer(Renderer):
    syntax = 'kql'

    def escape_inner(self, s):
        return s.replace('"', '""')

    def lit(self, v):
        if isinstance(v, bool):
            return 'true' if v else 'false'
        if isinstance(v, (int, float)):
            return str(v)
        return '@"%s"' % self.escape_inner(str(v))

    def cmp(self, native, op, v):
        op = '==' if op == '=' else op
        return '%s %s %s' % (native, op, self.lit(v))

    def in_(self, native, values):
        return '%s in (%s)' % (native, ', '.join(self.lit(v) for v in values))

    def contains(self, native, v):
        return '%s contains %s' % (native, self.lit(v))

    def startswith(self, native, v):
        return '%s startswith %s' % (native, self.lit(v))

    def endswith(self, native, v):
        return '%s endswith %s' % (native, self.lit(v))

    def regex(self, native, v):
        return '%s matches regex %s' % (native, self.lit(v))

    def exists(self, native):
        return 'isnotempty(%s)' % native

    def join_and(self, parts):
        return ' and '.join(parts)

    def join_or(self, parts):
        return ' or '.join(parts)

    def negate(self, expr):
        return 'not%s' % (expr if expr.startswith('(') else '(%s)' % expr)

    def public_ip(self, native):
        return 'not(ipv4_is_private(%s))' % native

    def private_ip(self, native):
        return 'ipv4_is_private(%s)' % native

    def metric_kql(self):
        kind, fld, alias = self.metric_parts()
        if kind == 'count':
            return '%s = count()' % alias, alias
        native = self.metric_native(fld)
        fn = 'dcount' if kind == 'distinct_count' else 'sum'
        return '%s = %s(%s)' % (alias, fn, native), alias

    def render(self):
        lines = [self.source()]
        ts = self.fmap.get('ts')
        if ts:
            lines.append('| where %s > ago(%dd)' % (ts, self.days()))
        where = self.where_expr()
        if where:
            lines.append('| where ' + where)
        if self.agg():
            groups = self.group_natives()
            expr, alias = self.metric_kql()
            lines.append('| summarize %s by %s' % (expr, ', '.join(n for _, n in groups)))
            lines.append('| where %s %s %s' % (alias, self.having_op(), self.having_value()))
            lines.append('| order by %s desc' % alias)
        else:
            cols = [n for _, n in self.select_natives()]
            if cols:
                lines.append('| project ' + ', '.join(cols))
            if ts:
                lines.append('| order by %s desc' % ts)
        lines.append('| take %d' % self.limit())
        return '\n'.join(lines)


# ------------------------------------------------------------------- ES|QL
class EsqlRenderer(Renderer):
    syntax = 'esql'
    event_id_as_string = True

    def cmp(self, native, op, v):
        op = '==' if op == '=' else op
        return '%s %s %s' % (native, op, self.lit(v))

    def contains(self, native, v):
        return '%s LIKE %s' % (native, self.lit('*' + v + '*'))

    def startswith(self, native, v):
        return '%s LIKE %s' % (native, self.lit(v + '*'))

    def endswith(self, native, v):
        return '%s LIKE %s' % (native, self.lit('*' + v))

    def regex(self, native, v):
        return '%s RLIKE %s' % (native, self.lit(v))

    def public_ip(self, native):
        return 'NOT CIDR_MATCH(%s, %s)' % (
            native, ', '.join(self.lit(c) for c in PRIVATE_CIDRS))

    def private_ip(self, native):
        return 'CIDR_MATCH(%s, %s)' % (
            native, ', '.join(self.lit(c) for c in PRIVATE_CIDRS))

    def metric_esql(self):
        kind, fld, alias = self.metric_parts()
        if kind == 'count':
            return '%s = COUNT(*)' % alias, alias
        native = self.metric_native(fld)
        fn = 'COUNT_DISTINCT' if kind == 'distinct_count' else 'SUM'
        return '%s = %s(%s)' % (alias, fn, native), alias

    def render(self):
        lines = [self.source()]
        conds = []
        ts = self.fmap.get('ts')
        if ts:
            conds.append('%s > NOW() - %d days' % (ts, self.days()))
        where = self.where_expr()
        if where:
            conds.append(where)
        if conds:
            lines.append('| WHERE ' + ' AND '.join(conds))
        if self.agg():
            groups = self.group_natives()
            expr, alias = self.metric_esql()
            lines.append('| STATS %s BY %s' % (expr, ', '.join(n for _, n in groups)))
            lines.append('| WHERE %s %s %s' % (alias, self.having_op(), self.having_value()))
            lines.append('| SORT %s DESC' % alias)
        else:
            cols = [n for _, n in self.select_natives()]
            if cols:
                lines.append('| KEEP ' + ', '.join(cols))
            if ts:
                lines.append('| SORT %s DESC' % ts)
        lines.append('| LIMIT %d' % self.limit())
        return '\n'.join(lines)


# --------------------------------------------------------- DQL / KQL / Lucene
class DqlRenderer(Renderer):
    syntax = 'dql'
    supports_agg = False
    supports_time = False
    supports_regex = False
    event_id_as_string = True

    _LUCENE_SPECIAL = '+-&|!(){}[]^"~*?:\\/ '

    def escape_inner(self, s):
        out = []
        for ch in s:
            if ch in self._LUCENE_SPECIAL:
                out.append('\\' + ch)
            else:
                out.append(ch)
        return ''.join(out)

    def lit(self, v):
        if isinstance(v, (int, float)) and not isinstance(v, bool):
            return '"%s"' % v
        return '"%s"' % str(v).replace('\\', '\\\\').replace('"', '\\"')

    def cmp(self, native, op, v):
        if op == '=':
            return '%s:%s' % (native, self.lit(v))
        if op == '!=':
            return 'NOT %s:%s' % (native, self.lit(v))
        bound = {'>': '{%s TO *}', '>=': '[%s TO *]',
                 '<': '{* TO %s}', '<=': '[* TO %s]'}[op]
        return '%s:%s' % (native, bound % v)

    def in_(self, native, values):
        return '%s:(%s)' % (native, ' OR '.join(self.lit(v) for v in values))

    def contains(self, native, v):
        return '%s:*%s*' % (native, self.escape_inner(str(v)))

    def startswith(self, native, v):
        return '%s:%s*' % (native, self.escape_inner(str(v)))

    def endswith(self, native, v):
        return '%s:*%s' % (native, self.escape_inner(str(v)))

    def exists(self, native):
        return '%s:*' % native

    def cidr(self, native, block):
        return '%s:%s' % (native, self.lit(block))

    def render(self):
        parts = []
        src = self.source()
        if src:
            parts.append(src)
        where = self.where_expr()
        if where:
            parts.append(where)
        if self.agg():
            self.agg_note()
        self.time_note()
        self.note("Ustunlarni ko'rish uchun tanlang: %s."
                  % ', '.join(n for _, n in self.select_natives()))
        return ' AND '.join(parts) if parts else '*'


# --------------------------------------------------------------------- UDM
class UdmRenderer(Renderer):
    syntax = 'udm'
    supports_agg = False
    event_id_as_string = True

    def cmp(self, native, op, v):
        return '%s %s %s' % (native, op, self.lit(v))

    def in_(self, native, values):
        return self.group(self.join_or([self.cmp(native, '=', v) for v in values]))

    def contains(self, native, v):
        return '%s = /.*%s.*/ nocase' % (native, self._re(v))

    def startswith(self, native, v):
        return '%s = /^%s.*/ nocase' % (native, self._re(v))

    def endswith(self, native, v):
        return '%s = /.*%s$/ nocase' % (native, self._re(v))

    def regex(self, native, v):
        return '%s = /%s/ nocase' % (native, v)

    def _re(self, v):
        out = []
        for ch in str(v):
            if ch in '.^$*+?()[]{}|/\\':
                out.append('\\' + ch)
            else:
                out.append(ch)
        return ''.join(out)

    def exists(self, native):
        return '%s != ""' % native

    def cidr(self, native, block):
        return 'net.ip_in_range_cidr(%s, %s)' % (native, self.lit(block))

    def render(self):
        parts = []
        src = self.source()
        if src:
            parts.append(src)
        where = self.where_expr()
        if where:
            parts.append(where)
        if self.agg():
            self.agg_note()
        self.time_note()
        self.note("Matn ichidan qidirish uchun regex literali (/.../) ishlatilgan — "
                  "muhitingizda qo'llab-quvvatlanmasa, `nocase` ni olib tashlab "
                  "to'liq qiymat bilan tenglashtiring.")
        return ' AND '.join(parts) if parts else '*'


# -------------------------------------------------------------------- Sumo
class SumoRenderer(Renderer):
    syntax = 'sumo'
    supports_time = False

    def cmp(self, native, op, v):
        return '%s %s %s' % (native, op, self.lit(v))

    def in_(self, native, values):
        return self.group(self.join_or([self.cmp(native, '=', v) for v in values]))

    def contains(self, native, v):
        return '%s matches %s' % (native, self.lit('*' + v + '*'))

    def startswith(self, native, v):
        return '%s matches %s' % (native, self.lit(v + '*'))

    def endswith(self, native, v):
        return '%s matches %s' % (native, self.lit('*' + v))

    def exists(self, native):
        return '!isNull(%s)' % native

    def negate(self, expr):
        return '!%s' % (expr if expr.startswith('(') else '(%s)' % expr)

    def public_ip(self, native):
        return '!isPrivateIP(%s)' % native

    def private_ip(self, native):
        return 'isPrivateIP(%s)' % native

    def metric_sumo(self):
        kind, fld, alias = self.metric_parts()
        if kind == 'count':
            return 'count as %s' % alias, alias
        native = self.metric_native(fld)
        fn = 'count_distinct' if kind == 'distinct_count' else 'sum'
        return '%s(%s) as %s' % (fn, native, alias), alias

    def render(self):
        lines = [self.source()]
        where = self.where_expr()
        if where:
            lines.append('| where ' + where)
        if self.agg():
            groups = self.group_natives()
            expr, alias = self.metric_sumo()
            lines.append('| %s by %s' % (expr, ', '.join(n for _, n in groups)))
            lines.append('| where %s %s %s' % (alias, self.having_op(), self.having_value()))
            lines.append('| sort by %s' % alias)
        else:
            cols = [n for _, n in self.select_natives()]
            if cols:
                lines.append('| fields ' + ', '.join(cols))
        lines.append('| limit %d' % self.limit())
        self.time_note()
        return '\n'.join(lines)


# ------------------------------------------------------------- ArcSight CEF
class CefRenderer(Renderer):
    syntax = 'cef_search'
    supports_agg = False
    supports_time = False
    supports_cidr = False
    supports_regex = False

    def lit(self, v):
        # ArcSight qidiruvida qiymatlar har doim qo'shtirnoqda yoziladi.
        return '"%s"' % self.escape_inner(str(v))

    def cmp(self, native, op, v):
        return '%s%s%s' % (native, op, self.lit(v))

    def in_(self, native, values):
        return self.group(self.join_or([self.cmp(native, '=', v) for v in values]))

    def contains(self, native, v):
        return '%s CONTAINS %s' % (native, self.lit(v))

    def startswith(self, native, v):
        return '%s STARTSWITH %s' % (native, self.lit(v))

    def endswith(self, native, v):
        return '%s ENDSWITH %s' % (native, self.lit(v))

    def exists(self, native):
        return '%s=*' % native

    def render(self):
        parts = []
        src = self.source()
        if src:
            parts.append(src)
        where = self.where_expr()
        if where:
            parts.append(where)
        if self.agg():
            self.agg_note()
        self.time_note()
        return ' AND '.join(parts) if parts else '*'


# --------------------------------------------------------------- LogScale CQL
class CqlRenderer(Renderer):
    syntax = 'cql'
    supports_time = False
    supports_cidr = False

    def cmp(self, native, op, v):
        return '%s%s%s' % (native, op, self.lit(v))

    def in_(self, native, values):
        return self.group(self.join_or([self.cmp(native, '=', v) for v in values]))

    def contains(self, native, v):
        return '%s=%s' % (native, self.lit('*' + v + '*'))

    def startswith(self, native, v):
        return '%s=%s' % (native, self.lit(v + '*'))

    def endswith(self, native, v):
        return '%s=%s' % (native, self.lit('*' + v))

    def regex(self, native, v):
        return '%s=/%s/' % (native, v)

    def exists(self, native):
        return '%s=*' % native

    def join_and(self, parts):
        return ' and '.join(parts)

    def join_or(self, parts):
        return ' or '.join(parts)

    def negate(self, expr):
        return '!%s' % (expr if expr.startswith('(') else '(%s)' % expr)

    def metric_cql(self):
        kind, fld, alias = self.metric_parts()
        if kind == 'count':
            return 'count(as=%s)' % alias, alias
        native = self.metric_native(fld)
        fn = 'count' if kind == 'distinct_count' else 'sum'
        extra = ', distinct=true' if kind == 'distinct_count' else ''
        return '%s(field=%s%s, as=%s)' % (fn, native, extra, alias), alias

    def render(self):
        lines = []
        src = self.source()
        where = self.where_expr()
        head = ' '.join(x for x in (src, where) if x and x != '*')
        lines.append(head if head else '*')
        if self.agg():
            groups = self.group_natives()
            expr, alias = self.metric_cql()
            lines.append('| groupBy([%s], function=%s)'
                         % (', '.join(n for _, n in groups), expr))
            lines.append('| %s %s %s' % (alias, self.having_op(), self.having_value()))
            lines.append('| sort(field=%s, order=desc, limit=%d)' % (alias, self.limit()))
        else:
            cols = [n for _, n in self.select_natives()]
            if cols:
                lines.append('| select([%s])' % ', '.join(cols))
            lines.append('| head(%d)' % self.limit())
        self.time_note()
        return '\n'.join(lines)


RENDERERS = {
    'aql': AqlRenderer, 'spl': SplRenderer, 'kql': KqlRenderer,
    'esql': EsqlRenderer, 'dql': DqlRenderer, 'udm': UdmRenderer,
    'sumo': SumoRenderer, 'cef_search': CefRenderer, 'cql': CqlRenderer,
}


def escape_value(siem, value):
    """Foydalanuvchi qiymatini o'sha dialekt literali uchun qochiradi."""
    if siem not in DIALECTS:
        raise ValueError("Noma'lum SIEM: %s" % siem)
    cls = RENDERERS[DIALECTS[siem]['syntax']]
    dummy = {'id': '_', 'params': {}, 'select': [], 'attack': [], 'category': 'auth'}
    return cls(siem, dummy, {}).escape_inner(str(value))


def list_dialects():
    return DIALECTS


def get_hunt(hunt_id):
    if hunt_id not in HUNTS:
        raise ValueError("Noma'lum hunt: %s. Mavjudlari: %s"
                         % (hunt_id, ', '.join(sorted(HUNTS))))
    return HUNTS[hunt_id]


def list_hunts(category=None, search=None, siem=None):
    if category and category not in CATEGORIES:
        raise ValueError("Noma'lum kategoriya: %s. Mavjudlari: %s"
                         % (category, ', '.join(sorted(CATEGORIES))))
    if siem and siem not in DIALECTS:
        raise ValueError("Noma'lum SIEM: %s. Mavjudlari: %s"
                         % (siem, ', '.join(sorted(DIALECTS))))
    out = []
    for hunt in HUNTS.values():
        if category and hunt['category'] != category:
            continue
        if search:
            hay = ' '.join([hunt['id'], hunt['name'], hunt['description'],
                            ' '.join(hunt['attack'])]).lower()
            if search.lower() not in hay:
                continue
        out.append(hunt)
    return sorted(out, key=lambda h: (h['category'], h['id']))


def next_steps(siem, hunt):
    preset = DIALECTS[siem]['bk_preset']
    analyze = 'python bk.py logs analyze <eksport.csv>'
    if preset:
        analyze += ' --preset %s' % preset
    steps = [analyze, 'python bk.py ir chain <eksport.csv>']
    if hunt['category'] == 'network':
        steps.append('python bk.py hunt beacons <eksport.csv>')
    return steps


def build_query(hunt_id, siem, params=None):
    if siem not in DIALECTS:
        raise ValueError("Noma'lum SIEM: %s. Mavjudlari: %s"
                         % (siem, ', '.join(sorted(DIALECTS))))
    hunt = get_hunt(hunt_id)

    merged = dict(hunt.get('params', {}))
    for k, v in (params or {}).items():
        if v is not None:
            merged[k] = v

    dialect = DIALECTS[siem]
    renderer = RENDERERS[dialect['syntax']](siem, hunt, merged)
    query = renderer.render()

    notes = ['%s: %s' % (dialect['name'], dialect['where'])] + renderer.notes
    if hunt['category'] == 'network':
        notes.append("Davriy (beacon) tahlil uchun eksportni "
                     "`python bk.py hunt beacons <fayl>` ga bering — SIEM so'rovi "
                     "intervallarni o'zi hisoblay olmaydi.")

    return {
        'hunt_id': hunt['id'],
        'hunt_name': hunt['name'],
        'category': hunt['category'],
        'category_name': CATEGORIES[hunt['category']],
        'description': hunt['description'],
        'siem': siem,
        'siem_name': dialect['name'],
        'language': dialect['language'],
        'query': query,
        'select_fields': list(hunt.get('select', [])),
        'attack': list(hunt['attack']),
        'params': merged,
        'notes': notes,
        'tuning': hunt.get('tuning', ''),
        'next_steps': next_steps(siem, hunt),
    }
