from sys import stderr
import requests
from pyquery import PyQuery as PyQuery_orig
from urllib.parse import urljoin
from prettytable import PrettyTable
import json
from datetime import datetime
import time
import calendar
from collections import defaultdict
from progressbar import ProgressBar
from pathlib import Path


try:
	import keyring
except ImportError:
	print('''To avoid having to enter your password every time you use auprint
install the python keyring module using `pip install keyring`.''', file=stderr)
	keyring = None


class LocalAuth:
	def __init__(self, filename):
		self.filename = filename
		try:
			with open(filename) as f:
				self.username = f.read().strip()
		except IOError:
			self.username = None

		if keyring:
			self.password = keyring.get_password('auprint', 'auid')
		else:
			self.password = None

	def __setattr__(self, key, value):
		super().__setattr__(key, value)

		if key == 'username':
			try:
				if value == None:
					Path(self.filename).unlink()
				else:
					with open(self.filename, 'w') as f:
						f.write(self.username)
			except IOError:
				pass
		elif key == 'password':
			if not keyring:
				return

			if value == None:
				try:
					keyring.delete_password('auprint', 'auid')
				except keyring.errors.PasswordDeleteError:
					pass
			else:
				keyring.set_password('auprint', 'auid', value)


def PyQuery(*args, **kwargs):
    if 'parser' not in kwargs:
        kwargs['parser'] = 'html'

    return PyQuery_orig(*args, **kwargs)


def meta_refresh_url(response):
    dom = PyQuery(response)
    meta = dom('meta[http-equiv="refresh"]')
    if meta:
        content = meta.attr('content')
        if content:
            parts = content.split(';url=', 1)
            if len(parts) == 2:
                return parts[1]

    return None


def submit_form(form, current_url, input_fields={}, session=requests):
    action = form.attr('action') or ''
    method = (form.attr('method') or 'GET').upper()

    if method not in ['GET', 'POST']:
        raise Exception('Only GET and POST supported')

    url = urljoin(current_url, action)
    fields = {}

    for el in form('input'):
        input = PyQuery(el)
        name = input.attr('name')
        if name != None:
            fields[name] = input.attr('value') or ''

    fields.update(input_fields)

    return session.request(method, url, **{'params' if method == 'GET' else 'data': fields})


class AUAuthenticationError(Exception):
    pass


class InvalidCredentialsError(AUAuthenticationError):
    pass


def login(username, password):
    username = str(username)
    session = requests.Session()

    r = session.get('https://stadssb.au.dk/sb_STAP/sb/')

    next_url = meta_refresh_url(r.content)
    r = session.get(next_url)

    form_url = r.url
    form = PyQuery(r.content)('form[name="f"]')
    r = submit_form(form, form_url, {'username': username, 'password': password}, session)

    for i in range(2):
        form = PyQuery(r.content)('form')
        if not form('input[name="SAMLResponse"]'):
            alert = PyQuery(r.content)('.alert')
            if 'Forkert brugernavn eller kodeord' in alert.text():
                raise InvalidCredentialsError('Invalid username or password')
            else:
                raise AUAuthenticationError('Unknown error: %s' % alert.text())

        r = submit_form(form, r.url, {}, session)

    return session


def try_int(s):
    try:
        return int(s)
    except ValueError:
        return s


def date_to_int(s):
    parts = s.split('.')
    dt = datetime(*map(int, reversed(parts)))
    return calendar.timegm(dt.utctimetuple())


def int_to_date(t):
    ts = time.gmtime(t)
    return time.strftime('%Y-%m-%d', ts)


def get_results(session, show_progress=False):
    r = session.get('https://sbstads.au.dk/sb_STAP/sb/resultater/studresultater.jsp')

    table = PyQuery(r.content)('#resultTable')

    key_dict = {
        'Afdeling/område': 'department',
        'Kode': 'code',
        'Aktivitet': 'course',
        'ECTS': ('ects', int),
        'Bedømmelsesdato': ('evaluation_date', date_to_int),
        'Registreret': ('publication_date', date_to_int),
        'Karakter': ('grade', try_int),
        'ECTS-kar.': 'ects_grade',
        # 'Censurform': 'eval_type',
        'Bedømmelsesform': 'grading_system',
        'Prøveform': 'exam_type',
        'Eksamen aflagt på': 'exam_language'
    }

    data = []
    total_exams = len(table('tbody')('tr'))

    wrapper = ProgressBar() if show_progress else (lambda x: x)

    for i in wrapper(range(total_exams)):
        info = {}

        r1 = session.get(f'https://sbstads.au.dk/sb_STAP/sb/resultater/studresdetaljer.jsp?id={i}&returnmethod=genopfrisk')

        doc1 = PyQuery(r1.content)

        keys = [PyQuery(el).text().strip() for el in doc1('table:nth-of-type(2) tr .UVDetailLedeText')]
        values = [PyQuery(el).text().strip() for el in doc1('table:nth-of-type(2) tr .DetailValue')]

        for k, v in zip(keys, values):
            if k in key_dict:
                trans = key_dict[k]
                if isinstance(trans, tuple):
                    info[trans[0]] = trans[1](v)
                else:
                    info[trans] = v

        r2 = session.get(f'https://sbstads.au.dk/sb_STAP/sb/resultater/visStatistik.jsp?id={i}&returnmethod=genopfrisk')

        doc2 = PyQuery(r2.content)

        grade_keys = []

        grade_key_row = doc2('table table tr').eq(-1)
        for el in grade_key_row('td')[1:-1]:
            k = PyQuery(el).text().strip()
            try:
                k = int(k)
            except ValueError:
                pass
            grade_keys.append(k)

        grade_distribution = []
        for k, el in zip(grade_keys, doc2('img[src$="graapix.gif"]')):
            grade_distribution.append((k, int(el.attrib['title'].split()[0])))

        info['grade_distribution'] = grade_distribution
        info['total_examined'] = sum(g[1] for g in grade_distribution)

        data.append(info)

    return data


def average_grade(results):
    tot = 0
    d = defaultdict(complex)
    for r in results:
        v = r['grade']
        if not isinstance(v, int):
            continue

        w = r['ects']
        t = r['department']

        c = v * w + w * 1j
        d[t] += c
        tot += c

    if tot.imag == 0:
        return None

    return tot.real / tot.imag
    # return (tot.real / tot.imag, {k: v.real / v.imag for k, v in d.items()})


def pretty_results(results):
    keys = ['course', 'evaluation_date', 'ects', 'grade', 'top_percentage']
    table = PrettyTable(keys)
    table.align['course'] = 'l'
    table.align['ects'] = 'r'
    table.align['grade'] = 'r'
    table.align['top_percentage'] = 'r'

    for r in results:
        row = []
        for k in keys:
            if k == 'top_percentage':
                grade = r['grade']
                if isinstance(grade, int):
                    grade_distribution = r['grade_distribution']
                    atleast_as_good = sum(v for k, v in grade_distribution if k >= grade)
                    better = sum(v for k, v in grade_distribution if k > grade)
                    v = '%.1f  -  %4.1f' % (better / r['total_examined'] * 100, atleast_as_good / r['total_examined'] * 100)
                else:
                    v = ''
            elif k == 'evaluation_date':
                v = int_to_date(r[k])
            else:
                v = r[k]
            row.append(v)

        table.add_row(row)

    return table.get_string()


def plot_average(results):
    import matplotlib.pyplot as plt
    fig, ax = plt.subplots()

    QUARTERS = {
        10: 1,
        11: 1,
        1: 2,
        2: 2,
        3: 3,
        4: 3,
        6: 4,
    }

    values = {}
    grades = defaultdict(list)

    value = 0
    weight = 0

    first_year = None
    for r in results[::-1]:
        grade = r['grade']
        if not isinstance(grade, int):
            continue

        value += grade * r['ects']
        weight += r['ects']

        d = time.gmtime(r['evaluation_date'])
        q = QUARTERS[d.tm_mon]
        if not first_year:
            first_year = d.tm_year

        uni_year = d.tm_year - first_year + (1 if q <= 1 else 0)

        period = uni_year * 4 + q
        values[period] = value / weight

        grades[period].append(grade)

    l = sorted(values.items())
    xs = [p[0] for p in l]
    ys = [p[1] for p in l]

    min_x = min(xs)
    def format_coord(x, y):
        period = int(round(x))
        p = period
        while True:
            val = values.get(p)
            if val or period == min_x:
                break

            p -= 1

        if val:
            val = round(val, 2)
        else:
            val = '-'

        return 'Q%s: %s, %s' % (period, val, grades[period])

    ax.plot(xs, ys, '-o')
    ax.format_coord = format_coord

    plt.show(fig)


if __name__ == '__main__':
    import sys
    from getpass import getpass

    actions = ['update', 'show']

    if len(sys.argv) != 2 or sys.argv[1] not in actions:
        print('Usage: python %s update|show' % sys.argv[0], file=sys.stderr)
        sys.exit(1)

    action = sys.argv[1]

    if action == 'update':
        auth = LocalAuth('auid.txt')

        logged_in = False
        while not logged_in:
            while not auth.username:
                auth.username = input('AUID: ').strip()
                if not auth.username.startswith('au'):
                    auth.username = None

            while not auth.password:
                auth.password = getpass('AU password: ').strip()

            try:
                print('Logging in...')
                session = login(auth.username, auth.password)
                logged_in = True
            except AUAuthenticationError:
                print('Invalid auid/password combination')
                auth.username = None
                auth.password = None

        print('Fetching results...')
        results = get_results(session, show_progress=True)

        with open('results.json', 'w') as f:
            json.dump(results, f)
    elif action == 'show':
        with open('results.json') as f:
            results = json.load(f)

        print(pretty_results(results[::-1]))

        plot_average(results)

