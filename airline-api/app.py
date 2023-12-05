import psycopg2
from psycopg2 import sql
import psycopg2.extras

from fastapi import FastAPI, Request, HTTPException
from starlette.middleware.sessions import SessionMiddleware

import credentials

import hashlib
from dataclasses import dataclass

_connection = None


def get_conn():
  global _connection
  if not _connection:
    _connection = psycopg2.connect(
        dbname=credentials.dbname,
        user=credentials.user,
        password=credentials.password,
        host=credentials.host,
    )
    _connection.set_session(autocommit=True)
  return _connection


def get_cur():
  return get_conn().cursor(cursor_factory=psycopg2.extras.RealDictCursor)


app = FastAPI()


@dataclass
class SqlQuery:
  select_base: sql.SQL
  insert_base: sql.SQL
  params: any


def normalize_params(params):
  normal = []
  for param in params:
    if isinstance(param, tuple):
      normal.append((param[0], param[1]))
    else:
      normal.append((param, param))
  return normal


def get_op(op):
  return {
      'gt': '>',
      'gte': '>=',
      'eq': '=',
      'lt': '<',
      'lte': '<=',
  }.get(op, '=')


def format_field(field):
  if field[0] == field[1]:
    return sql.Identifier(field[0])

  as_ = sql.SQL('{field} as {field_as}')
  return as_.format(
      field=sql.Identifier(field[1]),
      field_as=sql.Identifier(field[0]),
  )


def build_select(table, params):
  base = sql.SQL('select {fields} from {table}')
  return base.format(
      table=sql.Identifier(table),
      fields=sql.SQL(', ').join([format_field(f) for f in params]))


def build_insert(table):
  return sql.SQL('insert into {table}').format(table=sql.Identifier(table))


def has_field(params, field):
  for param in params:
    if param[0] == field:
      return param
  return None


def build_colvals(params, kwargs, put_custom):
  cols = []
  vals = []
  for field in kwargs.keys():
    param = has_field(put_custom, field) or has_field(params, field)
    if param:
      cols.append(sql.Identifier(param[1]))
      vals.append(sql.Placeholder(param[0]))

  col_st = sql.SQL(', ').join(cols)
  val_st = sql.SQL(', ').join(vals)
  return sql.SQL(' ({}) values ({})').format(col_st, val_st)


def build_where(params, kwargs, get_custom=None):
  fields = []
  if get_custom is None:
    get_custom = {}

  comp = sql.SQL('{field} = {val}')
  for field in kwargs.keys():
    if field in get_custom:
      continue
    if has_field(params, field):
      fields.append(
          comp.format(
              field=sql.Identifier(field),
              val=sql.Placeholder(field),
          ))

  comp = sql.SQL('{field} {op} {val}')
  for field, op in get_custom.items():
    if field not in kwargs:
      continue
    fields.append(
        comp.format(
            field=sql.Identifier(field),
            op=sql.SQL(op),
            val=sql.Placeholder(field),
        ))

  if not fields:
    return ''

  return sql.Composed([sql.SQL(' where '), sql.SQL(' and ').join(fields)])


def build_sql(*params, table):
  params = normalize_params(params)

  return SqlQuery(
      build_select(table, params),
      build_insert(table),
      params,
  )


def run_fetch_raw(query, kwargs):
  with get_cur() as cur:
    cur.execute(query, kwargs)
    return cur.fetchall()


def run_query_raw(query, kwargs):
  with get_cur() as cur:
    cur.execute(query, kwargs)


def run_get(sqlo, kwargs, get_custom=None):
  _where = build_where(sqlo.params, kwargs, get_custom)
  if _where:
    query = sql.Composed([sqlo.select_base, _where])
  else:
    query = sqlo.select_base
  return run_fetch_raw(query, kwargs)


def run_insert(sqlo, kwargs, put_custom=None):
  put_custom = put_custom or []
  _colvals = build_colvals(sqlo.params, kwargs, put_custom)
  query = sql.Composed([sqlo.insert_base, _colvals])
  return run_query_raw(query, kwargs)


def make_path(path, sql):
  async def f(req: Request):
    return run_get(sql, dict(req.query_params))

  app.get(path)(f)


def get_staff(req, err=True):
  staff_user = req.session.get('staff_user', None)
  if not staff_user and err:
    raise HTTPException(status_code=401)
  return staff_user


def get_user(req, err=True):
  user_email = req.session.get('user_email', None)
  if not user_email and err:
    raise HTTPException(status_code=401)
  return user_email


customer_query = build_sql('email', 'firstname', 'lastname', 'streetname',
                           'zipcode', 'apartment', 'city', ('state', 'state_'),
                           table='customer')


@app.get('/api/customer')
async def customer_get(req: Request):
  if get_staff(req, False):
    return run_get(customer_query, dict(req.query_params))

  user_email = get_user(req)
  return run_get(customer_query, {'email': user_email})[0]


@app.put('/api/customer')
async def customer_put(req: Request, email: str, password: str):
  kwargs = dict(req.query_params)
  kwargs['password'] = hashlib.md5(password.encode()).hexdigest()
  return run_insert(customer_query, kwargs, [('password', 'password_')])


airline_query = build_sql('airlinename', table='airline')


@app.get('/api/airline')
async def airline_get(req: Request):
  return run_get(airline_query, {})


make_path(
    '/api/airline',
    build_sql('airlinename', table='airline'),
)

userlogin_query = build_sql(
    'email',
    ('pass', 'password_'),
    table='customer',
)


@app.get('/api/userlogin')
@app.post('/api/userlogin')
async def userlogin(req: Request, email: str, password: str):
  result = run_get(userlogin_query, {'email': email})
  if result:
    result = result[0]
    password = hashlib.md5(password.encode()).hexdigest()
    if password == result['pass']:
      req.session['is_user'] = True
      req.session['user_email'] = result['email']
      return
    else:
      raise HTTPException(status_code=401, detail='Invalid password')
  else:
    raise HTTPException(status_code=401, detail='No such user')


stafflogin_query = build_sql(
    'username',
    ('pass', 'password_'),
    table='airlinestaff',
)


@app.get('/api/stafflogin')
@app.post('/api/stafflogin')
async def stafflogin(req: Request, username: str, password: str):
  result = run_get(stafflogin_query, {'username': username})
  if result:
    result = result[0]
    password = hashlib.md5(password.encode()).hexdigest()
    if password == result['pass']:
      req.session['is_staff'] = True
      req.session['staff_user'] = result['username']
      return
    else:
      raise HTTPException(status_code=401, detail='Invalid password')
  else:
    raise HTTPException(status_code=401, detail='No such user')


@app.get('/api/staffphone')
async def staffphone_get(req: Request):
  staff_user = get_staff(req)
  result = run_fetch_raw(
      'select phonenumber from staffphone where username = %s',
      [staff_user],
  )
  return [d['phonenumber'] for d in result]


@app.delete('/api/staffphone')
async def staffphone_del(req: Request, phonenumber: str):
  staff_user = get_staff(req)
  run_fetch_raw(
      'delete from staffphone where username = %s and phonenumber = %s',
      [staff_user, phonenumber])


@app.put('/api/staffphone')
async def staffphone_put(req: Request, phonenumber: str):
  staff_user = get_staff(req)
  run_fetch_raw(
      'insert into staffphone (username, phonenumber) values (%s, %s)',
      [staff_user, phonenumber])


@app.get('/api/staffemail')
async def staffphone(req: Request):
  staff_user = get_staff(req)
  result = run_fetch_raw(
      'select email from staffemail where username = %s',
      [staff_user],
  )
  return [d['email'] for d in result]


@app.delete('/api/staffemail')
async def staffemail_del(req: Request, email: str):
  staff_user = get_staff(req)
  run_fetch_raw('delete from staffemail where username = %s and email = %s',
                [staff_user, email])


@app.put('/api/staffemail')
async def staffemail_put(req: Request, email: str):
  staff_user = get_staff(req)
  run_fetch_raw('insert into staffemail (username, email) values (%s, %s)',
                [staff_user, email])


@app.get('/api/logout')
@app.post('/api/logout')
async def logout(req: Request):
  req.session['is_user'] = False
  req.session['user_email'] = None
  req.session['is_staff'] = False
  req.session['staff_user'] = None


flight_query = build_sql('flightnumber', 'departuredatetime', 'airlinename',
                         'airlineplanenumber', 'departureairport',
                         'arrivalairport', 'arrivaldatetime',
                         'ticketbaseprice', ('status', 'status_'),
                         table='flight')


@app.get('/api/flight')
async def flight(req: Request):
  kwargs = dict(req.query_params)
  arrival_op = get_op(kwargs.get('arrivaldatetime_op', 'eq'))
  depart_op = get_op(kwargs.get('departuredatetime_op', 'eq'))
  get_custom = {'arrivaldatetime': arrival_op, 'departuredatetime': depart_op}
  return run_get(flight_query, kwargs, get_custom=get_custom)


ticket_query = build_sql('ticketid', 'flightnumber', 'departuredatetime',
                         'airlinename', 'email', 'firstname', 'lastname',
                         'calculatedprice', 'purchasedatetime', table='ticket')


@app.get('/api/ticket')
async def ticket(req: Request):
  user_email = req.session.get('user_email', None)
  is_staff = req.session.get('is_staff', False)

  print(is_staff)

  kwargs = dict(req.query_params)
  depart_op = get_op(kwargs.get('departuredatetime_op', 'eq'))
  purchase_op = get_op(kwargs.get('purchasedatetime_op', 'eq'))
  custom = {'departuredatetime': depart_op, 'purchasedatetime': purchase_op}

  if is_staff:
    return run_get(ticket_query, kwargs, custom)

  if user_email:
    kwargs['email'] = user_email
    return run_get(ticket_query, kwargs, custom)

  raise HTTPException(status_code=401)


app.add_middleware(SessionMiddleware, secret_key='most-secret')
