#!/usr/bin/env python3
from datetime import datetime
from os import mkdir
from aiohttp import web
from jinja2 import Environment, FileSystemLoader, select_autoescape
import json
from uuid import UUID
import logging
import sys
import re

from elections import Backend, ElectionType

"""
jinja stuff
"""
jinja_env = Environment(
    loader=FileSystemLoader('templates'),
    autoescape=select_autoescape()
)

"""
logging stuff
"""

try:
    mkdir('.logs')
except FileExistsError:
    pass

fp = f'./.logs/{datetime.now()}.log'.replace(' ', '-')

if sys.platform.lower() == 'win32':
    # Windows is dumb as fuck and for some reason doesn't support colons
    fp = fp.replace(':', '.')

backend = None
logger = logging.getLogger()

logger.setLevel(logging.DEBUG)

fh = logging.FileHandler(fp)
fh.setLevel(logging.DEBUG)

ch = logging.StreamHandler()
ch.setLevel(logging.INFO)

fmt = logging.Formatter('[%(asctime)s] [%(name)s] [%(levelname)s] : %(message)s')

ch.setFormatter(fmt)
fh.setFormatter(fmt)

logger.addHandler(ch)
logger.addHandler(fh)


routes = web.RouteTableDef()

unprotected_routes = re.compile("^\/(files\/(.*\.css|.*\.js)$|login$|style.css$|register$|favicon\.ico$|ballots\/[A-Za-z0-9_-]{107}($|\/vote$))")



@routes.get('/login')
async def login(request):
    data = request.query
    if 'username' not in data and 'password' not in data:
        template = jinja_env.get_template('login.html')
        return web.Response(text=template.render(), content_type="HTML")
    try:
        token = backend.login(data['username'], data['password'])
    except:
        token = ""
    resp = web.Response(status=302, headers={"Location":"/"})
    resp.set_cookie('token', token)
    return resp

@routes.get('/register')
async def register(request):
    data = request.query
    if 'username' not in data and 'password' not in data:
        template = jinja_env.get_template('register.html')
        return web.Response(text=template.render(), content_type="HTML")

    token = backend.add_account(data['username'], data['password'])
    resp = web.Response(status=302, headers={"Location": "/"})
    resp.set_cookie('token', token)
    return resp

@routes.get('/ballots/{endpoint:[A-Za-z0-9_-]{107}}')
async def get_ballot(request):
    endpoint = request.match_info["endpoint"]
    ballot = backend.get_ballot_from_endpoint(endpoint)
    template = jinja_env.get_template(('ballot.html' if not ballot.voted else 'voted.html') if not ballot.election.closed else 'closed.html')
    return web.Response(text=template.render(ballot=ballot), content_type="HTML")

@routes.post('/ballots/{endpoint:[A-Za-z0-9_-]{107}}/vote')
async def vote(request):
    endpoint = request.match_info["endpoint"]
    ballot = backend.get_ballot_from_endpoint(endpoint)
    data = await request.json()
    try:
        ballot.vote(data)
    except:
        raise web.HTTPForbidden()
    raise web.HTTPOk()
    

@routes.get('/elections')
async def elections(request):
   elections = backend.get_elections(request['account'])
   template = jinja_env.get_template('elections.html')
   resp = web.Response(text=template.render(elections=elections), content_type="HTML")
   return resp

@routes.get('/elections/create')
async def get_create_election(request):
    data = request.query
    if not {"name", "type", "candidates_list", "email_list", "required_seats"}.issubset(set(data.keys())):
        template = jinja_env.get_template('create_election.html')
        return web.Response(text=template.render(), content_type="HTML")
    candidates_list = [i.strip('\n') for i in data["candidates_list"].split(",") if i.strip('\n') != '']
    email_list = data["email_list"].split(",")
    election_type = ElectionType[data["type"]]
    backend.create_election(request['account'], data["name"], election_type, candidates_list, email_list, int(data["required_seats"]))
    resp = web.Response(status=302, headers={"Location": "/elections"})
    return resp

@routes.get('/')
async def index(request):
    template = jinja_env.get_template('index.html')
    return web.Response(text=template.render(), content_type="HTML")


@routes.get('/files/{path:.*\..*}')
async def get_file(request):
    try:
        path = request.match_info["path"]
        template = jinja_env.get_template(path if path != "" else "index.html")
    except Exception as e:
        raise web.HTTPNotFound()
    split_path = path.split(".")
    extension = split_path[len(split_path)-1]
    content_type = {"html": "HTML", "css": "text/css", "js": "text/javascript"}[extension.lower()]
    return web.Response(text=template.render(), content_type=content_type)

@routes.get('/elections/{uuid:[0-9a-z]{8}-[0-9a-z]{4}-4[0-9a-z]{3}-[0-9a-z]{4}-[0-9a-z]{12}$}')
async def get_election(request):
    election_id = UUID(request.match_info["uuid"])
    election = backend.get_election(election_id)
    if election is None:
        raise web.HTTPNotFound()
    if election.owner != request["account"]:
        raise web.HTTPUnauthorized()
    template = jinja_env.get_template("election.html")
    return web.Response(text=template.render(election=election, results=backend.generate_results(election)), content_type="HTML")


@routes.post('/elections/{uuid:[0-9a-z]{8}-[0-9a-z]{4}-4[0-9a-z]{3}-[0-9a-z]{4}-[0-9a-z]{12}}/close')
async def close_election(request):
    election_id = UUID(request.match_info["uuid"])
    election = backend.get_election(election_id)
    if election is None:
        raise web.HTTPNotFound()
    if election.owner != request["account"]:
        raise web.HTTPUnauthorized()
    election.closed = True
    backend.session.commit()
    raise web.HTTPOk()

@web.middleware
async def request_logger(request: web.Request, handler):
    logger.info(f'{request.remote} {request.method} {request.url}')
    return await handler(request)

@web.middleware
async def authenticate(request: web.Request, handler):
    if unprotected_routes.match(request.rel_url.raw_path):
        return await handler(request)
    if 'token' not in request.cookies.keys():
        raise web.HTTPFound('/login')
    
    token = request.cookies["token"]
    try: 
        request["account"] = backend.get_account_from_token(token)
    except:
        raise web.HTTPFound('/login')

    resp = await handler(request)
    resp.set_cookie('token', token)
    return resp

    

if __name__ == '__main__':
    app = web.Application(middlewares=[request_logger, authenticate])
    app.add_routes(routes)
    backend = Backend(**json.load(open("config.json")))
    web.run_app(app, port=8000)

