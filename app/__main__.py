#!/usr/bin/env python3
from datetime import datetime
from os import mkdir
from aiohttp import web
from jinja2 import Environment, FileSystemLoader, select_autoescape

import logging
import sys

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

@routes.get('/')
async def index():
    pass

app = web.Application()
app.add_routes(routes)

web.run_app(app)
