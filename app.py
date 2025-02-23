import os, zipfile, hashlib, hmac, struct, logging, random, json
import urllib
from io import BytesIO
from logging.handlers import SMTPHandler
from datetime import datetime, timedelta
from flask import Flask, request, g, render_template, make_response, redirect, url_for
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

COUNT_CACHE_AGE = 60
counter_cache = (datetime(1999, 1, 1), -1)

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1)
app.config.from_object("config")

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[],
    storage_uri="memory://",
)

BUNDLEBASE = os.path.join(app.root_path, "bundle")

class RequestFormatter(logging.Formatter):
    def format(self, record):
        s = logging.Formatter.format(self, record)
        try:
            return (
                "[%s] [%s] [%s %s] "
                % (
                    self.formatTime(record),
                    request.remote_addr,
                    request.method,
                    request.path,
                )
                + s
            )
        except:
            return "[%s] [SYS] " % self.formatTime(record) + s


if not app.debug:
    handler = logging.FileHandler(os.path.join(app.root_path, "log", "info.log"))
    handler.setLevel(logging.INFO)
    handler.setFormatter(RequestFormatter())
    app.logger.addHandler(handler)

    app.logger.setLevel(logging.INFO)
    app.logger.warning("Starting...")


def count_unique_wilbrands(path="./log/info.log"):
    global counter_cache
    if (datetime.now() - counter_cache[0]).total_seconds() < COUNT_CACHE_AGE:
        return counter_cache[1]
    res = []
    with open(path) as logfile:
        for line in logfile.readlines():
            try:
                loc = line.find("Wilbranded")
                if loc == -1:
                    continue
                mac = line[loc:].split(" ")[1]
                res.append(mac)
            except:
                pass
    res = len(set(res))
    counter_cache = (datetime.now(), res)
    return res


def _index(error=None):
    rs = make_response(
        render_template("index.html", region="U", error=error, num_lb=count_unique_wilbrands())
    )
    rs.headers["Expires"] = "Thu, 01 Dec 1983 20:00:00 GMT"
    return rs


@app.route("/")
@limiter.limit("100/minute")
def index():
    return _index()

from pprint import pprint
@app.route("/haxx", methods=["POST"])
@limiter.limit("3/minute")
def haxx():
    pprint(request.environ)
    pprint(request.form)
    OUI_LIST = [
        bytes.fromhex(i)
        for i in open(os.path.join(app.root_path, "oui_list.txt")).read().split("\n")
        if len(i) == 6
    ]
    dt = datetime.utcnow() - timedelta(1)
    delta = dt - datetime(2000, 1, 1)
    timestamp = delta.days * 86400 + delta.seconds
    try:
        mac = bytes((int(request.form[i], 16)) for i in "abcdef")
        template = "{}{}".format(request.form["version"], request.form["region"])
        bundle = "bundle" in request.form
    except:
        return _index("Invalid input.")

    if mac == b"\x00\x17\xab\x99\x99\x99":
        app.logger.info(
            "Derp MAC %s at %d ver %s bundle %r",
            mac.hex(),
            timestamp,
            request.form["region"],
            bundle,
        )
        return _index("If you're using Dolphin, try File->Open instead ;-).")

    if not any([mac.startswith(i) for i in OUI_LIST]):
        app.logger.info(
            "Bad MAC %s at %d ver %s bundle %r",
            mac.hex(),
            timestamp,
            request.form["region"],
            bundle,
        )
        return _index("The exploit will only work if you enter your Wii's MAC address.")


    app.logger.info(
        "Wilbranded %s at %d ver %s bundle %r",
        mac.hex(),
        timestamp,
        request.form["region"],
        bundle,
    )

    #rs = make_response(zipdata.getvalue())
    #zipdata.close()
    #rs.headers.add("Content-Disposition", "attachment", filename="LetterBomb.zip")
    #rs.headers["Content-Type"] = "application/zip"
    #return rs
    return _index("TODO: run wilbrand")


application = app

if __name__ == "__main__":
    app.run("0.0.0.0", 10142)
