import os, zipfile, hashlib, hmac, struct, logging, random, json
import urllib
import subprocess
import shutil
from io import BytesIO
from logging.handlers import SMTPHandler
from datetime import datetime, timedelta
from flask import Flask, request, g, render_template, make_response, redirect, url_for
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from pathlib import Path
from tempfile import mkdtemp

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

ROOTDIR = Path(app.root_path)
WILBRAND_EXE = ROOTDIR / "wilbrand"
WILBRAND_WRITEDIR = ROOTDIR / "rw"
BUNDLEBASE = ROOTDIR / "bundle"

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

def make_wilbrand_zip(our_dir, bundle):
    zipbuf = BytesIO()
    with zipfile.ZipFile(zipbuf, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, _, files, in os.walk(our_dir):
            for file in files:
                file_path = os.path.join(root, file)
                arcname = os.path.relpath(file_path, our_dir)
                zf.write(file_path, arcname)
        if bundle:
            for root, _, files in os.walk(BUNDLEBASE):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, BUNDLEBASE)
                    zf.write(file_path, arcname)
    return zipbuf


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

@app.route("/haxx", methods=["POST"])
@limiter.limit("3/minute")
def haxx():
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

    our_dir = mkdtemp(mac.hex(), None, WILBRAND_WRITEDIR)
    wilbrand_res = subprocess.run([WILBRAND_EXE.absolute(), mac.hex(), f"{timestamp:x}", template, our_dir])
    if wilbrand_res.returncode != 0:
        app.logger.error("wilbrand cli error %d. mac %s ts %s ver %s dir %s",
            wilbrand_res.returncode,
            mac.hex(),
            f"{timestamp:x}",
            template,
            our_dir,
        )
        return _index("Internal Error: {}. Try again.".format(wilbrand_res.returncode))
    zipdata = make_wilbrand_zip(our_dir, bundle)
    shutil.rmtree(our_dir)
    app.logger.info(
        "Wilbranded %s at %d ver %s bundle %r",
        mac.hex(),
        timestamp,
        request.form["region"],
        bundle,
    )

    rs = make_response(zipdata.getvalue())
    rs.headers.add("Content-Disposition", "attachment", filename="Wilbrand.zip")
    rs.headers["Content-Type"] = "application/zip"
    return rs


application = app

if __name__ == "__main__":
    app.run("0.0.0.0", 10142)
