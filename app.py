import os.path
import tornado.httpserver
import tornado.ioloop
import tornado.web
import tornado.auth
import tornadio2
import pymongo
import hashlib

from tornado.options import define, options
from tornado.escape import json_encode, json_decode
from tornado.web import HTTPError

define("address", default="", help="run on the given address", type=str)
define("port", default=8080, help="run on the given port", type=int)
define("debug", default=1, help="debug mode", type=int)

class Application(tornado.web.Application):
    def __init__(self):
        conn = pymongo.Connection("localhost", 27017)
        self.db = conn['triangle']

        if options.debug == 0:
            options.debug = False
        else:
            options.debug = True

        # Will need login_url for settings
        settings = dict(
            template_path = os.path.join(os.path.dirname(__file__), "templates"),
            static_path = os.path.join(os.path.dirname(__file__), "static"),
            cookie_secret = 'NTliOTY5NzJkYTVlMTU0OTAwMTdlNjgzMTA5M2U3OGQ5NDIxZmU3Mg==',
            socket_io_port = options.port,
            socket_io_address = options.address,
            login_url = "/auth/login",
            debug = options.debug
        )

        handlers = [
            (r"/", IndexHandler),
            (r"/philanthropy", PhilanthropyHandler),
            (r"/auth/login", LoginHandler),
            (r"/auth/logout", LogoutHandler),
            (r"/content/([-\w]+)", ContentHandler),

            # Favicon
            (r"/favicon.ico", tornado.web.StaticFileHandler, dict(path=settings['static_path'])),

            # Robots.txt
            (r"/robots.txt", tornado.web.StaticFileHandler, dict(path=settings['static_path'])),
        ]

        tornado.web.Application.__init__(self, handlers, **settings)

class BaseHandler(tornado.web.RequestHandler):
    def get_current_user(self):
        coll = self.application.db["users"]
        return coll.find_one({"handle": self.get_secure_cookie("user")}) or {}

class LoginHandler(BaseHandler):
    def get(self):
        # If user is logged in go to index, otherwise display login
        if not self.get_current_user():
            self.render("login.html")
        else:
            self.redirect("/")

    def post(self):
        redirect_url = self.get_argument('redirect', '/')
        username = self.get_argument('username', '')
        password = self.get_argument('password', '')
        password_hash = hashlib.sha1(password).hexdigest()
        coll = self.application.db["users"]
        results = coll.find({"handle": username, "password": password_hash})

        if results.count() == 1:
            self.set_secure_cookie('user', username)
            self.redirect(redirect_url)
        else:
            self.redirect("/auth/login?error=failed")

class LogoutHandler(BaseHandler):
    def get(self):
        self.clear_all_cookies()
        self.redirect("/")

class IndexHandler(BaseHandler):
    def get(self):
        u = self.get_current_user()
        self.render("index.html", user=u.get("handle", None))

class PhilanthropyHandler(BaseHandler):
    def get(self):
        u = self.get_current_user()
        self.render("philanthropy.html", user=u.get("handle", None))

class ContentHandler(BaseHandler):
    def get(self, what):
        u = self.get_current_user()

        coll = self.application.db["content"]
        doc = coll.find_one({"name": what})
        if doc:
            if doc["private"] != 0 and not u:
                raise HTTPError(401)
            self.write({"result": doc["content"]})
        else:
            raise HTTPError(404)

    def post(self, what):
        u = self.get_current_user()
        if not u or not u["superuser"]:
            raise HTTPError(403)

        content = self.get_argument("content")
        private = self.get_argument("private", 0)
        coll = self.application.db["content"]
        doc = coll.find_one({"name": what})
        if not doc:
            doc = {"name": what, "content": content, "private": private}
            coll.save(doc)
        else:
            print content
            doc["content"] = content
            doc["private"] = private
            coll.save(doc)

        self.write({"result": doc["content"]})

def main():
    tornado.options.parse_command_line()
    application = Application()
    tornadio2.server.SocketServer(application)

if __name__ == "__main__":
    main()

