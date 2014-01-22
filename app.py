import os.path
import tornado.httpserver
import tornado.ioloop
import tornado.web
import tornado.auth
import tornadio2
import pymongo
import hashlib
import random
from datetime import datetime

import smtplib
from email.MIMEText import MIMEText

from tornado.options import define, options
from tornado.escape import json_encode, json_decode
from tornado.web import HTTPError

define("address", default="", help="run on the given address", type=str)
define("port", default=8080, help="run on the given port", type=int)
define("debug", default=1, help="debug mode", type=int)

def tod(hour):
    # Convert hour [0..23] to 'morning', 'afternoon', or 'evening'
    if hour < 12:
        return 'morning'
    elif hour < 17:
        return 'afternoon'
    else:
        return 'evening'

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
            (r"/invite", InviteHandler),
            (r"/grant", GrantHandler),
            (r"/register", RegisterHandler),
            (r"/philanthropy", PhilanthropyHandler),
            (r"/scholarship", ScholarshipHandler),
            (r"/scholarship/apply", ScholarshipApplyHandler),
            (r"/scholarship/view", ScholarshipViewHandler),
            (r"/rush", RushHandler),
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
        if not self.get_secure_cookie("user"):
            return {}
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

class RushHandler(BaseHandler):
    def get(self):
        u = self.get_current_user()
        self.render("rush-public.html", user=u.get("handle", None))

class InviteHandler(BaseHandler):
    def get(self):
        u = self.get_current_user()
        if u and u['superuser']:
            self.render("invite.html")
        else:
            self.redirect('/')

    def post(self):
        u = self.get_current_user()
        if not u or not u['superuser']:
            raise HTTPError(403)

        username = self.get_argument("username")
        regcode = ''.join(random.choice("abcdefghijklmnopqrstuvwxyz0123456789") for i in range(20))
        coll = self.application.db["invitations"]
        coll.save({"regcode": regcode, "username": username})

        self.redirect("/register?regcode=%s&username=%s" % (regcode, username))

class GrantHandler(BaseHandler):
    def get(self):
        u = self.get_current_user()
        if u and u['superuser']:
            self.render("grant.html")
        else:
            self.redirect('/')

    def post(self):
        u = self.get_current_user()
        if not u or not u['superuser']:
            raise HTTPError(403)

        username = self.get_argument("username")
        coll = self.application.db["users"]
        result = coll.find_one({"handle": username})

        if result is None:
            raise HTTPError(404)

        result["superuser"] = 1
        coll.save(result)

        self.redirect('/')

class RegisterHandler(BaseHandler):
    def get(self):
        self.render("register.html")

    def post(self):
        username = self.get_argument("username", '')
        regcode = self.get_argument("regcode", '')
        password = self.get_argument("password", '')
        password2 = self.get_argument("password2", '')

        # Check that the regcode exists and matches the username assigned to it
        coll = self.application.db["invitations"]
        result = coll.find_one({"regcode": regcode, "username": username})

        if result is None:
            self.redirect("/register?regcode=%s&username=%s&error=noreg" % (regcode, username))
            return

        if len(password) < 5:
            self.redirect("/register?regcode=%s&username=%s&error=shortpass" % (regcode, username))
            return

        if password != password2:
            self.redirect("/register?regcode=%s&username=%s&error=passmatch" % (regcode, username))
            return

        # Passed all the reqs, create the user
        new_user = {"handle": username, "password": hashlib.sha1(password).hexdigest(), "superuser": 0}
        self.application.db["users"].save(new_user)
        coll.remove(result)

        self.redirect('/auth/login')

class PhilanthropyHandler(BaseHandler):
    def get(self):
        u = self.get_current_user()
        self.render("philanthropy.html", user=u.get("handle", None))

class ScholarshipHandler(BaseHandler):
    def get(self):
        u = self.get_current_user()
        self.render("scholarship.html", user=u.get("handle", None))

# TODO: in general, why is the tornado templating engine so fragile? Can there be ignore KeyErrors and more properties of None?

class ScholarshipViewHandler(BaseHandler):
    def get(self):
        u = self.get_current_user()
        if not u:
            raise HTTPError(403)

        # Get all scholarships
        exclude_params = ['extracurricular', 'awards', 'workexperience', 'interests', 'personalstatement', 'legacy']
        exclude_dict = {}
        for p in exclude_params:
            exclude_dict[p] = False
        scholarships = self.application.db["scholarships"].find(fields=exclude_dict)

        self.render("scholarship-view.html", user=u.get("handle", None), superuser=u.get("superuser", False), scholarships=scholarships)

class ScholarshipApplyHandler(BaseHandler):
    def delete(self):
        u = self.get_current_user()
        application_id = self.get_argument('application_id', None)
        coll = self.application.db["scholarships"]

        if not u or not u['superuser']:
            raise HTTPError(403)

        if not (len(application_id) == 6 or len(application_id) == 11):
            raise HTTPError(400)

        coll.remove({"application_id": application_id})
        self.write(json_encode({"error": "ok"}))
        self.finish()

    def put(self):
        # TODO: Lol, totally hijacked REST. Anyways the PUT functionality allows one to change the application state.
        u = self.get_current_user()
        application_id = self.get_argument('application_id')
        application_status = self.get_argument('application_status', '')

        if not u or not u['superuser']:
            raise HTTPError(403)

        coll = self.application.db["scholarships"]
        doc = coll.find_one({"application_id": application_id})

        if doc is None:
            raise HTTPError(404)

        doc["status"] = application_status
        coll.save(doc)
        self.write(json_encode({"error": "ok"}))
        self.finish()

    def get(self):
        u = self.get_current_user()
        application_id = self.get_argument('application_id', None)
        form_req_params = ['fullname', 'dob', 'email', 'phonenumber', 'address', 
                           'citystate', 'country', 'highschool', 'hscity', 'hsgpa', 
                           'hsrank', 'uiucmajor', 'extracurricular', 'awards',
                           'workexperience', 'interests', 'personalstatement',
                           'legacy']
        doc = dict((k, "") for k in form_req_params)
        doc["application_id"] = ""

        if application_id is not None:
            coll = self.application.db["scholarships"]
            doc = coll.find_one({"application_id": application_id})

        self.render("scholarship-apply.html", user=u.get("handle", None), form_data=doc, error=None)

    def post(self):
        u = self.get_current_user()
        action = self.get_argument('action', None)
        application_id = self.get_argument('application_id', None)
        coll = self.application.db["scholarships"]

        if application_id and len(application_id) == 0:
            application_id = None

        if action not in ['save', 'submit']:
            raise HTTPError(400)    # User cannot trigger this in normal usage

        # Save/submit application -- give ID if needed.
        form_req_params = ['fullname', 'dob', 'email', 'phonenumber', 'address', 
                           'citystate', 'country', 'highschool', 'hscity', 'hsgpa', 
                           'hsrank', 'uiucmajor', 'extracurricular', 'awards',
                           'workexperience', 'interests', 'personalstatement',
                           'legacy']
        doc = dict((k, "") for k in form_req_params)
        doc["application_id"] = ""

        # TODO: application_id assignment process is not thread-safe.
        if application_id is None:
            while 1:
                application_id = ''.join(random.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789") for i in range(11))

                # Make sure application_id is unique
                doc = coll.find_one({"application_id": application_id})
                if doc is None:
                    # Now create it and continue
                    doc = {"application_id": application_id, "finalized": False}
                    coll.save(doc)
                    break
        else:
            # Check application is not already submitted (submit = locked)
            doc = coll.find_one({"application_id": application_id})
            if doc is not None and doc["finalized"] == True:
                self.render("scholarship-apply.html", user=u.get("handle", None), form_data=doc, error="finalized")

        # Update and save this application. (action = "save" or "submit")
        for kw in form_req_params:
            val = self.get_argument(kw, None)
            if val is not None:
                doc[kw] = val
        coll.save(doc)

        if action == 'submit':
            # Submit this application.
            doc["finalized"] = True
            coll.save(doc)

            # Email to the RVP
            guser = 'triangle.scholarship@gmail.com'
            gpass = 'schwerin1'
            mailer = smtplib.SMTP('smtp.gmail.com:587')
            mailer.starttls()
            mailer.login(guser, gpass)

            fromaddr = 'triangle.scholarship@gmail.com'
            toaddr = 'triangle.uiuc.rvp@gmail.com'
            sc_url = 'http://www.illinoistriangle.com/scholarship/apply?application_id=%s' % doc["application_id"]
            message = 'Good %s Mr. RVP:<br/><br/>A scholarship application has been submitted, please review it here: <a href="%s">%s</a><br/><br/>At your service,<br/>Triangle Overmind' % (tod(datetime.now().hour), sc_url, sc_url)

            # Encode the email
            # http://mg.pov.lt/blog/unicode-emails-in-python.html
            header_charset = 'ISO-8859-1'
            for body_charset in 'US-ASCII', 'ISO-8859-1', 'UTF-8':
                try:
                    message.encode(body_charset)
                except UnicodeError:
                    pass
                else:
                    break

            email_body = MIMEText(message.encode(body_charset), 'html', body_charset)
            email_body['From'] = fromaddr
            email_body['To'] = toaddr
            email_body['Subject'] = unicode("Scholarship Application Submitted: %s" % datetime.now().strftime("%A, %B %d, %Y"))
            
            mailer.sendmail(fromaddr, toaddr, email_body.as_string())
            mailer.quit()

        # Render page, no errors (normal behavior)
        self.render("scholarship-apply.html", user=u.get("handle", None), form_data=doc, error=None)

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

    # Create admin user with password "ruby.o.harder!" as temporary password
    coll = application.db["users"]
    result = coll.find_one({"handle": "APL"})

    if not result:
        print "Creating APL user..."
        doc = {"handle": "APL", "password": hashlib.sha1("ruby.o.harder!").hexdigest(), "superuser": 1}
        coll.save(doc)

    tornadio2.server.SocketServer(application)

if __name__ == "__main__":
    main()

