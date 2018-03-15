version = "v.0.8 Alpha"
print("\nLyceum Shoutboard", version)
print("Importing dependencies")

import tornado.web, tornado.ioloop
import sqlite3
import json
import urllib
import os
import random
import datetime
from base64 import b64encode
from hashlib import sha256, md5
from inspect import signature

print("Initializing application")

port = 8888
db_url = "shoutboard.sqlite"
timemod = '+3 hours'

session_lifespan = 14
username_alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZабвгдеёжзийклмнопрстуфхцчшщъыьэюяАБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ1234567890_"
locales = ["ru"]  # ["en", "ru", "1337"]

db_conn = sqlite3.connect(db_url, detect_types = sqlite3.PARSE_DECLTYPES)
sql = db_conn.cursor()

def mid_print(x):
    print(type(x), x)
    return x

def normalize_str(string, alphabet = None, lower = True):
    if string is None:
        return None
    if lower:
        string = string.lower()
    if alphabet is None:
        return string
    output = str()
    for char in string:
        if char in alphabet:
            output += char
    return output

def validate_str(string, alphabet, length = None):
    valid = True
    if type(string) is not str:
        return None
    if length is not None and not length[0] <= len(string) <= length[1]:
        return None
    if alphabet is not None:
        for char in string:
            if char not in alphabet:
                valid = False
                break
    return string if valid else None

def purify(func):
    def wrapper(request, *__):
        return func(request)
    return wrapper

def find_nth(haystack, needle, n):
    start = haystack.find(needle)
    while start >= 0 and n > 1:
        start = haystack.find(needle, start + len(needle))
        n -= 1
    return start

def trim(text, expand_msg="\n-------", char_thresh=1000, char_gate=950, line_thresh=8, line_gate=7):
    ok = True
    if len(text) > char_thresh:
        text = text[:char_gate]
        ok = False
    if text.count("\n") > line_thresh:
        text = text[:find_nth(text, "\n", line_gate)]
        ok = False
    if not ok:
        text += expand_msg
    return text

def cookie_setup(func):
    def wrapper(request, slug=""):
        setup(func, request, slug, True)
    return wrapper

def arg_setup(func):
    def wrapper(request, slug=""):
        setup(func, request, slug, False)
    return wrapper

def setup(func, request, slug, use_cookie):
    grab = request.get_cookie if use_cookie else request.get_argument
    print(request.__class__.__name__, 'serving', func.__name__.upper(), slug)
    locale = grab("locale", None)
    if locale is None or locale.lower() not in locales:
        request.set_cookie("locale", locales[0])
        locale = locales[0]
    session_key = grab("auth", None)
    data = None
    userdata = [None, None, None, None, None]
    if session_key is not None:
        session_key = session_key.strip("\"")
        data = sql.execute("SELECT usersTest.username, dayIssued, alive, usersTest.fullName, usersTest.gravatar, usersTest.badge, usersTest.about FROM sessionsTest JOIN usersTest ON sessionsTest.username = usersTest.username WHERE sessionKey = ? LIMIT 1", (session_key,)).fetchone()
        if data is not None:
            if datetime.datetime.strptime(data[1], "%d/%m/%Y").date() + datetime.timedelta(session_lifespan) <= datetime.date.today() or not data[2]:
                data = None
    if data is None:
        data = [None, None, None, None, None, None, None]
    userdata[0] = validate_str(data[0], username_alphabet, (6, 20))
    if userdata[0] is None:
        if use_cookie:
            request.clear_cookie("auth")
            request.clear_cookie("whoami")
        userdata = [None, None, None, None, None]
    else:
        userdata = list(data)
        del userdata[1:3]
    func(request, locale, userdata, slug) if len(signature(func).parameters) == 4 else func(request, locale, userdata)

class Page_NotFound_Handler(tornado.web.RequestHandler):
    @purify
    def get(self):
        locale = self.get_cookie("locale")
        if locale is None or locale.lower() not in locales:
            self.set_cookie("locale", locales[0])
            locale = locales[0]
        err_desc = {
            "ru": {
                "ERR_NAME": "Не найдено",
                "ERR_DESCRIPTION": "Запрошенная вами страница отсутствует на сервере"
            },
            "en": {
                "ERR_NAME": "Not found",
                "ERR_DESCRIPTION": "The page you have requested is not present on the server"
            },
            "1337": {
                "ERR_NAME": "N07 f0und",
                "ERR_DESCRIPTION": "7h3 p493 y0u h4v3 r3qu3573d 15 n07 pr353n7 0n 7h3 53rv3r"
            }
        }
        self.set_status(404, "Not found")
        self.render("./frontend/error.html", **err_desc[locale])

class Page_Home_Handler(tornado.web.RequestHandler):
    @cookie_setup
    def get(self, locale, userdata):
        if userdata[0] is None:
            self.redirect("/login")
        else:
            self.redirect("/feed")

class Page_Account_Handler(tornado.web.RequestHandler):
    @cookie_setup
    def get(self, locale, userdata):
        if userdata[0] is None:
            self.redirect("/login")
        else:
            self.render("./frontend/" + locale + "/account.html")

class Page_Logout_Handler(tornado.web.RequestHandler):
    def get(self):
        session_key = self.get_cookie("auth", None)
        sql.execute("UPDATE sessionsTest SET alive = 0 WHERE sessionKey = ?", (session_key,))
        db_conn.commit()
        self.clear_cookie("auth")
        self.clear_cookie("whoami")
        self.redirect("/login")

class Page_Login_Handler(tornado.web.RequestHandler):
    @cookie_setup
    def get(self, locale, userdata):
        if userdata[0] is None:
            self.render("./frontend/" + locale + "/login.html")
        else:
            self.redirect("/feed")
    @cookie_setup
    def post(self, locale, userdata):
        target_username = validate_str(self.get_argument("username"), username_alphabet, (6, 20))
        target_password = validate_str(self.get_argument("password"), None, (6, 50))
        if userdata[0] is None:
            if target_username is None or target_password is None:
                response = {
                    "ru": {
                        "status": "WrongCredentials",
                        "description": "Пожалуйста, проверьте\nправильность введенных данных",
                        "username": target_username
                    },
                    "en": {
                        "status": "WrongCredentials",
                        "description": "Please make sure you\nhave provided correct credentials",
                        "username": target_username
                    },
                    "1337": {
                        "status": "WrongCredentials",
                        "description": "P13453 m4k3 5ur3 y0u\nh4v3 pr0v1d3d c0rr3c7 cr3d3n71415",
                        "username": target_username
                    }
                }
                self.finish(json.dumps(response[locale]))
                return
            try:
                target_data = sql.execute("SELECT username, passHash, salt FROM usersTest WHERE uname = ? LIMIT 1", (normalize_str(target_username, username_alphabet),)).fetchone()
            except sqlite3.DatabaseError as e:
                response = {
                    "ru": {
                        "status": "DatabaseMalfunc",
                        "description": "Ошибка базы данных. Пожалуйста, попробуйте еще раз...",
                        "username": target_username
                    },
                    "en": {
                        "status": "DatabaseMalfunc",
                        "description": "Database error. Please try again...",
                        "username": target_username
                    },
                    "1337": {
                        "status": "DatabaseMalfunc",
                        "description": "D474b453 3rr0r. P13453 7ry 4941n...",
                        "username": target_username
                    }
                }
                self.finish(json.dumps(response[locale]))
                return
            if target_data is None:
                response = {
                    "ru": {
                        "status": "WrongCredentials",
                        "description": "Пожалуйста, проверьте\nправильность введенных данных",
                        "username": target_username
                    },
                    "en": {
                        "status": "WrongCredentials",
                        "description": "Please make sure you\nhave provided correct credentials",
                        "username": target_username
                    },
                    "1337": {
                        "status": "WrongCredentials",
                        "description": "P13453 m4k3 5ur3 y0u\nh4v3 pr0v1d3d c0rr3c7 cr3d3n71415",
                        "username": target_username
                    }
                }
                self.finish(json.dumps(response[locale]))
                return
            if sha256((target_password + target_data[2]).encode("utf-8")).hexdigest() == target_data[1]:
                while True:
                    try:
                        session_key = b64encode(os.urandom(69)).decode("utf-8")
                        sql.execute("INSERT INTO sessionsTest VALUES (?, ?, ?, ?)", (session_key, target_data[0], datetime.date.today().strftime("%d/%m/%Y"), True))
                    except sqlite3.DatabaseError as e:
                        if str(e).split()[0] == "UNIQUE":
                            continue
                        else:
                            response = {
                                "ru": {
                                    "status": "DatabaseMalfunc",
                                    "description": "Ошибка базы данных. Пожалуйста, попробуйте еще раз...",
                                    "username": target_username
                                },
                                "en": {
                                    "status": "DatabaseMalfunc",
                                    "description": "Database error. Please try again...",
                                    "username": target_username
                                },
                                "1337": {
                                    "status": "DatabaseMalfunc",
                                    "description": "D474b453 3rr0r. P13453 7ry 4941n...",
                                    "username": target_username
                                }
                            }
                            self.finish(json.dumps(response[locale]))
                            return
                    else:
                        break
                db_conn.commit()
                self.set_cookie("auth", session_key)
                self.set_cookie("whoami", urllib.parse.quote(target_data[0]))
                response = {
                    "ru": {
                        "status": "Ok",
                        "description": "Вход успешно выполнен",
                    },
                    "en": {
                        "status": "Ok",
                        "description": "Successfully logged in",
                    },
                    "1337": {
                        "status": "Ok",
                        "description": "5ucc355fu11y l0993d 1n",
                    }
                }
                self.finish(json.dumps(response[locale]))
            else:
                response = {
                    "ru": {
                        "status": "WrongCredentials",
                        "description": "Пожалуйста, проверьте\nправильность введенных данных",
                        "username": target_username
                    },
                    "en": {
                        "status": "WrongCredentials",
                        "description": "Please make sure you\nhave provided correct credentials",
                        "username": target_username
                    },
                    "1337": {
                        "status": "WrongCredentials",
                        "description": "P13453 m4k3 5ur3 y0u\nh4v3 pr0v1d3d c0rr3c7 cr3d3n71415",
                        "username": target_username
                    }
                }
                self.finish(json.dumps(response[locale]))
                return
        else:
            response = {
                "ru": {
                    "status": "PlsLogOut",
                    "description": "Пожалуйста, выйдите из\nтекущего аккаунта для входа в другой",
                    "username": target_username
                },
                "en": {
                    "status": "PlsLogOut",
                    "description": "Please log out before\nbefore logging into another account",
                    "username": target_username
                },
                "1337": {
                    "status": "PlsLogOut",
                    "description": "P13453 109 0u7 b3f0r3\nb3f0r3 l0991n9 1n70 4n07h3r 4cc0un7",
                    "username": target_username
                }
            }
            self.finish(json.dumps(response[locale]))
            return

class Security_ChangePasswd_Handler(tornado.web.RequestHandler):
    @arg_setup
    def post(self, locale, userdata):
        if userdata[0] is None:
            response = {
                "ru": {
                    "status": "NotAuthenticated",
                    "description": "Не удалось аутентифицировать запрос",
                },
                "en": {
                    "status": "NotAuthenticated",
                    "description": "Failed to authenticate the request",
                },
                "1337": {
                    "status": "NotAuthenticated",
                    "description": "F4113d 70 4u7h3n71c473 7h3 r3qu357",
                }
            }
            self.finish(json.dumps(response[locale]))
            return
        else:
            old_passwd = self.get_argument("oldPasswd", "")
            new_passwd = validate_str(self.get_argument("newPasswd", ""), None, (6, 50))
            conf_passwd = self.get_argument("confPasswd", "")
            target_data = sql.execute("SELECT username, passHash, salt FROM usersTest WHERE uname = ? LIMIT 1", (normalize_str(userdata[0], username_alphabet),)).fetchone()
            if sha256((old_passwd + target_data[2]).encode("utf-8")).hexdigest() != target_data[1]:
                response = {
                    "ru": {
                        "status": "WrongOldPasswd",
                        "description": "Старый пароль указан неверно",
                    },
                    "en": {
                        "status": "WrongOldPasswd",
                        "description": "Wrong old password",
                    },
                    "1337": {
                        "status": "WrongOldPasswd",
                        "description": "Wr0n9 01d p455w0rd",
                    }
                }
                self.finish(json.dumps(response[locale]))
                return
            if new_passwd is None:
                response = {
                    "ru": {
                        "status": "InvalidPassword",
                        "description": "Пожалуйста, придумайте надежный пароль,\nсостоящий из 6 - 50 символов",
                    },
                    "en": {
                        "status": "InvalidPassword",
                        "description": "Please create a secure password\nconsisting of 6 - 50 symbols",
                    },
                    "1337": {
                        "status": "InvalidPassword",
                        "description": "P13453 cr3473 4 53cur3 p455w0rd\nc0n741n1n9 0f 6 - 50 5ymb015",
                    }
                }
                self.finish(json.dumps(response[locale]))
                return
            if new_passwd != conf_passwd:
                response = {
                    "ru": {
                        "status": "UnverifiedPassword",
                        "description": "Пожалуйста, проверьте правильность\nподтверждения пароля",
                    },
                    "en": {
                        "status": "UnverifiedPassword",
                        "description": "Please make sure you have\nverified your password correctly",
                    },
                    "1337": {
                        "status": "UnverifiedPassword",
                        "description": "P13453 m4k3 5ur3 y0u h4v3\nv3r1f13d y0ur p455w0rd c0rr3ct1y",
                    }
                }
                self.finish(json.dumps(response[locale]))
                return
            try:
                salt = b64encode(os.urandom(12)).decode("utf-8")
                sql.execute("UPDATE usersTest SET passHash = ?, salt = ? WHERE uname = ?", (sha256((new_passwd + salt).encode('utf-8')).hexdigest(), salt, normalize_str(userdata[0], username_alphabet)))
            except sqlite3.DatabaseError as e:
                db_conn.rollback()
                print(e)
                response = {
                    "ru": {
                        "status": "DatabaseMalfunc",
                        "description": "Ошибка базы данных. Пожалуйста, попробуйте еще раз...",
                    },
                    "en": {
                        "status": "DatabaseMalfunc",
                        "description": "Database error. Please try again...",
                    },
                    "1337": {
                        "status": "DatabaseMalfunc",
                        "description": "D474b453 3rr0r. P13453 7ry 4941n...",
                    }
                }
                self.finish(json.dumps(response[locale]))
                return
            else:
                db_conn.commit()
                response = {
                    "ru": {
                        "status": "Ok",
                        "description": "Запрос успешно выполенен",
                    },
                    "en": {
                        "status": "Ok",
                        "description": "Request successfully fulfilled",
                    },
                    "1337": {
                        "status": "Ok",
                        "description": "R3qu357 5ucc355fu11y fu1f1113d",
                    },
                }
                self.finish(json.dumps(response[locale]))

class Data_CheckUsername_Handler(tornado.web.RequestHandler):
    def post(self):
        locale = self.get_argument("locale")
        if locale is None or locale.lower() not in locales:
            self.set_cookie("locale", locales[0])
            locale = locales[0]
        target_username = validate_str(self.get_argument("username", None), username_alphabet, (6, 20))
        if target_username is None:
            response = {
                "ru": {
                    "status": "InvalidUsername",
                    "description": "Пожалуйста, выберите имя пользователя, состоящее из \n 6 - 20 символов русского или английского алфавита, цифр или подчеркиваний",
                    "username": target_username
                },
                "en": {
                    "status": "InvalidUsername",
                    "description": "Please choose a userdata[0] consisting of 6 - 20 symbols\nof Russian or English alphabet, digits or underscores",
                    "username": target_username
                },
                "1337": {
                    "status": "InvalidUsername",
                    "description": "P13453 ch0053 4 u53rn4m3 c0n51571n9 0f 6 - 20 5ymb015\n0f Ru5514n 0r 3ng115h 41ph4b37, d19175 0r und3r5c0r35",
                    "username": target_username
                }
            }
            self.finish(json.dumps(response[locale]))
            return
        target_data = sql.execute("SELECT username FROM usersTest WHERE uname = ? LIMIT 1", (normalize_str(target_username),)).fetchone()
        if target_data is None:
            response = {
                "ru": {
                    "status": "Ok",
                    "description": "Имя пользователя доступно",
                    "username": target_username
                },
                "en": {
                    "status": "Ok",
                    "description": "The username is available",
                    "username": target_username
                },
                "1337": {
                    "status": "Ok",
                    "description": "7h3 u53rn4m3 15 4v4114b13",
                    "username": target_username
                }
            }
            self.finish(json.dumps(response[locale]))
            return
        else:
            response = {
                "ru": {
                    "status": "ExistingUsername",
                    "description": "Имя пользователя занято",
                    "username": target_username
                },
                "en": {
                    "status": "ExistingUsername",
                    "description": "The username is taken",
                    "username": target_username
                },
                "1337": {
                    "status": "ExistingUsername",
                    "description": "7h3 u53rn4m3 15 74k3n",
                    "username": target_username
                }
            }
            self.finish(json.dumps(response[locale]))
            return

class Data_FetchUserSubs_Handler(tornado.web.RequestHandler):
    @arg_setup
    def post(self, locale, userdata):
        target_username = self.get_argument("user", "")
        try:
            subs = sql.execute("SELECT topic FROM subsTest WHERE subber = ? AND NOT secret", (normalize_str(target_username, username_alphabet, lower=True),)).fetchall()
            subbers = sql.execute("SELECT subber FROM subsTest WHERE topic = ? AND NOT secret", (("@" + normalize_str(target_username, username_alphabet, lower=True)),)).fetchall()
        except sqlite3.DatabaseError as e:
            db_conn.rollback()
            print(e)
            response = {
                "ru": {
                    "status": "DatabaseMalfunc",
                    "description": "Ошибка базы данных. Пожалуйста, попробуйте еще раз...",
                },
                "en": {
                    "status": "DatabaseMalfunc",
                    "description": "Database error. Please try again...",
                },
                "1337": {
                    "status": "DatabaseMalfunc",
                    "description": "D474b453 3rr0r. P13453 7ry 4941n...",
                },
            }
            self.finish(json.dumps(response[locale]))
            return
        else:
            subscribers = " ".join(["<a href='/u/" + subber[0] + "'>@" + subber[0] + "</a>" for subber in reversed(subbers)])
            subscriptions = " ".join(["<a href='" + ("/u/" if sub[0][0] == "@" else ("/search?" + ("hashtag" if sub[0][0] == "#" else "group") + "=")) + sub[0][1:] + "'>" + sub[0] + "</a>" for sub in reversed(subs)])
            response = {
                "ru": {
                    "subs": subscriptions,
                    "subsN": len(subs),
                    "subbers": subscribers,
                    "subbersN": len(subbers),
                    "status": "Ok",
                    "description": "Запрос успешно выполенен",
                },
                "en": {
                    "subs": subscriptions,
                    "subsN": len(subs),
                    "subbers": subscribers,
                    "subbersN": len(subbers),
                    "status": "Ok",
                    "description": "Request successfully fulfilled",
                },
                "1337": {
                    "subs": subscriptions,
                    "subsN": len(subs),
                    "subbers": subscribers,
                    "subbersN": len(subbers),
                    "status": "Ok",
                    "description": "R3qu357 5ucc355fu11y fu1f1113d",
                },
            }
            self.finish(json.dumps(response[locale]))
            return

class Data_FetchPost_Handler(tornado.web.RequestHandler):
    @arg_setup
    def post(self, locale, userdata):
        author, post_id = self.get_argument("which", "/").split("/")
        try:
            row = sql.execute("SELECT postsTest.*, usersTest.username, fullName FROM postsTest JOIN usersTest ON usersTest.uname = postsTest.uname WHERE postsTest.uname = ? AND postId = ? LIMIT 1", (normalize_str(author, username_alphabet, lower=True), post_id.upper())).fetchone()
        except sqlite3.DatabaseError as e:
            db_conn.rollback()
            print(e)
            response = {
                "ru": {
                    "status": "DatabaseMalfunc",
                    "description": "Ошибка базы данных. Пожалуйста, попробуйте еще раз...",
                },
                "en": {
                    "status": "DatabaseMalfunc",
                    "description": "Database error. Please try again...",
                },
                "1337": {
                    "status": "DatabaseMalfunc",
                    "description": "D474b453 3rr0r. P13453 7ry 4941n...",
                },
            }
            self.finish(json.dumps(response[locale]))
            return
        else:
            if row is None:
                response = {
                    "ru": {
                        "status": "NotFound",
                        "description": "Новость не найдена",
                    },
                    "en": {
                        "status": "NotFound",
                        "description": "Shout not found",
                    },
                    "1337": {
                        "status": "NotFound",
                        "description": "5h0u7 n07 f0und",
                    },
                }
                self.finish(json.dumps(response[locale]))
                return
            else:
                num, uname, postId, recipients, recips, text, tags, time, deleted, secret, username, fullName = row
                if deleted or (secret and not " @" + normalize_str(userdata[0], username_alphabet, lower=True) + " " in recips):
                    response = {
                            "ru": {
                            "status": "NotFound",
                            "description": "Нoвoсть не найдена",
                        },
                        "en": {
                            "status": "NotFound",
                            "description": "Shоut not found",
                        },
                        "1337": {
                            "status": "NotFound",
                            "description": "5h0u7 n07 f0und",
                        },
                    }
                    self.finish(json.dumps(response[locale]))
                    return
                else:
                    post = {
                        "author": username,
                        "postId": postId,
                        "authorFullName": fullName,
                        "text": text,
                        "recipients": recipients,
                        "time": time,
                        "secret": secret,
                    }
                    response = {
                        "ru": {
                            "post": post,
                            "status": "Ok",
                            "description": "Успешно выполнено",
                        },
                        "en": {
                            "post": post,
                            "status": "Ok",
                            "description": "Success",
                        },
                        "1337": {
                            "post": post,
                            "status": "Ok",
                            "description": "5ucc355",
                        },
                    }
                    self.finish(json.dumps(response[locale]))
                    return

class Data_FetchWall_Handler(tornado.web.RequestHandler):
    @arg_setup
    def post(self, locale, userdata):
        target_username = validate_str(self.get_argument("username"), username_alphabet, (6, 20))
        if not target_username:
            response = {
                "ru": {
                    "status": "InvalidUsername",
                    "description": "Неверное имя пользователя",
                },
                "en": {
                    "status": "InvalidUsername",
                    "description": "The username is invalid",
                },
                "1337": {
                    "status": "InvalidUsername",
                    "description": "7h3 u53rn4m3 15 1nv411d",
                }
            }
            self.finish(json.dumps(response[locale]))
            return
        auth_user = userdata[0] if userdata[0] else ""
        auth_user = normalize_str(auth_user, username_alphabet)
        try:
            rows = sql.execute("SELECT postId, postsTest.uname, username, fullName, text, recipients, timeCreated, secret FROM postsTest JOIN usersTest ON postsTest.uname = usersTest.uname WHERE (NOT deleted AND postsTest.uname = '{unm}') AND (NOT secret OR recips LIKE '% @' || '{auth}' || ' %') ORDER BY timeCreated DESC".format(
                                unm=normalize_str(target_username, username_alphabet), auth=auth_user)).fetchall()
        except sqlite3.DatabaseError as e:
            db_conn.rollback()
            print(e)
            response = {
                "ru": {
                    "status": "DatabaseMalfunc",
                    "description": "Ошибка базы данных. Пожалуйста, попробуйте еще раз...",
                },
                "en": {
                    "status": "DatabaseMalfunc",
                    "description": "Database error. Please try again...",
                },
                "1337": {
                    "status": "DatabaseMalfunc",
                    "description": "D474b453 3rr0r. P13453 7ry 4941n...",
                },
            }
            self.finish(json.dumps(response[locale]))
        else:
            if not rows:
                response = {
                    "ru": {
                        "status": "NotFound",
                        "description": "Соответствующие объявления не найдены",
                    },
                    "en": {
                        "status": "NotFound",
                        "description": "No corresponding shouts found",
                    },
                    "1337": {
                        "status": "NotFound",
                        "description": "N0 c0rr35p0nd1n9 5h0u75 f0und",
                    },
                }
                self.finish(json.dumps(response[locale]))
                return
            posts = list()
            for row in rows:
                postId, uname, username, fullName, text, recipients, timeCreated, secret = row
                post = {
                    "author": username,
                    "postId": postId,
                    "authorFullName": fullName,
                    # "text": text,
                    "text": trim(text, "<span class='w3-text-indigo'>...</span><p><a href=javascript:viewPost('" + username + "/" + postId + "')>Читать полностью</a></p>"),
                    "recipients": recipients,
                    "time": timeCreated,
                    "secret": secret,
                }
                posts.append(post)
            response = {
                "ru": {
                    "status": "Ok",
                    "description": "Запрос успешно выполенен",
                },
                "en": {
                    "status": "Ok",
                    "description": "Request successfully fulfilled",
                },
                "1337": {
                    "status": "Ok",
                    "description": "R3qu357 5ucc355fu11y fu1f1113d",
                },
            }
            response[locale].update({"wall": posts})
            self.finish(json.dumps(response[locale]))

class Data_FetchFeed_Handler(tornado.web.RequestHandler):
    @arg_setup
    def post(self, locale, userdata):
        if userdata[0] is None:
            response = {
                "ru": {
                    "status": "NotAuthenticated",
                    "description": "Не удалось аутентифицировать запрос",
                },
                "en": {
                    "status": "NotAuthenticated",
                    "description": "Failed to authenticate the request",
                },
                "1337": {
                    "status": "NotAuthenticated",
                    "description": "F4113d 70 4u7h3n71c473 7h3 r3qu357",
                }
            }
            self.finish(json.dumps(response[locale]))
            return
        offsetPost = self.get_argument("offsetPost", "").split()
        offsetPostId, offsetPostAuthor = (offsetPost if len(offsetPost) == 2 else (None, None))
        offsetPostId = validate_str(offsetPostId, '0123456789ABCDEFHIJKLMNOPQRSTUVWXYZ', (6, 6))
        offsetPostAuthor = validate_str(offsetPostAuthor, username_alphabet, (6, 20))
        count = int(self.get_argument("count", 20))
        try:
            if offsetPostId and offsetPostAuthor:
                # DANGEROUS: postID may not be unique on its own!
                rows = sql.execute("""
                    SELECT * FROM
                    (
                        SELECT postId, feed.uname, username, fullName, text, recipients, timeCreated, important, secret FROM
                        (
                            SELECT postsTest.*, important FROM postsTest
                            JOIN (SELECT topic, subber, important FROM subsTest WHERE subber = '{auth}')
                                ON (substr(topic, 1, 1) = '@' AND substr(topic, 2) = uname)
                                OR (substr(topic, 1, 1) = '$' AND recips LIKE '% ' || topic || ' %')
                                OR (substr(topic, 1, 1) = '#' AND tags   LIKE '% ' || topic || ' %')
                            UNION
                            SELECT postsTest.*, -1 AS important FROM postsTest WHERE recips LIKE '% @' || '{auth}' || ' %'
                        )
                        AS feed JOIN usersTest ON feed.uname = usersTest.uname
                        WHERE NOT deleted AND (NOT secret OR recips LIKE '% @' || '{auth}' || ' %') AND timeCreated < (SELECT timeCreated FROM postsTest WHERE postId = '{offsetPostId}' AND uname = '{offsetPostAuthor}')
                        GROUP BY postId
                        LIMIT {count}
                    ) ORDER BY timeCreated DESC
                    """.format(auth=normalize_str(userdata[0], username_alphabet), offsetPostId=offsetPostId, offsetPostAuthor=normalize_str(offsetPostAuthor, username_alphabet), count=count)).fetchall()
            else:
                # DANGEROUS: postID may not be unique on its own!
                rows = sql.execute("""
                    SELECT * FROM
                    (
                        SELECT postId, feed.uname, username, fullName, text, recipients, timeCreated, important, secret FROM
                        (
                            SELECT postsTest.*, important FROM postsTest
                            JOIN (SELECT topic, subber, important FROM subsTest WHERE subber = '{auth}')
                                ON (substr(topic, 1, 1) = '@' AND substr(topic, 2) = uname)
                                OR (substr(topic, 1, 1) = '$' AND recips LIKE '% ' || topic || ' %')
                                OR (substr(topic, 1, 1) = '#' AND tags   LIKE '% ' || topic || ' %')
                            UNION
                            SELECT postsTest.*, -1 AS important FROM postsTest WHERE recips LIKE '% @' || '{auth}' || ' %'
                        )
                        AS feed JOIN usersTest ON feed.uname = usersTest.uname
                        WHERE NOT deleted AND (NOT secret OR recips LIKE '% @' || '{auth}' || ' %')
                        GROUP BY postId
                        LIMIT {count}
                    ) ORDER BY timeCreated DESC
                """.format(auth=normalize_str(userdata[0], username_alphabet), count=count)).fetchall()
        except sqlite3.DatabaseError as e:
            if str(e) == "no such table: feed":
                response = {
                    "ru": {
                        "status": "NotFound",
                        "description": "Соответствующие объявления не найдены",
                    },
                    "en": {
                        "status": "NotFound",
                        "description": "No corresponding shouts found",
                    },
                    "1337": {
                        "status": "NotFound",
                        "description": "N0 c0rr35p0nd1n9 5h0u75 f0und",
                    },
                }
                self.finish(json.dumps(response[locale]))
                return
            else:
                db_conn.rollback()
                print(e)
                response = {
                    "ru": {
                        "status": "DatabaseMalfunc",
                        "description": "Ошибка базы данных. Пожалуйста, попробуйте еще раз...",
                    },
                    "en": {
                        "status": "DatabaseMalfunc",
                        "description": "Database error. Please try again...",
                    },
                    "1337": {
                        "status": "DatabaseMalfunc",
                        "description": "D474b453 3rr0r. P13453 7ry 4941n...",
                    },
                }
                self.finish(json.dumps(response[locale]))
        else:
            posts = list()
            for row in rows:
                postId, uname, username, fullName, text, recipients, timeCreated, important, secret = row
                post = {
                    "author": username,
                    "postId": postId,
                    "authorFullName": fullName,
                    "text": trim(text, "<span class='w3-text-indigo'>...</span><p><a href=javascript:viewPost('" + username + "/" + postId + "')>Читать полностью</a></p>"),
                    "recipients": recipients,
                    "time": timeCreated,
                    "important": important,
                    "secret": secret,
                }
                posts.append(post)
            if not posts:
                response = {
                    "ru": {
                        "status": "NotFound",
                        "description": "Соответствующие объявления не найдены",
                    },
                    "en": {
                        "status": "NotFound",
                        "description": "No corresponding shouts found",
                    },
                    "1337": {
                        "status": "NotFound",
                        "description": "N0 c0rr35p0nd1n9 5h0u75 f0und",
                    },
                }
                self.finish(json.dumps(response[locale]))
                return
            response = {
                "ru": {
                    "status": "Ok",
                    "description": "Запрос успешно выполенен",
                },
                "en": {
                    "status": "Ok",
                    "description": "Request successfully fulfilled",
                },
                "1337": {
                    "status": "Ok",
                    "description": "R3qu357 5ucc355fu11y fu1f1113d",
                },
            }
            response[locale].update({"feed": posts})
            self.finish(json.dumps(response[locale]))
            return

class Data_SearchPosts_Handler(tornado.web.RequestHandler):
    @arg_setup
    def post(self, locale, userdata):
        if userdata[0] is None:
            auth = "!!!NOBODY!!!"
        else:
            auth = normalize_str(userdata[0], username_alphabet, True)
        # offsetPost = self.get_argument("offsetPost", "").split()
        # offsetPostId, offsetPostAuthor = (offsetPost if len(offsetPost) == 2 else (None, None))
        # offsetPostId = validate_str(offsetPostId, '0123456789ABCDEFHIJKLMNOPQRSTUVWXYZ', (6, 6))
        # offsetPostAuthor = validate_str(offsetPostAuthor, username_alphabet, (6, 20))
        # count = int(self.get_argument("count", 20))
        hashtag = validate_str(self.get_argument("hashtag", None), username_alphabet)
        text = self.get_argument("text", "").replace("\\", "\\\\").replace("%", "\%").replace("_", "\_")
        print(auth, hashtag, text)
        if hashtag:
            text = "&&"
        else:
            hashtag = "!!!NOTHING!!!"
            if text:
                text = tornado.escape.xhtml_escape(text)
            else:
                response = {
                    "ru": {
                        "status": "NotFound",
                        "description": "Соответствующие объявления не найдены",
                    },
                    "en": {
                        "status": "NotFound",
                        "description": "No corresponding shouts found",
                    },
                    "1337": {
                        "status": "NotFound",
                        "description": "N0 c0rr35p0nd1n9 5h0u75 f0und",
                    },
                }
                self.finish(json.dumps(response[locale]))
                return
        try:
            #if offsetPostId and offsetPostAuthor:
            if False:
                # DANGEROUS: postID may not be unique on its own!
                rows = sql.execute("""
                    SELECT * FROM
                    (
                        SELECT postId, feed.uname, username, fullName, text, recipients, timeCreated, secret FROM
                        (
                            SELECT postsTest.* FROM postsTest WHERE
                                tags LIKE '% #{hashtag} %' ESCAPE '\\' OR
                                text LIKE '%{text}%' ESCAPE '\\'
                        )
                        AS feed JOIN usersTest ON feed.uname = usersTest.uname
                        WHERE NOT deleted AND (NOT secret OR recips LIKE '% @' || '{auth}' || ' %') AND timeCreated < (SELECT timeCreated FROM postsTest WHERE postId = '{offsetPostId}' AND uname = '{offsetPostAuthor}')
                        GROUP BY postId
                        -- LIMIT count
                    ) ORDER BY timeCreated DESC
                    """.format(auth=auth, offsetPostId=offsetPostId, offsetPostAuthor=normalize_str(offsetPostAuthor, username_alphabet), hashtag=hashtag, text=text)).fetchall()
            #else:
            if True:
                # DANGEROUS: postID may not be unique on its own!
                rows = sql.execute(mid_print("""
                    SELECT * FROM
                    (
                        SELECT postId, feed.uname, username, fullName, text, recipients, timeCreated, secret FROM
                        (
                            SELECT postsTest.* FROM postsTest WHERE
                                tags LIKE '% #{hashtag} %' ESCAPE '\\' OR
                                text LIKE '%{text}%' ESCAPE '\\'
                        )
                        AS feed JOIN usersTest ON feed.uname = usersTest.uname
                        WHERE NOT deleted AND (NOT secret OR recips LIKE '% @' || '{auth}' || ' %')
                        GROUP BY postId
                        -- LIMIT count
                    ) ORDER BY timeCreated DESC
                """.format(auth=normalize_str(userdata[0], username_alphabet), hashtag=hashtag, text=text))).fetchall()
            print(rows)
        except sqlite3.DatabaseError as e:
            if str(e) == "no such table: feed":
                response = {
                    "ru": {
                        "status": "NotFound",
                        "description": "Соответствующие объявления не найдены",
                    },
                    "en": {
                        "status": "NotFound",
                        "description": "No corresponding shouts found",
                    },
                    "1337": {
                        "status": "NotFound",
                        "description": "N0 c0rr35p0nd1n9 5h0u75 f0und",
                    },
                }
                self.finish(json.dumps(response[locale]))
                return
            else:
                db_conn.rollback()
                print(e)
                response = {
                    "ru": {
                        "status": "DatabaseMalfunc",
                        "description": "Ошибка базы данных. Пожалуйста, попробуйте еще раз...",
                    },
                    "en": {
                        "status": "DatabaseMalfunc",
                        "description": "Database error. Please try again...",
                    },
                    "1337": {
                        "status": "DatabaseMalfunc",
                        "description": "D474b453 3rr0r. P13453 7ry 4941n...",
                    },
                }
                self.finish(json.dumps(response[locale]))
        else:
            posts = list()
            for row in rows:
                postId, uname, username, fullName, text, recipients, timeCreated, secret = row
                post = {
                    "author": username,
                    "postId": postId,
                    "authorFullName": fullName,
                    # "text": text,
                    "text": trim(text, "<span class='w3-text-indigo'>...</span><p><a href=javascript:viewPost('" + username + "/" + postId + "')>Читать полностью</a></p>"),
                    "recipients": recipients,
                    "time": timeCreated,
                    "secret": secret,
                }
                posts.append(post)
            if not posts:
                response = {
                    "ru": {
                        "status": "NotFound",
                        "description": "Соответствующие объявления не найдены",
                    },
                    "en": {
                        "status": "NotFound",
                        "description": "No corresponding shouts found",
                    },
                    "1337": {
                        "status": "NotFound",
                        "description": "N0 c0rr35p0nd1n9 5h0u75 f0und",
                    },
                }
                self.finish(json.dumps(response[locale]))
                return
            response = {
                "ru": {
                    "status": "Ok",
                    "description": "Запрос успешно выполенен",
                },
                "en": {
                    "status": "Ok",
                    "description": "Request successfully fulfilled",
                },
                "1337": {
                    "status": "Ok",
                    "description": "R3qu357 5ucc355fu11y fu1f1113d",
                },
            }
            response[locale].update({"posts": posts})
            self.finish(json.dumps(response[locale]))
            return

class Data_FetchSubscriptions_Handler(tornado.web.RequestHandler):
    @arg_setup
    def post(self, locale, userdata):
        if userdata[0] is None:
            response = {
                "ru": {
                    "status": "NotAuthenticated",
                    "description": "Не удалось аутентифицировать запрос",
                },
                "en": {
                    "status": "NotAuthenticated",
                    "description": "Failed to authenticate the request",
                },
                "1337": {
                    "status": "NotAuthenticated",
                    "description": "F4113d 70 4u7h3n71c473 7h3 r3qu357",
                }
            }
            self.finish(json.dumps(response[locale]))
            return
        try:
            rows = sql.execute("SELECT topic, important, secret, notify FROM subsTest WHERE subber = ?", (normalize_str(userdata[0], username_alphabet),)).fetchall()
        except sqlite3.DatabaseError as e:
            print(e)
            response = {
                "ru": {
                    "status": "DatabaseMalfunc",
                    "description": "Ошибка базы данных. Пожалуйста, попробуйте еще раз...",
                },
                "en": {
                    "status": "DatabaseMalfunc",
                    "description": "Database error. Please try again...",
                },
                "1337": {
                    "status": "DatabaseMalfunc",
                    "description": "D474b453 3rr0r. P13453 7ry 4941n...",
                },
            }
            self.finish(json.dumps(response[locale]))
            return
        else:
            if not rows:
                response = {
                    "ru": {
                        "status": "NotFound",
                        "description": "Соответствующих подписок не найдено",
                    },
                    "en": {
                        "status": "NotFound",
                        "description": "No corresponding subscriptions found",
                    },
                    "1337": {
                        "status": "NotFound",
                        "description": "N0 c0rr35p0nd1n9 5ub5cr1p710n5 f0und",
                    },
                }
                self.finish(json.dumps(response[locale]))
                return
            subscriptions = list()
            for row in rows:
                subscriptions.append({
                    "topic": row[0],
                    "important": row[1],
                    "secret": row[2],
                    "notify": row[3]
                })
            response = {
                "ru": {
                    "status": "Ok",
                    "description": "Запрос успешно выполенен",
                },
                "en": {
                    "status": "Ok",
                    "description": "Request successfully fulfilled",
                },
                "1337": {
                    "status": "Ok",
                    "description": "R3qu357 5ucc355fu11y fu1f1113d",
                },
            }
            response[locale].update({"subs": subscriptions})
            self.finish(json.dumps(response[locale]))
            return

class Data_SearchUsers_Handler(tornado.web.RequestHandler):
    @arg_setup
    def post(self, locale, userdata):
        group = normalize_str(self.get_argument("group", ""), username_alphabet)
        try:
            if not group:
                usr = tornado.escape.xhtml_escape(self.get_argument("user", "").lower().replace("\\", "\\\\").replace("%", "\%").replace("_", "\_"))
                rows = sql.execute(mid_print("SELECT username, fullName FROM usersTest WHERE uname LIKE '%{usr}%' OR fname LIKE '%{usr}%' ESCAPE '\\'".format(usr=usr))).fetchall()
            else:
                rows = sql.execute(mid_print("SELECT username, fullName FROM usersTest JOIN subsTest ON uname = subber WHERE topic LIKE '${grp}' ESCAPE '\\'".format(grp=group))).fetchall()
        except sqlite3.DatabaseError as e:
            print(e)
            response = {
                "ru": {
                    "status": "DatabaseMalfunc",
                    "description": "Ошибка базы данных. Пожалуйста, попробуйте еще раз...",
                },
                "en": {
                    "status": "DatabaseMalfunc",
                    "description": "Database error. Please try again...",
                },
                "1337": {
                    "status": "DatabaseMalfunc",
                    "description": "D474b453 3rr0r. P13453 7ry 4941n...",
                },
            }
            self.finish(json.dumps(response[locale]))
            return
        else:
            if not rows:
                response = {
                    "ru": {
                        "status": "NotFound",
                        "description": "Соответствующих пользователей не найдено",
                    },
                    "en": {
                        "status": "NotFound",
                        "description": "No corresponding users found",
                    },
                    "1337": {
                        "status": "NotFound",
                        "description": "N0 c0rr35p0nd1n9 u53r5 f0und",
                    },
                }
                self.finish(json.dumps(response[locale]))
                return
            users = list()
            for row in rows:
                users.append({
                    "username": row[0],
                    "fullname": row[1] if row[1] else "@" + row[0],
                })
            response = {
                "ru": {
                    "status": "Ok",
                    "description": "Запрос успешно выполенен",
                },
                "en": {
                    "status": "Ok",
                    "description": "Request successfully fulfilled",
                },
                "1337": {
                    "status": "Ok",
                    "description": "R3qu357 5ucc355fu11y fu1f1113d",
                },
            }
            response[locale].update({"users": users})
            self.finish(json.dumps(response[locale]))
            return

class Data_CreatePost_Handler(tornado.web.RequestHandler):
    @arg_setup
    def post(self, locale, userdata):
        if userdata[0] is None:
            response = {
                "ru": {
                    "status": "NotAuthenticated",
                    "description": "Не удалось аутентифицировать запрос",
                },
                "en": {
                    "status": "NotAuthenticated",
                    "description": "Failed to authenticate the request",
                },
                "1337": {
                    "status": "NotAuthenticated",
                    "description": "F4113d 70 4u7h3n71c473 7h3 r3qu357",
                }
            }
            self.finish(json.dumps(response[locale]))
            return
        recipients = self.get_argument("recipients")
        sec = self.get_argument("secret", "false")
        recipients = " " + " ".join(list({ normalize_str(rcpt.strip(), username_alphabet + "$", False) for rcpt in recipients.replace('$',' $').split() if rcpt.startswith("$") and validate_str(rcpt, username_alphabet + "$", (4, 21)) })
                                    + list({ normalize_str(rcpt.strip(), username_alphabet + "@", False) for rcpt in recipients.replace('@',' @').split() if rcpt.startswith("@") and validate_str(rcpt, username_alphabet + "@", (7, 21)) })) + " "
        text = self.get_argument("text")
        tags = " " + " ".join(list({ tag.strip() for tag in text.replace('#',' #').split() if tag.startswith("#") and validate_str(tag, username_alphabet + "#") })) + " "
        try:
            while True:
                post_id = "".join(''.join(random.choice('0123456789ABCDEFHIJKLMNOPQRSTUVWXYZ') for __ in range(6)))
                if sql.execute("SELECT postId FROM postsTest WHERE uname = (?) AND postId = (?)", (userdata[0], post_id)).fetchone() is None:
                    break

            sql.execute("INSERT INTO postsTest VALUES (NULL, :unm, :pid, :rec, :rcp, :txt, :tag, datetime('now', :timemod), 0, :sec)",
                        {
                            "unm": normalize_str(userdata[0], username_alphabet),
                            "pid": post_id,
                            "rec": recipients,
                            "rcp": normalize_str(recipients, username_alphabet + " $@"),
                            "txt": tornado.escape.xhtml_escape(text),
                            "tag": normalize_str(tags, username_alphabet + " #"),
                            "sec": 1 if sec == "true" else 0,
                            "timemod": timemod,
                        })
        except sqlite3.DatabaseError as e:
            print(e)
            db_conn.rollback()
            response = {
                "ru": {
                    "status": "DatabaseMalfunc",
                    "description": "Ошибка базы данных. Пожалуйста, попробуйте еще раз...",
                },
                "en": {
                    "status": "DatabaseMalfunc",
                    "description": "Database error. Please try again...",
                },
                "1337": {
                    "status": "DatabaseMalfunc",
                    "description": "D474b453 3rr0r. P13453 7ry 4941n...",
                },
            }
            self.finish(json.dumps(response[locale]))
        else:
            db_conn.commit()
            response = {
                "ru": {
                    "status": "Ok",
                    "description": "Новость успешно создана",
                    "postNo": post_id,
                },
                "en": {
                    "status": "Ok",
                    "description": "Posted successfully",
                    "postNo": post_id,
                },
                "1337": {
                    "status": "OK",
                    "description": "P0573d 5ucc355fu11y",
                    "postNo": post_id,
                }
            }
            self.finish(json.dumps(response[locale]))

class Data_DeletePost_Handler(tornado.web.RequestHandler):
    @arg_setup
    def post(self, locale, userdata):
        if userdata[0] is None:
            response = {
                "ru": {
                    "status": "NotAuthenticated",
                    "description": "Не удалось аутентифицировать запрос",
                },
                "en": {
                    "status": "NotAuthenticated",
                    "description": "Failed to authenticate the request",
                },
                "1337": {
                    "status": "NotAuthenticated",
                    "description": "F4113d 70 4u7h3n71c473 7h3 r3qu357",
                }
            }
            self.finish(json.dumps(response[locale]))
            return
        post = self.get_argument("post", "").split()
        postId, postAuthor = (post if len(post) == 2 else (None, None))
        postId = validate_str(postId, '0123456789ABCDEFHIJKLMNOPQRSTUVWXYZ', (6, 6))
        postAuthor = validate_str(postAuthor, username_alphabet, (6, 20))
        if userdata[0] != postAuthor:
            print(userdata, "vs.", postAuthor)
            response = {
                "ru": {
                    "status": "Forbidden",
                    "description": "Вы не можете удалить данное объявление",
                },
                "en": {
                    "status": "Forbidden",
                    "description": "You cannot delete that post",
                },
                "1337": {
                    "status": "Forbidden",
                    "description": "Y0u c4nn07 d31373 7h47 p057",
                }
            }
            self.finish(json.dumps(response[locale]))
            return
        if postId and postAuthor:
            try:
                sql.execute("UPDATE postsTest SET deleted = 1 WHERE postId = ? AND postAuthor = ?", (postId, postAuthor))
            except sqlite3.DatabaseError as e:
                print(e)
                db_conn.rollback()
                response = {
                    "ru": {
                        "status": "DatabaseMalfunc",
                        "description": "Ошибка базы данных. Пожалуйста, попробуйте еще раз...",
                    },
                    "en": {
                        "status": "DatabaseMalfunc",
                        "description": "Database error. Please try again...",
                    },
                    "1337": {
                        "status": "DatabaseMalfunc",
                        "description": "D474b453 3rr0r. P13453 7ry 4941n...",
                    },
                }
                self.finish(json.dumps(response[locale]))
            else:
                db_conn.commit()
                response = {
                    "ru": {
                        "status": "Ok",
                        "description": "Новость отсутствует или успешно удалена",
                        "postNo": post_id,
                    },
                    "en": {
                        "status": "Ok",
                        "description": "Post doesn't exist or was deleted successfully",
                        "postNo": post_id,
                    },
                    "1337": {
                        "status": "OK",
                        "description": "P057 d035n'7 3x157 0r w45 d31373d 5ucc355fu11y",
                        "postNo": post_id,
                    }
                }
                self.finish(json.dumps(response[locale]))

class Data_Subscribe_Handler(tornado.web.RequestHandler):
    @arg_setup
    def post(self, locale, userdata):
        if userdata[0] is None:
            response = {
                "ru": {
                    "status": "NotAuthenticated",
                    "description": "Не удалось аутентифицировать запрос",
                },
                "en": {
                    "status": "NotAuthenticated",
                    "description": "Failed to authenticate the request",
                },
                "1337": {
                    "status": "NotAuthenticated",
                    "description": "F4113d 70 4u7h3n71c473 7h3 r3qu357",
                }
            }
            self.finish(json.dumps(response[locale]))
            return
        topic = self.get_argument("topic", "").strip().split()
        if len(topic) != 1 or topic[0][0] not in ["#", "$", "@"] or validate_str(topic[0][1:], username_alphabet) is None or len(topic[0]) < 2:
            response = {
                "ru": {
                    "status": "InvalidTopic",
                    "description": "Указанный объект подписки недействителен",
                },
                "en": {
                    "status": "InvalidTopic",
                    "description": "The defined topic is invalid",
                },
                "1337": {
                    "status": "InvalidTopic",
                    "description": "7h3 d3f1n3d 70p1c 15 1nv411d",
                },
            }
            self.finish(json.dumps(response[locale]))
            return
        topic = topic[0]
        secret = True if self.get_argument("secret", None) == "true" else False
        important = True if self.get_argument("important", None) == "true" else False
        try:
            if sql.execute("SELECT topic FROM subsTest WHERE topic = ? AND subber = ? LIMIT 1", (normalize_str(topic), normalize_str(userdata[0]))).fetchone() is None:
                sql.execute("INSERT INTO subsTest VALUES (?, ?, ?, ?, ?)", (normalize_str(userdata[0]), normalize_str(topic), secret, important, ""))
            else:
                sql.execute("UPDATE subsTest SET secret = :sec, important = :imp, notify = :ntf WHERE topic = :top AND subber = :sub", {"top": normalize_str(topic), "sub": normalize_str(userdata[0]), "sec": secret, "imp": important, "ntf": ""})
        except sqlite3.DatabaseError as e:
            print(e)
            db_conn.rollback()
            response = {
                "ru": {
                    "status": "DatabaseMalfunc",
                    "description": "Ошибка базы данных. Пожалуйста, попробуйте еще раз...",
                },
                "en": {
                    "status": "DatabaseMalfunc",
                    "description": "Database error. Please try again...",
                },
                "1337": {
                    "status": "DatabaseMalfunc",
                    "description": "D474b453 3rr0r. P13453 7ry 4941n...",
                },
            }
            self.finish(json.dumps(response[locale]))
        else:
            response = {
                "ru": {
                    "status": "Ok",
                    "description": "Подписка успешно оформлена",
                },
                "en": {
                    "status": "Ok",
                    "description": "Subscribed successfully",
                },
                "1337": {
                    "status": "OK",
                    "description": "5ub5cr1b3d 5ucc355fu11y",
                }
            }
            db_conn.commit()
            self.finish(json.dumps(response[locale]))

class Data_Unubscribe_Handler(tornado.web.RequestHandler):
    @arg_setup
    def post(self, locale, userdata):
        if userdata[0] is None:
            response = {
                "ru": {
                    "status": "NotAuthenticated",
                    "description": "Не удалось аутентифицировать запрос",
                },
                "en": {
                    "status": "NotAuthenticated",
                    "description": "Failed to authenticate the request",
                },
                "1337": {
                    "status": "NotAuthenticated",
                    "description": "F4113d 70 4u7h3n71c473 7h3 r3qu357",
                }
            }
            self.finish(json.dumps(response[locale]))
            return
        topic = self.get_argument("topic", "").strip().split()
        if len(topic) != 1 or topic[0][0] not in ["#", "$", "@"] or validate_str(topic[0][1:], username_alphabet) is None or len(topic[0]) < 2: 
            response = {
                "ru": {
                    "status": "InvalidTopic",
                    "description": "Указанный объект подписки недействителен",
                },
                "en": {
                    "status": "InvalidTopic",
                    "description": "The defined topic is invalid",
                },
                "1337": {
                    "status": "InvalidTopic",
                    "description": "7h3 d3f1n3d 70p1c 15 1nv411d",
                },
            }
            self.finish(json.dumps(response[locale]))
            return
        topic = topic[0]
        try:
            if sql.execute("SELECT topic FROM subsTest WHERE topic = ? AND subber = ? LIMIT 1", (normalize_str(topic), normalize_str(userdata[0]))).fetchone() is None:
                response = {
                    "ru": {
                        "status": "NoChanges",
                        "description": "Данной подписки не существует",
                    },
                    "en": {
                        "status": "NoChanges",
                        "description": "No such subscription exists",
                    },
                    "1337": {
                        "status": "NoChanges",
                        "description": "N0 5uch 5ub5cr1p710n 3x1575",
                    }
                }
                self.finish(json.dumps(response[locale]))
                return
            else:
                sql.execute("DELETE FROM subsTest WHERE topic = ? AND subber = ? LIMIT 1", (normalize_str(topic), normalize_str(userdata[0])))
        except sqlite3.DatabaseError as e:
            print(e)
            db_conn.rollback()
            response = {
                "ru": {
                    "status": "DatabaseMalfunc",
                    "description": "Ошибка базы данных. Пожалуйста, попробуйте еще раз...",
                },
                "en": {
                    "status": "DatabaseMalfunc",
                    "description": "Database error. Please try again...",
                },
                "1337": {
                    "status": "DatabaseMalfunc",
                    "description": "D474b453 3rr0r. P13453 7ry 4941n...",
                },
            }
            self.finish(json.dumps(response[locale]))
        else:
            response = {
                "ru": {
                    "status": "Ok",
                    "description": "Подписка успешно отменена",
                },
                "en": {
                    "status": "Ok",
                    "description": "Unsubscribed successfully",
                },
                "1337": {
                    "status": "OK",
                    "description": "Un5ub5cr1b3d 5ucc355fu11y",
                }
            }
            db_conn.commit()
            self.finish(json.dumps(response[locale]))


class Page_Register_Handler(tornado.web.RequestHandler):
    @cookie_setup
    def get(self, locale, userdata):
        if userdata[0] is None:
            self.render("./frontend/" + locale + "/register.html")
        else:
            self.redirect("/feed")
    @cookie_setup
    def post(self, locale, userdata):
        target_username = validate_str(self.get_argument("username", ""), username_alphabet, (6, 20))
        target_password = validate_str(self.get_argument("password", ""), None, (6, 50))
        target_verifypass = self.get_argument("verifyPassword", "")
        if userdata[0] is None:
            if target_username is None:
                response = {
                    "ru": {
                        "status": "InvalidUsername",
                        "description": "Пожалуйста, выберите имя пользователя, состоящее из \n 6 - 20 символов русского или английского алфавита, цифр или подчеркиваний",
                        "username": target_username
                    },
                    "en": {
                        "status": "InvalidUsername",
                        "description": "Please choose a userdata[0] consisting of 6 - 20 symbols\nof Russian or English alphabet, digits or underscores",
                        "username": target_username
                    },
                    "1337": {
                        "status": "InvalidUsername",
                        "description": "P13453 ch0053 4 u53rn4m3 c0n51571n9 0f 6 - 20 5ymb015\n0f Ru5514n 0r 3n9115h 41ph4b37, d19175 0r und3r5c0r35",
                        "username": target_username
                    }
                }
                self.finish(json.dumps(response[locale]))
                return
            if target_password != target_verifypass:
                response = {
                    "ru": {
                        "status": "UnverifiedPassword",
                        "description": "Пожалуйста, проверьте правильность\nподтверждения пароля",
                        "username": target_username
                    },
                    "en": {
                        "status": "UnverifiedPassword",
                        "description": "Please make sure you have\nverified your password correctly",
                        "username": target_username
                    },
                    "1337": {
                        "status": "UnverifiedPassword",
                        "description": "P13453 m4k3 5ur3 y0u h4v3\nv3r1f13d y0ur p455w0rd c0rr3ct1y",
                        "username": target_username
                    }
                }
                self.finish(json.dumps(response[locale]))
                return
            if target_password is None:
                response = {
                    "ru": {
                        "status": "InvalidPassword",
                        "description": "Пожалуйста, придумайте надежный пароль,\nсостоящий из 6 - 50 символов",
                        "username": target_username
                    },
                    "en": {
                        "status": "InvalidPassword",
                        "description": "Please create a secure password\nconsisting of 6 - 50 symbols",
                        "username": target_username
                    },
                    "1337": {
                        "status": "InvalidPassword",
                        "description": "P13453 cr3473 4 53cur3 p455w0rd\nc0n741n1n9 0f 6 - 50 5ymb015",
                        "username": target_username
                    }
                }
                self.finish(json.dumps(response[locale]))
                return
            try:
                salt = b64encode(os.urandom(12)).decode("utf-8")
                sql.execute("INSERT INTO usersTest VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", (normalize_str(target_username, username_alphabet), target_username, sha256((target_password + salt).encode('utf-8')).hexdigest(), salt, "", "", "", "", ""))
            except sqlite3.DatabaseError as e:
                if str(e).split()[0] == "UNIQUE":
                    response = {
                        "ru": {
                            "status": "ExistingUsername",
                            "description": "Имя пользователя занято",
                            "username": target_username
                        },
                        "en": {
                            "status": "ExistingUsername",
                            "description": "The username is taken",
                            "username": target_username
                        },
                        "1337": {
                            "status": "ExistingUsername",
                            "description": "7h3 u53rn4m3 15 74k3n",
                            "username": target_username
                        }
                    }
                    self.finish(json.dumps(response[locale]))
                    return
                else:
                    print(e)
                    response = {
                        "ru": {
                            "status": "DatabaseMalfunc",
                            "description": "Ошибка базы данных. Пожалуйста, попробуйте еще раз...",
                            "username": target_username
                        },
                        "en": {
                            "status": "DatabaseMalfunc",
                            "description": "Database error. Please try again...",
                            "username": target_username
                        },
                        "1337": {
                            "status": "DatabaseMalfunc",
                            "description": "D474b453 3rr0r. P13453 7ry 4941n...",
                            "username": target_username
                        }
                    }
                    self.finish(json.dumps(response[locale]))
                    return
            else:
                while True:
                    try:
                        session_key = b64encode(os.urandom(69)).decode("utf-8")
                        sql.execute("INSERT INTO sessionsTest VALUES (?, ?, ?, ?)", (session_key, target_username, datetime.date.today().strftime("%d/%m/%Y"), True))
                    except sqlite3.DatabaseError as e:
                        if str(e).split()[0] == "UNIQUE":
                            continue
                        else:
                            print(e)
                            response = {
                                "ru": {
                                    "status": "DatabaseMalfunc",
                                    "description": "Ошибка базы данных. Пожалуйста, попробуйте еще раз...",
                                    "username": target_username
                                },
                                "en": {
                                    "status": "DatabaseMalfunc",
                                    "description": "Database error. Please try again...",
                                    "username": target_username
                                },
                                "1337": {
                                    "status": "DatabaseMalfunc",
                                    "description": "D474b453 3rr0r. P13453 7ry 4941n...",
                                    "username": target_username
                                }
                            }
                            self.finish(json.dumps(response[locale]))
                            return
                    else:
                        break
                db_conn.commit()
                self.set_cookie("auth", session_key)
                self.set_cookie("whoami", urllib.parse.quote(target_username))
                response = {
                    "ru": {
                        "status": "Ok",
                        "description": "Регистрация успешно завершена",
                        "username": target_username
                    },
                    "en": {
                        "status": "Ok",
                        "description": "Successfully registered",
                        "username": target_username
                    },
                    "1337": {
                        "status": "Ok",
                        "description": "5ucc355fu11y r391573r3d",
                        "username": target_username
                    }
                }
                self.finish(json.dumps(response[locale]))
                return
        else:
            response = {
                "ru": {
                    "status": "PlsLogOut",
                    "description": "Пожалуйста, выйдите из текущего аккаунта для создания нового",
                    "username": target_username
                },
                "en": {
                    "status": "PlsLogOut",
                    "description": "Please log out before registering a new account",
                    "username": target_username
                },
                "1337": {
                    "status": "PlsLogOut",
                    "description": "P13453 109 0u7 b3f0r3 r391573r1n9 4 n3w 4cc0un7",
                    "username": target_username
                }
            }
            self.finish(json.dumps(response[locale]))
            return

class Data_UpdateGravatar_Handler(tornado.web.RequestHandler):
    @arg_setup
    def post(self, locale, userdata):
        if not userdata[0]:
            response = {
                "ru": {
                    "status": "NotAuthenticated",
                    "description": "Не удалось аутентифицировать запрос",
                },
                "en": {
                    "status": "NotAuthenticated",
                    "description": "Failed to authenticate the request",
                },
                "1337": {
                    "status": "NotAuthenticated",
                    "description": "F4113d 70 4u7h3n71c473 7h3 r3qu357",
                }
            }
            self.finish(json.dumps(response[locale]))
            return
        email_hash = self.get_argument("emailHash", "")
        try:
            if email_hash == "":
                sql.execute("UPDATE usersTest SET gravatar = ? WHERE uname = ?", ("", normalize_str(userdata[0], username_alphabet)))
            else:
                sql.execute("UPDATE usersTest SET gravatar = ? WHERE uname = ?", (email_hash, normalize_str(userdata[0], username_alphabet)))
        except sqlite3.DatabaseError as e:
            db_conn.rollback()
            print(e)
            response = {
                "ru": {
                    "status": "DatabaseMalfunc",
                    "description": "Ошибка базы данных. Пожалуйста, попробуйте еще раз...",
                },
                "en": {
                    "status": "DatabaseMalfunc",
                    "description": "Database error. Please try again...",
                },
                "1337": {
                    "status": "DatabaseMalfunc",
                    "description": "D474b453 3rr0r. P13453 7ry 4941n...",
                }
            }
            self.finish(json.dumps(response[locale]))
            return
        else:
            db_conn.commit()
            if email_hash == "":
                response = {
                    "ru": {
                        "status": "Ok",
                        "description": "Gravatar успешно отключен",
                    },
                    "en": {
                        "status": "Ok",
                        "description": "Gravatar successfully disconnected",
                    },
                    "1337": {
                        "status": "Ok",
                        "description": "9r4v474r 5ucc355fu11y d15c0nn3c73d",
                    },
                }
            else:
                response = {
                    "ru": {
                        "status": "Ok",
                        "description": "Gravatar успешно подключен",
                    },
                    "en": {
                        "status": "Ok",
                        "description": "Gravatar successfully connected",
                    },
                    "1337": {
                        "status": "Ok",
                        "description": "9r4v474r 5ucc355fu11y c0nn3c73d",
                    },
                }
            self.finish(json.dumps(response[locale]))

class Data_UpdatePersonal_Handler(tornado.web.RequestHandler):
    @arg_setup
    def post(self, locale, userdata):
        if not userdata[0]:
            response = {
                "ru": {
                    "status": "NotAuthenticated",
                    "description": "Не удалось аутентифицировать запрос",
                },
                "en": {
                    "status": "NotAuthenticated",
                    "description": "Failed to authenticate the request",
                },
                "1337": {
                    "status": "NotAuthenticated",
                    "description": "F4113d 70 4u7h3n71c473 7h3 r3qu357",
                }
            }
            self.finish(json.dumps(response[locale]))
            return
        fullname = tornado.escape.xhtml_escape(self.get_argument("fullname", ""))
        about = tornado.escape.xhtml_escape(self.get_argument("about", ""))
        try:
            sql.execute("UPDATE usersTest SET fullName = :fullname, fname = :fname, about = :about WHERE uname = :auth", (fullname, fullname.lower(), about, normalize_str(userdata[0], username_alphabet)))
        except sqlite3.DatabaseError as e:
            db_conn.rollback()
            print(e)
            response = {
                "ru": {
                    "status": "DatabaseMalfunc",
                    "description": "Ошибка базы данных. Пожалуйста, попробуйте еще раз...",
                },
                "en": {
                    "status": "DatabaseMalfunc",
                    "description": "Database error. Please try again...",
                },
                "1337": {
                    "status": "DatabaseMalfunc",
                    "description": "D474b453 3rr0r. P13453 7ry 4941n...",
                }
            }
            self.finish(json.dumps(response[locale]))
            return
        else:
            db_conn.commit()
            response = {
                "ru": {
                    "status": "Ok",
                    "description": "Персональные данные успешно обновлены",
                },
                "en": {
                    "status": "Ok",
                    "description": "Personal data successfully updated",
                },
                "1337": {
                    "status": "Ok",
                    "description": "P3r50n41 d474 5ucc355fu11y upd473d",
                },
            }
            self.finish(json.dumps(response[locale]))

class Page_Gravatar_Handler(tornado.web.RequestHandler):
    @cookie_setup
    def get(self, locale, userdata):
        if userdata[0] is None:
            self.redirect("/login")
        else:
            self.render("./frontend/" + locale + "/gravatar.html")

class Page_Personal_Handler(tornado.web.RequestHandler):
    @cookie_setup
    def get(self, locale, userdata):
        if userdata[0] is None:
            self.redirect("/login")
            return
        if userdata[2]:
            avatar_link = "https://www.gravatar.com/avatar/" + userdata[2] + "?s=256"
        else:
            avatar_link = "/static/default_avatar.png"
        self.render("./frontend/" + locale + "/personal.html", USERNAME=userdata[0], FULL_NAME=tornado.escape.xhtml_unescape(userdata[1]), AVATAR_LINK=avatar_link, ABOUT_TEXT=tornado.escape.xhtml_unescape(userdata[4]))

class Page_Subscriptions_Handler(tornado.web.RequestHandler):
    @cookie_setup
    def get(self, locale, userdata):
        if userdata[0] is None:
            self.redirect("/login")
        else:
            self.render("./frontend/" + locale + "/subscriptions.html")


class Page_Me_Handler(tornado.web.RequestHandler):
    @cookie_setup
    def get(self, locale, userdata):
        if userdata[0] is None:
            self.redirect("/login")
        else:
            self.redirect("/u/" + userdata[0])

class Page_Feed_Handler(tornado.web.RequestHandler):
    @cookie_setup
    def get(self, locale, userdata):
        if userdata[0] is None:
            self.redirect("/login")
        else:
            self.render("./frontend/" + locale + "/feed.html")

class Page_Settings_Handler(tornado.web.RequestHandler):
    @cookie_setup
    def get(self, locale, userdata):
        if userdata[0] is None:
            self.redirect("/login")
        else:
            self.render("./frontend/" + locale + "/settings.html")

class Page_Search_Handler(tornado.web.RequestHandler):
    @cookie_setup
    def get(self, locale, userdata, whatever):
        hashtag = self.get_argument("hashtag", None)
        group = self.get_argument("group", None)
        text = self.get_argument("text", None)
        user = self.get_argument("user", None)
        wait_text = {
            "ru": "Производится поиск...",
            "en": "Search in progress...",
            "1337": "P3rf0rm1n9 5qLm4p 5c4n...",
        }[locale]
        if hashtag is not None:
            query_title = "по #" + hashtag + " "
            search_what = 2
        elif text is not None:
            query_title = "новостей \"" + text + "\" "
            search_what = 2
        elif group is not None:
            query_title = "по $" + group + " "
            search_what = 1
        elif user is not None:
            query_title = "пользователя \"" + user + "\" "
            search_what = 1
        else:
            query_title = ""
            search_what = 0
            wait_text = ""
        self.render("./frontend/" + locale + "/search.html", QUERY_TITLE=query_title, WAIT_TEXT=wait_text, SEARCH_WHAT=search_what)


class Page_Post_Handler(tornado.web.RequestHandler):
    @cookie_setup
    def get(self, locale, userdata, slug):
        if len(slug.split("/")) != 2:
            err_desc = {
                "ru": {
                    "ERR_NAME": "Не найдено",
                    "ERR_DESCRIPTION": "Запрошенная вами страница отсутствует на сервере"
                },
                "en": {
                    "ERR_NAME": "Not found",
                    "ERR_DESCRIPTION": "The page you have requested is not present on the server"
                },
                "1337": {
                    "ERR_NAME": "N07 f0und",
                    "ERR_DESCRIPTION": "7h3 p493 y0u h4v3 r3qu3573d 15 n07 pr353n7 0n 7h3 53rv3r"
                }
            }
            self.set_status(404, "Not found")
            self.render("./frontend/error.html", **err_desc[locale])
        else:
            self.render("./frontend/" + locale + "/viewPost.html", WHICH_POST=slug)

class Page_User_Handler(tornado.web.RequestHandler):
    @cookie_setup
    def get(self, locale, userdata, slug):
        err_desc = {
            "ru": {
                "ERR_NAME": "Не найдено",
                "ERR_DESCRIPTION": "Запрошенный вами профиль отсутствует на сервере"
            },
            "en": {
                "ERR_NAME": "Not found",
                "ERR_DESCRIPTION": "The user profile you have requested is not present on the server"
            },
            "1337": {
                "ERR_NAME": "N07 f0und",
                "ERR_DESCRIPTION": "7h3 u53r pr0f113 y0u h4v3 r3qu3573d 15 n07 pr353n7 0n 7h3 53rv3r"
            }
        }
        if validate_str(slug, username_alphabet, (6, 20)) is None:
            self.set_status(404, "Not found")
            self.render("./frontend/error.html", **err_desc[locale])
            return
        else:
            uname = normalize_str(slug, username_alphabet)
            try:
                target_data = sql.execute("SELECT username, fullName, gravatar, badge, about FROM usersTest WHERE uname = ? LIMIT 1", (uname,)).fetchone()
                subs_count = sql.execute("SELECT count(*) FROM subsTest WHERE subber = ? AND NOT secret", (uname,)).fetchone()[0]
                subbers_count = sql.execute("SELECT count(*) FROM subsTest WHERE topic = ? AND NOT secret", ("@" + uname,)).fetchone()[0]
            except sqlite3.DatabaseError as e:
                print(e)
                response = {
                    "ru": {
                        "status": "DatabaseMalfunc",
                        "description": "Ошибка базы данных. Пожалуйста, попробуйте еще раз...",
                    },
                    "en": {
                        "status": "DatabaseMalfunc",
                        "description": "Database error. Please try again...",
                    },
                    "1337": {
                        "status": "DatabaseMalfunc",
                        "description": "D474b453 3rr0r. P13453 7ry 4941n...",
                    }
                }
                self.finish(json.dumps(response[locale]))
                return
            else:
                if target_data is None:
                    self.set_status(404, "Not found")
                    self.render("./frontend/error.html", **err_desc[locale])
                    return
                if target_data[2]:
                    avatar_link = "https://www.gravatar.com/avatar/" + target_data[2] + "?s=256"
                else:
                    avatar_link = "/static/default_avatar.png"
                profile_desc = {
                    "FULL_NAME": tornado.escape.xhtml_unescape(target_data[1]) if target_data[1] else "@" + target_data[0],
                    "USERNAME": target_data[0],
                    "AVATAR_LINK": avatar_link,
                    "HIDE_BADGE": "" if target_data[3] else "w3-hide",
                    "BADGE_LINK": "/static/badge/" + target_data[3] + ".png" if target_data[3] else "",
                    "ABOUT_TEXT": tornado.escape.xhtml_unescape(target_data[4]),
                    "SUBS_COUNT": subs_count,
                    "SUBBERS_COUNT": subbers_count,
                }
                self.render("./frontend/" + locale + "/profile.html", **profile_desc)

settings = {
    "debug": True,
}

app = tornado.web.Application([
    (r"/", Page_Home_Handler),
    (r"/logout", Page_Logout_Handler),
    (r"/login", Page_Login_Handler),
    (r"/security/changePasswd", Security_ChangePasswd_Handler),
    (r"/data/checkUsername", Data_CheckUsername_Handler),
    (r"/data/fetchWall", Data_FetchWall_Handler),
    (r"/data/fetchPost", Data_FetchPost_Handler),
    (r"/data/fetchFeed", Data_FetchFeed_Handler),
    (r"/data/fetchUserSubs", Data_FetchUserSubs_Handler),
    (r"/data/fetchSubscriptions", Data_FetchSubscriptions_Handler),
    (r"/data/createPost", Data_CreatePost_Handler),
    (r"/data/deletePost", Data_DeletePost_Handler),
    (r"/data/subscribe", Data_Subscribe_Handler),
    (r"/data/unsubscribe", Data_Unubscribe_Handler),
    (r"/data/updateGravatar", Data_UpdateGravatar_Handler),
    (r"/data/updatePersonal", Data_UpdatePersonal_Handler),
    (r"/data/searchPosts", Data_SearchPosts_Handler),
    (r"/data/searchUsers", Data_SearchUsers_Handler),
    (r"/register", Page_Register_Handler),
    (r"/settings", Page_Settings_Handler),
    (r"/gravatar", Page_Gravatar_Handler),
    (r"/account", Page_Account_Handler),
    (r"/personal", Page_Personal_Handler),
    (r"/subscriptions", Page_Subscriptions_Handler),
    (r"/me", Page_Me_Handler),
    (r"/feed", Page_Feed_Handler),
    (r"/search", Page_Search_Handler),
    (r"/u/(.*)", Page_User_Handler),
    (r"/p/(.*)", Page_Post_Handler),
    (r"/static/(.*)", tornado.web.StaticFileHandler, {"path": "./frontend/static"}),
    (r"/(.*)", Page_NotFound_Handler),
], **settings)

def start():
    print("Starting application")
    app.listen(port)
    tornado.ioloop.IOLoop.current().start()

if __name__ == "__main__":
    start()
