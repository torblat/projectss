from flask import redirect, render_template, request, session, flash
from functools import wraps
from datetime import datetime
from hashlib import md5
from rcon.source import Client
from config import *


def error(e):
    return render_template('error.html', errorcode = int(str(e)[0:3])), int(str(e)[0:3])

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            flash("Требуется авторизация!")
            return redirect("/login/")
        return f(*args, **kwargs)
    return decorated_function

def rank_required(db, rank = 1):
    def decor(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            urank = get_rank(db)
            if urank < rank:
                return error(403)
            return f(*args, **kwargs)
        return decorated_function
    return decor

def execmd(server : str, command : str, *args : str) -> str: 
    arg = " ".join(args)
    with Client(rcon_data[server]["host"], 25575, passwd=rcon_data[server]["passwd"]) as client:
        response = client.run(command, arg)
        if response == "":
            response = "Успех!"
        return response

def logined() -> bool: 
    return not (session.get("user_id") == None)

def get_rank(db):
    return db(f"SELECT * FROM dle_users WHERE name = '{session.get('user_id')}'")[0]["rank"]

def create_donate_link(nick : str, server : str, donType : str, item : str, cost : int = None, currency : str = "RUB"):
    if cost is None:
        cost = cost_data[item]

    mdhash = md5(f"{merch_id}:{cost}:{secret_word}:{currency}:{nick}_axx_{server}_axx_{donType}_axx_{item}".encode("UTF-8")).hexdigest()

    return f"https://pay.freekassa.ru/?m={merch_id}&oa={cost}&currency={currency}&o={nick}_axx_{server}_axx_{donType}_axx_{item}&s={mdhash}"

def log_admin(text, type = "MAIN") -> bool: 
    try:
        now = datetime.now()
        file = open("admin.log", "a", encoding="utf8")
        file.write(f"[{now.strftime('%d-%m-%Y %H:%M')}][{type}]: {text}")
        file.write("\n")
        file.close
        return True
    except Exception as e:
        print(e)
        return False
    
print(create_donate_link("WolframoviyI", "industrial", "pex", "aura"))