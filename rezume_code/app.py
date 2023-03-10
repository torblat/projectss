import pymysql
from datetime import datetime
from flask import Flask, flash, redirect, render_template, send_from_directory, request, session
from helpers import *
from parser import *
from flask_session import Session
from PIL import Image
from os import remove
from time import gmtime
from hashlib import md5
from config import *
from shutil import copy


# Настраиваем Flask 
app = Flask(__name__)
# Автоподгрузка шаблонов
app.config["TEMPLATES_AUTO_RELOAD"] = True
# Настройка сессии
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Подключаемся к базе данных
# ДБ Сайта
connection = pymysql.connect(host=dbconf["host"],
                             user=dbconf["user"],
                             password=dbconf["password"],                             
                             db=dbconf["dbname"],
                             charset='utf8mb4',
                             cursorclass=pymysql.cursors.DictCursor) 
# ДБ Авторизации
connectionauth = pymysql.connect(host=authdbconf["host"],
                             user=authdbconf["user"],
                             password=authdbconf["password"],                             
                             db=authdbconf["dbname"],
                             charset='utf8mb4',
                             cursorclass=pymysql.cursors.DictCursor) 
# ДБ хендлера сессий
connectionhand = pymysql.connect(host=handdbconf["host"],
                             user=handdbconf["user"],
                             password=handdbconf["password"],                             
                             db=handdbconf["dbname"],
                             charset='utf8mb4',
                             cursorclass=pymysql.cursors.DictCursor) 
# ДБ банов
connectionbans = pymysql.connect(host=bansdbconf["host"],
                             user=bansdbconf["user"],
                             password=bansdbconf["password"],                             
                             db=bansdbconf["dbname"],
                             charset='utf8mb4',
                             cursorclass=pymysql.cursors.DictCursor) 

db = connection.cursor()
dbauth = connectionauth.cursor()
dbhand = connectionhand.cursor()
dbbans = connectionbans.cursor()

# Сокращение обращений к БД
def dbexecute(query, *args):
    db.execute(query)
    connection.commit()
    return db.fetchall()
def dbauthexecute(query, *args):
    dbauth.execute(query, args)
    connectionauth.commit()
    return dbauth.fetchall()

def dbhandexecute(query, *args):
    dbhand.execute(query, args)
    connectionhand.commit()
    return dbhand.fetchall()

def dbbansexecute(query, *args):
    dbbans.execute(query)
    connectionbans.commit()
    return dbbans.fetchall()

# Обработка ошибок HTTP
@app.errorhandler(Exception)
def err(e):
    return error(e)

# Главная страница
@app.route("/")
def root():
    news = get_posts_data()
    customnews = list(dbexecute("SELECT * FROM news"))
    news = sorted(news + customnews, key = lambda d: d["date"])[::-1]
    return render_template("index.html", news=news, username = session.get("user_id"), logined = logined())

# Регистрация
@app.route("/register/", methods = ["GET", "POST"])
def register():
    if request.method == "POST":
        users = dbauthexecute("SELECT name FROM dle_users WHERE name = %s", request.form.get('username'))
        if not request.form.get("username"):
            flash("Введите ник-нейм!!")
            return render_template("register.html"), 400
        elif not request.form.get("email"):
            flash("Введите E-Mail!")
            return render_template("register.html"), 400
        elif '@' not in request.form.get("email") or '.' not in request.form.get("email"):
            flash("E-Mail не валидный!")
            return render_template("register.html"), 400
        elif len(users) >= 1:
            flash("Игрок с таким ник-неймом уже зарегистророван!")
            return render_template("register.html"), 400
        elif not request.form.get("password") or not request.form.get("confirmation"):
            flash("Введите и подтвердите пароль!")
            return render_template("register.html"), 400
        elif request.form.get("password") != request.form.get("confirmation"):
            flash("Пароли не совпадают!")
            return render_template("register.html"), 400

        passhash = md5(request.form.get("password").encode(encoding="UTF-8")).hexdigest()

        dbauthexecute(f"INSERT INTO dle_users (name, email, password) VALUES ('{request.form.get('username')}', '{request.form.get('email')}', '{passhash}')")
        dbhandexecute(f"INSERT INTO users (username) VALUES ('{request.form.get('username')}')")
        copy("skindb/default_skin_template.png", f"skindb/{request.form.get('username')}.png")

        session["user_id"] = request.form.get("username")

        return redirect("/")
    
    else:
        return render_template("register.html"), 200

# Вход в аккаунт
@app.route("/login/", methods = ["GET", "POST"])
def login():
    session.clear()

    if request.method == "POST":

        if not request.form.get("username"):
            flash("Введите ник-нейм!")
            return render_template("login.html"), 400

        elif not request.form.get("password"):
            flash("Введите пароль!")
            return render_template("login.html"), 400

        rows = dbauthexecute(f"SELECT * FROM dle_users WHERE name = '{request.form.get('username')}'")

        passhash = md5(request.form.get("password").encode(encoding="UTF-8")).hexdigest()
        if len(rows) != 1 or not rows[0]["password"] == passhash:
            flash("Неправильные данные для авторизации!")
            return render_template("login.html"), 400

        session["user_id"] = request.form.get("username")

        return redirect("/")

    else:
        return render_template("login.html"), 200

# Выход из аккаунта
@app.route("/logout/")
def logout():
    session.clear()
    return redirect("/")

# Профиль
@app.route("/profile/")
@login_required
def profile():
    if logined():
        banned = len(dbbansexecute(f"SELECT DATE_FORMAT(FROM_UNIXTIME(expires / 1000), '%T %e-%c-%Y') FROM bans WHERE name = '{session.get('user_id')}'")) != 0
        if banned:
            ban = dbbansexecute(f"SELECT DATE_FORMAT(FROM_UNIXTIME(expires / 1000), '%T %e-%c-%Y') FROM bans WHERE name = '{session.get('user_id')}'")[0]["DATE_FORMAT(FROM_UNIXTIME(expires / 1000), '%T %e-%c-%Y')"]
            print(ban)
        else:
            ban = None
        profinfo = dbauthexecute(f"SELECT * FROM dle_users WHERE name = '{session.get('user_id')}'")[0]
        return render_template("profile.html", username = session.get("user_id"), logined = logined(), email = profinfo["email"], expiries = ban, banned = banned), 200
    else:
        return redirect("/")

# Правила
@app.route("/rules/")
def rules():
    return render_template("rules.html", username = session.get("user_id"), logined = logined()), 200

# Банлист
@app.route("/banlist/")
def banlist():
    bans = dbbansexecute(f"SELECT name, reason, banner, DATE_FORMAT(FROM_UNIXTIME(time / 1000), '%T %e-%c-%Y'), DATE_FORMAT(FROM_UNIXTIME(expires / 1000), '%T %e-%c-%Y') FROM bans ORDER BY time DESC")
    return render_template("banlist.html", username = session.get("user_id"), logined = logined(), bans = bans), 200

# Донат
@app.route("/donate/")
@login_required
def donate():
    return render_template("donate.html", logined = True, username = session.get("user_id")), 200

@app.route("/change_skin/", methods = ["GET", "POST"])
@login_required
def change_skin():
    if request.method == "POST":
        if request.files.get("skin"):
            request.files.get("skin").save(f"temp/{session.get('user_id')}.png")
            im = Image.open(f"temp/{session.get('user_id')}.png")
            (width, height) = im.size
            if width == 64 and height == 64:
                request.files.get("skin").save(f"skindb/{session.get('user_id')}.png")
                remove(f"temp/{session.get('user_id')}.png")
    
    render_template("change_skin.html", username = session.get("user_id"), logined = True)

# БД Скинов
@app.route("/skindb/<filename>/", methods=["GET"])
def skindb(filename):
    return send_from_directory("./skindb/", filename, as_attachment = True)
# БД Плащей
@app.route("/capedb/<filename>/", methods=["GET"])
def capedb(filename):
    return send_from_directory("./capedb/", filename, as_attachment = True)(f"capedb/{filename}")
# Обработка платежей
@app.route("/wolframoviy/freekassa/pizdec/secret/transactions/", methods = ["POST"])
def transactions():
    if request.remote_addr in fk_ips:
        md5hash_orig = md5(f"{merch_id}:{request.form.get('AMOUNT')}:{secret_word}:{request.form.get('MERCHANT_ORDER_ID')}".encode("UTF-8")).hexdigest
        if md5hash_orig != request.form.get("SIGN"):
            print(md5hash_orig)
            print(request.form.get("SIGN"))
            return error(401)
        
        order_data = request.form.get('MERCHANT_ORDER_ID').split("_axx_")

        nick = order_data[0]
        server = order_data[1]
        donType = order_data[2]
        item = order_data[3]

        if donType == "pex":
            execmd(f"pex user {nick} group set {item}")
        else:
            pass

# Админ-панель: главная
@app.route("/admin/", methods = ["GET"])
@login_required
@rank_required(dbauthexecute, 1)
def admin():
    return render_template("admin.html", rank = get_rank(dbauthexecute), logined = True, username = session.get("user_id"))

# Админ-панель: добавление новости
@app.route("/admin/newpost/", methods = ["GET", "POST"])
@login_required
@rank_required(dbauthexecute, 2)
def newpost():
    if request.method == "POST":
        try:
            nowtime = f"{gmtime().tm_year}-{gmtime().tm_mon}-{gmtime().tm_mday}T{gmtime().tm_hour}:{gmtime().tm_min}"
            dbexecute(f"INSERT INTO `news`(`date`, `text`, `href`) VALUES (UNIX_TIMESTAMP(STR_TO_DATE('{request.form.get('date') if request.form.get('date') else nowtime}', '%Y-%m-%dT%H:%i')),'{request.form.get('text')}','{request.form.get('href')}')")
            flash("Успех!")
            log_admin(f"Администратор {session.get('user_id')} создал новость с текстом ниже. Результат: успех.")
            log_admin(request.form.get("text"))
            return render_template("admin_newpost.html", username = session.get("user_id"), logined = True, rank = get_rank(dbauthexecute))
        except Exception as e:
            flash("Произошла ошибка! Свяжитесь с IT-Отделом и занесите им банку сгущёнки. Ошибка:")
            flash(e)
            log_admin(f"Администратор {session.get('user_id')} попытался создать новость. Результат: ошибка.")
            log_admin(e, "ERROR")
            return render_template("admin_newpost.html", username = session.get("user_id"), logined = True, rank = get_rank(dbauthexecute))
    else:
        return render_template("admin_newpost.html", username = session.get("user_id"), logined = True, rank = get_rank(dbauthexecute))

# Админ-панель: удаление новости
@app.route("/admin/delpost/", methods = ["GET", "POST"])
@login_required
@rank_required(dbauthexecute, 2)
def delpost():
    if request.method == "POST":
        try:
            dbexecute('DELETE FROM news WHERE id = %d;' % (int(request.form.get("id"))))
            flash("Успех!")
            log_admin(f"Администратор {session.get('user_id')} удалил новость с ID {request.form.get('id')}. Результат: успех.")
            return render_template("admin_delpost.html", username = session.get("user_id"), logined = True, rank = get_rank(dbauthexecute))
        except Exception as e:
            log_admin(f"Администратор {session.get('user_id')} попытался удалить новость с ID {request.form.get('id')}. Результат: ошибка.")
            log_admin(e, "ERROR")
            flash("Произошла ошибка! Свяжитесь с IT-Отделом и занесите им банку сгущёнки. Ошибка:")
            flash(e)
            return render_template("admin_delpost.html", username = session.get("user_id"), logined = True, rank = get_rank(dbauthexecute))
    else:
        return render_template("admin_delpost.html", username = session.get("user_id"), logined = True, rank = get_rank(dbauthexecute))

# Админ-панель: бан игрока
@app.route("/admin/ban/", methods = ["GET", "POST"])
@login_required
@rank_required(dbauthexecute, 1)
def ban():
    if request.method == "POST":
        try:
            if int(request.form.get("banType")) == 0:
                resp = execmd(request.form.get("server"), "mbtempban", request.form.get("username"), request.form.get("time"), request.form.get("timeMult"), "-s", request.form.get("reason"))
                flash(resp)
                log_admin(f"Администратор {session.get('user_id')} забанил игрока {request.form.get('username')} на {request.form.get('time'), request.form.get('timeMult')} по причине: {request.form.get('reason')}")
                log_admin(f"Ответ сервера: {resp}")
            elif int(request.form.get("banType")) == 1:
                resp = execmd(request.form.get("server"), "mbban", request.form.get("username"), "-s", request.form.get("reason"))
                flash(resp)
                log_admin(f"Администратор {session.get('user_id')} забанил игрока {request.form.get('username')} по причине: {request.form.get('reason')}")
                log_admin(f"Ответ сервера: {resp}")
        except Exception as e:
            log_admin(f"Администратор {session.get('user_id')} попытался забанить игрока {request.form.get('username')} по причине: {request.form.get('reason')}. Результат: ошибка.")
            log_admin(e, "ERROR")
            flash("Произошла ошибка! Свяжитесь с IT-Отделом и занесите им банку сгущёнки. Ошибка:")
            flash(e)
            
    return render_template("admin_ban.html", rank = get_rank(dbauthexecute), logined = True, username = session.get("user_id"))

# Админ-панель: разбан игрока
@app.route("/admin/unban/", methods = ["GET", "POST"])
@login_required
@rank_required(dbauthexecute, 1)
def unban():
    if request.method == "POST":
        try:
            resp = execmd(request.form.get("server"), "mbunban", request.form.get("username"))
            flash(resp)
            log_admin(f"Администратор {session.get('user_id')} разбанил игрока {request.form.get('username')}.")
            log_admin(f"Ответ сервера: {resp}")
        except Exception as e:
            log_admin(f"Администратор {session.get('user_id')} попытался разбанить игрока {request.form.get('username')}. Результат: ошибка.")
            log_admin(e, "ERROR")
            flash("Произошла ошибка! Свяжитесь с IT-Отделом и занесите им банку сгущёнки. Ошибка:")
            flash(e)

    return render_template("admin_unban.html", rank = get_rank(dbauthexecute), logined = True, username = session.get("user_id"))

# Админ-панель: изменение группы(pex)
@app.route("/admin/pex/", methods = ["GET", "POST"])
@login_required
@rank_required(dbauthexecute, 2)
def pex():
    if request.method == "POST":
        try:
            resp = execmd(request.form.get("server"), "pex user", request.form.get("username"), "group", request.form.get("instr"), request.form.get("group"))
            flash(resp)
            log_admin(f"Администратор {session.get('user_id')} изменил({request.form.get('instr')}) групппу {request.form.get('group')} игроку {request.form.get('username')}.")
            log_admin(f"Ответ сервера: {resp}")
        except Exception as e:
            log_admin(f"Администратор {session.get('user_id')} попытался изменить({request.form.get('instr')}) группу {request.form.get('group')} игроку {request.form.get('username')}. Результат: ошибка.")
            log_admin(e, "ERROR")
            flash("Произошла ошибка! Свяжитесь с IT-Отделом и занесите им банку сгущёнки. Ошибка:")
            flash(e)
    
    return render_template("admin_pex.html", rank = get_rank(dbauthexecute), logined = True, username = session.get("user_id"))

# Админ-панель: перезапуск сервера
@app.route("/admin/restart/", methods = ["GET", "POST"])
@login_required
@rank_required(dbauthexecute, 3)
def restart():
    if request.method == "POST":
        try:
            resp = execmd(request.form.get("server"), "stop")
            flash(resp)
            log_admin(f"Администратор {session.get('user_id')} перезапустил сервер {request.form.get('server')}.")
            log_admin(f"Ответ сервера: {resp}")
        except Exception as e:
            log_admin(f"Администратор {session.get('user_id')} попытался перезапустить сервер {request.form.get('server')}. Результат: ошибка.")
            log_admin(e)
            flash("Произошла ошибка! Свяжитесь с IT-Отделом и занесите им банку сгущёнки. Ошибка:")
            flash(e)
    
    return render_template("admin_restart.html", rank = get_rank(dbauthexecute), logined = True, username = session.get("user_id"))

# Админ-панель: выполнение команды
@app.route("/admin/runcmd/", methods = ["GET", "POST"])
@login_required
@rank_required(dbauthexecute, 3)
def runcmd():
    if request.method == "POST":
        try:
            resp = execmd(request.form.get("server"), request.form.get("command"))
            for i in resp.split("\n"):
                flash(i)
            log_admin(f"Администратор {session.get('user_id')} выполнил команду '{request.form.get('command')}' на сервере {request.form.get('server')}.")
            log_admin(f"Ответ сервера: {resp}")
        except Exception as e:
            log_admin(f"Администратор {session.get('user_id')} попытался выполнить команду '{request.form.get('command')}' на сервере {request.form.get('server')}. Результат: ошибка.")
            log_admin(e)
            flash("Произошла ошибка! Свяжитесь с IT-Отделом и занесите им банку сгущёнки. Ошибка:")
            flash(e)
    
    return render_template("admin_runcmd.html", rank = get_rank(dbauthexecute), logined = True, username = session.get("user_id"))

# Админ-панель: изменение ранга администратора
@app.route("/admin/rank/", methods = ["GET", "POST"])
@login_required
@rank_required(dbauthexecute, 5)
def rank():
    if request.method == "POST":
        if int(request.form.get("rank")) < 0 or int(request.form.get("rank")) > 4:
            flash("Непрвильно указан ранг!")
            return render_template("admin_rank.html", rank = get_rank(dbauthexecute), logined = True, username = session.get("user_id"))
        # try:
        dbauthexecute(f"UPDATE dle_users SET `rank`={int(request.form.get('rank'))} WHERE `name`='{request.form.get('username')}';")
        log_admin(f"Администратор {session.get('user_id')} изменил ранг администратору {request.form.get('username')} на {request.form.get('rank')}.")
        # except Exception as e:
        #     log_admin(f"Администратор {session.get('user_id')} попытался изменить ранг администратору {request.form.get('username')} на {request.form.get('rank')}. Результат: ошибка.")
        #     log_admin(e)
        #     flash("Произошла ошибка! Свяжитесь с IT-Отделом и занесите им банку сгущёнки. Ошибка:")
        #     flash(e)
    
    return render_template("admin_rank.html", rank = get_rank(dbauthexecute), logined = True, username = session.get("user_id"))

# Запуск, ура
if __name__ == "__main__":
    app.run(host, port)