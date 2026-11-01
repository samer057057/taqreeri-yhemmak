import os, csv, io, hmac
from datetime import datetime, date
from functools import wraps
import requests
from flask import Flask, render_template, request, redirect, url_for, flash, session, Response, abort
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "CHANGE-ME-before-deploy")
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///taqreeri.db").replace("postgres://", "postgresql://")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["MAX_CONTENT_LENGTH"] = 8 * 1024 * 1024
db = SQLAlchemy(app)
CSRFProtect(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="staff")
    active = db.Column(db.Boolean, default=True)

class Device(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    brand = db.Column(db.String(50), nullable=False)
    model = db.Column(db.String(120), nullable=False)
    color = db.Column(db.String(50))
    capacity = db.Column(db.String(30))
    imei = db.Column(db.String(32), unique=True)
    serial = db.Column(db.String(80), unique=True)
    cost = db.Column(db.Float, nullable=False, default=0)
    status = db.Column(db.String(20), nullable=False, default="in_stock")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Operation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    kind = db.Column(db.String(20), nullable=False)
    device_in_id = db.Column(db.Integer, db.ForeignKey("device.id"))
    device_out_id = db.Column(db.Integer, db.ForeignKey("device.id"))
    customer = db.Column(db.String(120))
    counterparty = db.Column(db.String(120))
    amount = db.Column(db.Float, nullable=False, default=0)
    difference = db.Column(db.Float, nullable=False, default=0)
    notes = db.Column(db.Text)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    device_in = db.relationship("Device", foreign_keys=[device_in_id])
    device_out = db.relationship("Device", foreign_keys=[device_out_id])
    user = db.relationship("User")

class Audit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    action = db.Column(db.String(100), nullable=False)
    detail = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship("User")

def current_user():
    uid = session.get("uid")
    return db.session.get(User, uid) if uid else None

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user():
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper

def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        u = current_user()
        if not u: return redirect(url_for("login"))
        if u.role != "admin": abort(403)
        return fn(*args, **kwargs)
    return wrapper

def audit(action, detail=""):
    db.session.add(Audit(user_id=current_user().id, action=action, detail=detail))

def discord_send(content):
    hook = os.environ.get("DISCORD_WEBHOOK_URL")
    if not hook: return
    try:
        requests.post(hook, json={"content": content[:1900]}, timeout=8).raise_for_status()
    except requests.RequestException:
        app.logger.exception("Discord notification failed")

@app.route("/setup", methods=["GET", "POST"])
def setup():
    if User.query.first():
        abort(404)
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        if len(password) < 12:
            flash("اجعل كلمة المرور 12 حرفاً على الأقل.")
        elif not username:
            flash("اسم المستخدم مطلوب.")
        else:
            db.session.add(User(username=username, password_hash=generate_password_hash(password), role="admin"))
            db.session.commit()
            flash("تم إنشاء حساب المدير. سجل الدخول.")
            return redirect(url_for("login"))
    return render_template("setup.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = User.query.filter_by(username=request.form["username"].strip(), active=True).first()
        if u and check_password_hash(u.password_hash, request.form["password"]):
            session.clear(); session["uid"] = u.id
            return redirect(url_for("dashboard"))
        flash("بيانات الدخول غير صحيحة.")
    return render_template("login.html")

@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/")
@login_required
def dashboard():
    today = date.today()
    ops = Operation.query.order_by(Operation.created_at.desc()).limit(10).all()
    day_ops = Operation.query.filter(db.func.date(Operation.created_at) == today.isoformat()).all()
    sales = [x for x in day_ops if x.kind == "sale"]
    buys = [x for x in day_ops if x.kind == "purchase"]
    trades = [x for x in day_ops if x.kind == "trade"]
    stock = Device.query.filter_by(status="in_stock").count()
    profit = sum((x.amount - (x.device_out.cost if x.device_out else 0)) for x in sales)
    return render_template("dashboard.html", ops=ops, stock=stock,
        sales=sum(x.amount for x in sales), purchases=sum(x.amount for x in buys),
        profit=profit, trades=len(trades), users=User.query.count())

@app.route("/inventory")
@login_required
def inventory():
    q = request.args.get("q", "").strip()
    query = Device.query.filter_by(status="in_stock")
    if q:
        query = query.filter(db.or_(Device.model.ilike(f"%{q}%"), Device.imei.ilike(f"%{q}%"), Device.serial.ilike(f"%{q}%")))
    devices = query.order_by(Device.created_at.desc()).all()
    return render_template("inventory.html", devices=devices)

@app.route("/device/add", methods=["GET", "POST"])
@login_required
def device_add():
    if request.method == "POST":
        imei = request.form.get("imei","").strip() or None
        serial = request.form.get("serial","").strip() or None
        if (imei and Device.query.filter_by(imei=imei).first()) or (serial and Device.query.filter_by(serial=serial).first()):
            flash("رقم IMEI أو الرقم التسلسلي مسجل مسبقاً.")
        else:
            d = Device(brand=request.form["brand"], model=request.form["model"].strip(),
                color=request.form.get("color"), capacity=request.form.get("capacity"),
                imei=imei, serial=serial, cost=float(request.form.get("cost") or 0))
            db.session.add(d); db.session.flush()
            audit("إضافة جهاز", f"{d.brand} {d.model} / IMEI {d.imei or '-'}")
            db.session.commit()
            flash("تمت إضافة الجهاز للمخزون.")
            discord_send(f"📦 **إضافة مخزون**\n{d.brand} {d.model}\nIMEI: {d.imei or '-'}\nبواسطة: {current_user().username}")
            return redirect(url_for("inventory"))
    return render_template("device_form.html")

@app.route("/operation", methods=["GET", "POST"])
@login_required
def operation():
    stock = Device.query.filter_by(status="in_stock").order_by(Device.model).all()
    if request.method == "POST":
        kind = request.form["kind"]
        in_id = request.form.get("device_in_id") or None
        out_id = request.form.get("device_out_id") or None
        amount = float(request.form.get("amount") or 0)
        diff = float(request.form.get("difference") or 0)
        incoming = db.session.get(Device, int(in_id)) if in_id else None
        outgoing = db.session.get(Device, int(out_id)) if out_id else None
        if kind == "sale" and (not outgoing or outgoing.status != "in_stock"):
            flash("اختر جهازاً متاحاً للبيع."); return redirect(url_for("operation"))
        if kind == "purchase" and not incoming:
            flash("أضف الجهاز أولاً من صفحة المخزون، ثم سجّل الشراء."); return redirect(url_for("operation"))
        if kind == "trade" and (not incoming or not outgoing or incoming.id == outgoing.id or outgoing.status != "in_stock"):
            flash("في الاستبدال اختر جهازاً مستلماً وجهازاً خارجاً متاحاً."); return redirect(url_for("operation"))
        if kind == "sale": outgoing.status = "sold"
        if kind == "trade":
            outgoing.status = "traded_out"
            incoming.status = "in_stock"
        op = Operation(kind=kind, device_in_id=incoming.id if incoming else None,
            device_out_id=outgoing.id if outgoing else None, customer=request.form.get("customer"),
            counterparty=request.form.get("counterparty"), amount=amount, difference=diff,
            notes=request.form.get("notes"), user_id=current_user().id)
        db.session.add(op); audit("تسجيل عملية", f"{kind} / {amount} SAR"); db.session.commit()
        labels = {"sale":"بيع","purchase":"شراء","trade":"استبدال"}
        discord_send(f"🧾 **{labels.get(kind,kind)} جديد**\nالعميل: {op.customer or '-'}\nالجهاز الداخل: {incoming.model if incoming else '-'}\nالجهاز الخارج: {outgoing.model if outgoing else '-'}\nالمبلغ: {amount:,.2f} ر.س\nالفرق: {diff:,.2f} ر.س\nالموظف: {current_user().username}\nملاحظات: {op.notes or '-'}")
        flash("تم حفظ العملية وتحديث المخزون.")
        return redirect(url_for("dashboard"))
    return render_template("operation.html", stock=stock)

@app.route("/reports")
@login_required
def reports():
    ops = Operation.query.order_by(Operation.created_at.desc()).all()
    return render_template("reports.html", ops=ops)

@app.route("/export.csv")
@login_required
def export_csv():
    out = io.StringIO(); w = csv.writer(out)
    w.writerow(["date","type","customer","device_in","device_out","amount","difference","staff","notes"])
    for x in Operation.query.order_by(Operation.created_at.desc()).all():
        w.writerow([x.created_at.isoformat(),x.kind,x.customer,x.device_in.model if x.device_in else "",x.device_out.model if x.device_out else "",x.amount,x.difference,x.user.username,x.notes])
    return Response("\\ufeff"+out.getvalue(), mimetype="text/csv", headers={"Content-Disposition":"attachment; filename=taqreeri-report.csv"})

@app.route("/users", methods=["GET", "POST"])
@admin_required
def users():
    if request.method == "POST":
        name=request.form["username"].strip(); pw=request.form["password"]; role=request.form["role"]
        if User.query.filter_by(username=name).first(): flash("اسم المستخدم مستخدم.")
        elif len(pw)<12: flash("كلمة المرور يجب أن تكون 12 حرفاً على الأقل.")
        else:
            db.session.add(User(username=name,password_hash=generate_password_hash(pw),role=role))
            audit("إنشاء مستخدم", name); db.session.commit(); flash("تم إنشاء المستخدم.")
    return render_template("users.html", users=User.query.order_by(User.id).all())

@app.route("/daily-report")
def daily_report():
    secret=os.environ.get("DAILY_REPORT_SECRET","")
    supplied=request.headers.get("X-Report-Secret","")
    if not secret or not hmac.compare_digest(secret,supplied): abort(403)
    d=date.today()
    ops=Operation.query.filter(db.func.date(Operation.created_at)==d.isoformat()).all()
    sales=[x for x in ops if x.kind=="sale"]; buys=[x for x in ops if x.kind=="purchase"]; trades=[x for x in ops if x.kind=="trade"]
    text=(f"📊 **تقرير تقريري يهمك — {d.isoformat()}**\n"
      f"المبيعات: {sum(x.amount for x in sales):,.2f} ر.س ({len(sales)} عملية)\n"
      f"المشتريات: {sum(x.amount for x in buys):,.2f} ر.س ({len(buys)} عملية)\n"
      f"الاستبدالات: {len(trades)}\n"
      f"صافي ربح المبيعات التقديري: {sum(x.amount-(x.device_out.cost if x.device_out else 0) for x in sales):,.2f} ر.س\n"
      f"الأجهزة المتاحة: {Device.query.filter_by(status='in_stock').count()}")
    discord_send(text)
    return {"ok":True,"date":d.isoformat(),"operations":len(ops)}

@app.route("/health")
def health(): return {"status":"ok"}

with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(debug=False)
