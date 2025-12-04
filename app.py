from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from abc import ABC, abstractmethod
from datetime import datetime, date
import random
import string

app = Flask(__name__)


#Flask and Database Config

app.config['SECRET_KEY'] = '1234567890'
#SQLite DB file
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///mypass2.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

#Auto lock after inactivity period
AUTO_LOCK_MINUTES = 5
AUTO_LOCK_SECONDS = AUTO_LOCK_MINUTES * 60


#SessionManager --> Singleton

class SessionManager:
    #Stores currently logged in user in Flask session and tracks inactivity time
    instance = None

    def __new__(cls):
        if cls.instance is None:
            cls.instance = super(SessionManager, cls).__new__(cls)
        return cls.instance

    #Saves timestamp and tracks user login
    def login(self, user):
        session['user_id'] = user.id
        session['last_activity'] = datetime.utcnow().timestamp()

    
    def logout(self):
        session.clear() #clear session data

    #return ID of currently logged in user
    def get_current_user(self):
        user_id = session.get('user_id')
        if user_id is None:
            return None
        now_ts = datetime.utcnow().timestamp()
        last = session.get('last_activity')

        if last is not None and now_ts - last > AUTO_LOCK_SECONDS: #Automatic logout after inactivity
            # Auto-lock
            self.logout()
            flash("Session auto-locked after inactivity. Please log in again.", "warning")
            return None

        #refresh activity
        session['last_activity'] = now_ts
        return User.query.get(user_id)


session_manager = SessionManager() #create global SessionManager instance

# Database Tables
class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_master_weak = db.Column(db.Boolean, default=False) #Track if weak master password

    #Security question storage
    question1 = db.Column(db.String(255), nullable=False)
    answer1 = db.Column(db.String(255), nullable=False)
    question2 = db.Column(db.String(255), nullable=False)
    answer2 = db.Column(db.String(255), nullable=False)
    question3 = db.Column(db.String(255), nullable=False)
    answer3 = db.Column(db.String(255), nullable=False)

    #define relationships
    login_items = db.relationship('LoginItem', backref='user', lazy=True)
    credit_cards = db.relationship('CreditCardItem', backref='user', lazy=True)
    identities = db.relationship('IdentityItem', backref='user', lazy=True)
    secure_notes = db.relationship('SecureNoteItem', backref='user', lazy=True)

    def set_password(self, password: str):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8') #store encrypted master password

    def check_password(self, password: str) -> bool:
        return bcrypt.check_password_hash(self.password_hash, password) #check passqord using hashes


class LoginItem(db.Model):
    __tablename__ = 'login_items'
    id = db.Column(db.Integer, primary_key=True)
    site_name = db.Column(db.String(255), nullable=False)
    username = db.Column(db.String(255), nullable=False)
    password = db.Column(db.String(255), nullable=False)  #masked in UI 
    url = db.Column(db.String(255), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

#Store credit card info
class CreditCardItem(db.Model):
    __tablename__ = 'credit_cards'
    id = db.Column(db.Integer, primary_key=True)
    cardholder_name = db.Column(db.String(255), nullable=False)
    card_number = db.Column(db.String(255), nullable=False)
    cvv = db.Column(db.String(10), nullable=False)
    expiration_month = db.Column(db.String(2), nullable=False)
    expiration_year = db.Column(db.String(4), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

#Store identity info
class IdentityItem(db.Model):
    __tablename__ = 'identities'
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(255), nullable=False)
    passport_number = db.Column(db.String(255), nullable=True)
    passport_expiration_month = db.Column(db.String(2), nullable=True)
    passport_expiration_year = db.Column(db.String(4), nullable=True)
    license_number = db.Column(db.String(255), nullable=True)
    license_expiration_month = db.Column(db.String(2), nullable=True)
    license_expiration_year = db.Column(db.String(4), nullable=True)
    ssn = db.Column(db.String(255), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

#Store other notes made by user
class SecureNoteItem(db.Model):
    __tablename__ = 'secure_notes'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)


#Data mask using proxy pattern
class SecretFieldProxy:
    def __init__(self, raw_value: str):
        self.raw = raw_value or ""

    def masked(self):
        #fully mask the value
        return "*" * len(self.raw)

    #unmask value
    def unmasked(self):
        return self.raw

# password generator using builder pattern
class PasswordBuilder:
    def __init__(self):
        self.length = 12
        self.use_upper = True
        self.use_lower = True
        self.use_digits = True
        self.use_symbols = True

    #Define flags (set by user)
    def set_length(self, length: int):
        self.length = max(4, min(length, 64))  

    def enable_upper(self, flag: bool):
        self.use_upper = flag

    def enable_lower(self, flag: bool):
        self.use_lower = flag

    def enable_digits(self, flag: bool):
        self.use_digits = flag

    def enable_symbols(self, flag: bool):
        self.use_symbols = flag

    #Build + return randomized password
    def build(self) -> str:
        pool = ""
        if self.use_upper:
            pool += string.ascii_uppercase
        if self.use_lower:
            pool += string.ascii_lowercase
        if self.use_digits:
            pool += string.digits
        if self.use_symbols:
            pool += "!@#$%^&*()-_=+[]{};:,.?/"
        #lowercase - utilized in case where user unchecks everything
        if not pool:
            pool = string.ascii_lowercase
        return "".join(random.choice(pool) for _ in range(self.length))

#Define director
class PasswordDirector:
    def __init__(self, builder: PasswordBuilder):
        self.builder = builder

    def construct(self, length, upper, lower, digits, symbols):
        self.builder.set_length(length)
        self.builder.enable_upper(upper)
        self.builder.enable_lower(lower)
        self.builder.enable_digits(digits)
        self.builder.enable_symbols(symbols)
        return self.builder.build()

#Check password strength
def is_weak_password(pw: str) -> bool:
    if len(pw) < 10:
        return True
    has_upper = any(c.isupper() for c in pw)
    has_lower = any(c.islower() for c in pw)
    has_digit = any(c.isdigit() for c in pw)
    return not (has_upper and has_lower and has_digit)

#Notificaton logic using observer pattern

class Observer(ABC): #abstract observer
    @abstractmethod
    def update(self, message: str):
        pass


class InAppNotificationObserver(Observer): #concrete observer
    def __init__(self):
        self.messages = []

    def update(self, message: str):
        self.messages.append(message)


class NotificationSubject:
    def __init__(self):
        self.observers = []

    def attach(self, observer: Observer): #attach observer
        self.observers.append(observer)

    def detach(self, observer: Observer): #delete observer
        if observer in self.observers:
            self.observers.remove(observer)

    def notify(self, message: str): #send message to observers
        for obs in self.observers:
            obs.update(message)

    def evaluate_user(self, user: User):
        #evaluate password strngth
        if user.is_master_weak:
            self.notify("Your master password appears weak. Consider increasing its length and incorporating mixed characters.")
        for item in user.login_items:
            if is_weak_password(item.password):
                self.notify(f"Weak password detected for site '{item.site_name}'.")

        #evaluate if credit card expired
        today = date.today()
        for card in user.credit_cards:
            try:
                month = int(card.expiration_month)
                year = int(card.expiration_year)
                exp_date = date(year, month, 1)
                if exp_date < date(today.year, today.month, 1):
                    self.notify(f"Credit card ending in {card.card_number[-4:]} is expired.")
                elif exp_date == date(today.year, today.month, 1):
                    self.notify(f"Credit card ending in {card.card_number[-4:]} expires this month.")
            except ValueError:
                continue

        #check passport/license expiration
        for ident in user.identities:
            if ident.passport_expiration_month and ident.passport_expiration_year:
                try:
                    pm = int(ident.passport_expiration_month)
                    py = int(ident.passport_expiration_year)
                    pexp = date(py, pm, 1)
                    if pexp < date(today.year, today.month, 1):
                        self.notify(f"Passport for {ident.full_name} is expired.")
                    elif pexp == date(today.year, today.month, 1):
                        self.notify(f"Passport for {ident.full_name} expires this month.")
                except ValueError:
                    pass
            if ident.license_expiration_month and ident.license_expiration_year:
                try:
                    lm = int(ident.license_expiration_month)
                    ly = int(ident.license_expiration_year)
                    lexp = date(ly, lm, 1)
                    if lexp < date(today.year, today.month, 1):
                        self.notify(f"License for {ident.full_name} is expired.")
                    elif lexp == date(today.year, today.month, 1):
                        self.notify(f"License for {ident.full_name} expires this month.")
                except ValueError:
                    pass


#Define dashboard mediator
class DashboardMediator:
    def __init__(self, subject_cls):
        self.subject_cls = subject_cls

    def build_context(self, user: User): #define context dictionary
        subject = self.subject_cls()
        observer = InAppNotificationObserver()
        subject.attach(observer)
        subject.evaluate_user(user)
        return {
            "notifications": observer.messages
        }


dashboard_mediator = DashboardMediator(NotificationSubject) #instantiate mediator

def require_login():
    user = session_manager.get_current_user()
    if user is None:
        if 'user_id' not in session:
            flash("Please log in first.", "danger")
        return None
    return user


#Define app routes

@app.route('/') #landing route
def index(): 
    if session_manager.get_current_user():
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST']) #registration roufe
def register():
    if request.method == 'POST':
        email = request.form['email']
        master_password = request.form['master_password']
        q1 = request.form['question1']
        a1 = request.form['answer1']
        q2 = request.form['question2']
        a2 = request.form['answer2']
        q3 = request.form['question3']
        a3 = request.form['answer3']

        #check if email already in use
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'danger')
            return redirect(url_for('register'))

        #create/save new users
        user = User(
            email=email,
            question1=q1, answer1=a1,
            question2=q2, answer2=a2,
            question3=q3, answer3=a3,
        )
        user.set_password(master_password)
        user.is_master_weak = is_weak_password(master_password)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful. Please log in to continue.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

#login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        master_password = request.form['master_password']
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(master_password):
            session_manager.login(user)
            flash('Logged in successfully', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password', 'danger')

    return render_template('login.html')

#logout route
@app.route('/logout')
def logout():
    session_manager.logout()
    flash('Logged out', 'info')
    return redirect(url_for('login'))

#Recovery logic
class RecoveryHandler(ABC): #abstract handler
    def __init__(self):
        self.next = None

    def set_next(self, handler: "RecoveryHandler"): #define next successor
        self.next = handler
        return handler

    @abstractmethod
    def handle(self, user: User, answers: dict) -> bool: #validate anmswer
        if self.next:
            return self.next.handle(user, answers)
        return True


class Question1Handler(RecoveryHandler): #handler for first answer
    def handle(self, user: User, answers: dict) -> bool:
        given = answers.get("answer1", "").strip().lower()
        expected = (user.answer1 or "").strip().lower()
        if given != expected:
            return False
        return super().handle(user, answers)


class Question2Handler(RecoveryHandler): #handler for second answer
    def handle(self, user: User, answers: dict) -> bool:
        given = answers.get("answer2", "").strip().lower()
        expected = (user.answer2 or "").strip().lower()
        if given != expected:
            return False
        return super().handle(user, answers)


class Question3Handler(RecoveryHandler): #handlker for 3rd answer
    def handle(self, user: User, answers: dict) -> bool:
        given = answers.get("answer3", "").strip().lower()
        expected = (user.answer3 or "").strip().lower()
        if given != expected:
            return False
        return super().handle(user, answers)


@app.route('/recover', methods=['GET', 'POST']) #recovery route
def recover():
    user_for_display = None

    if request.method == 'POST':
        email = request.form['email']
        new_password = request.form['new_password']
        a1 = request.form['answer1']
        a2 = request.form['answer2']
        a3 = request.form['answer3']
        user = User.query.filter_by(email=email).first()
        if not user:
            flash('No account found for specified email.', 'danger')
            return render_template('recover.html', user=None)

        #instantiate recovery chain
        h1 = Question1Handler()
        h2 = Question2Handler()
        h3 = Question3Handler()
        h1.set_next(h2).set_next(h3)

        answers = {
            "answer1": a1,
            "answer2": a2,
            "answer3": a3,
        }

        if h1.handle(user, answers):
            user.set_password(new_password)
            user.is_master_weak = is_weak_password(new_password)
            db.session.commit()
            flash('Master password reset. Please log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Security answers incorrect.', 'danger')
            user_for_display = user  

    return render_template('recover.html', user=user_for_display)

@app.route('/dashboard') #dashboard route
def dashboard():
    user = require_login()
    if user is None:
        return redirect(url_for('login'))
    context = dashboard_mediator.build_context(user) #use mediator to build context
    return render_template('dashboard.html', **context)

#login items route
@app.route('/vault/logins', methods=['GET', 'POST'])
def vault_logins():
    user = require_login()
    if user is None:
        return redirect(url_for('login'))

    #create new item
    if request.method == 'POST':
        site_name = request.form['site_name']
        username = request.form['username']
        password = request.form['password']
        url_val = request.form['url']
        item = LoginItem(
            site_name=site_name,
            username=username,
            password=password,
            url=url_val,
            user_id=user.id
        )
        db.session.add(item)
        db.session.commit()
        flash('Login item saved.', 'success')
    #fetch items from DB
    db_items = LoginItem.query.filter_by(user_id=user.id).all()

    #use proxy to mask passwords
    items = []
    for it in db_items:
        proxy = SecretFieldProxy(it.password)
        items.append({
            'id': it.id,
            'site_name': it.site_name,
            'username': it.username,
            'password_masked': proxy.masked(),
            'password_full': proxy.unmasked(),
            'url': it.url
        })

    return render_template('vault_logins.html', items=items, edit_item=None)

#edit route
@app.route('/vault/logins/edit/<int:item_id>', methods=['GET', 'POST'])
def edit_login_item(item_id):
    user = require_login()
    if user is None:
        return redirect(url_for('login'))
    item = LoginItem.query.filter_by(id=item_id, user_id=user.id).first()
    if not item:
        flash('Login item not found.', 'danger')
        return redirect(url_for('vault_logins'))
    if request.method == 'POST':
        #Update item
        item.site_name = request.form['site_name']
        item.username = request.form['username']
        item.password = request.form['password']
        item.url = request.form['url']
        db.session.commit()
        flash('Login item updated.', 'success')
        return redirect(url_for('vault_logins'))
    db_items = LoginItem.query.filter_by(user_id=user.id).all()
    items = []
    for it in db_items:
        proxy = SecretFieldProxy(it.password)
        items.append({
            'id': it.id,
            'site_name': it.site_name,
            'username': it.username,
            'password_masked': proxy.masked(),
            'password_full': proxy.unmasked(),
            'url': it.url
        })
    #pass current item to auto-fill form when started
    return render_template('vault_logins.html', items=items, edit_item=item)

#delete route
@app.route('/vault/logins/delete/<int:item_id>', methods=['POST'])
def delete_login_item(item_id):
    user = require_login()
    if user is None:
        return redirect(url_for('login'))
    item = LoginItem.query.filter_by(id=item_id, user_id=user.id).first()
    if item:
        db.session.delete(item)
        db.session.commit()
        flash('Login item deleted.', 'info')
    else:
        flash('Item not found.', 'danger')
    return redirect(url_for('vault_logins'))


#credit card route
@app.route('/vault/cards', methods=['GET', 'POST'])
def vault_cards():
    user = require_login()
    if user is None:
        return redirect(url_for('login'))

    # create new card
    if request.method == 'POST':
        name = request.form['cardholder_name']
        number = request.form['card_number']
        cvv_val = request.form['cvv']
        exp_month = request.form['expiration_month']
        exp_year = request.form['expiration_year']
        card = CreditCardItem(
            cardholder_name=name,
            card_number=number,
            cvv=cvv_val,
            expiration_month=exp_month,
            expiration_year=exp_year,
            user_id=user.id
        )
        db.session.add(card)
        db.session.commit()
        flash('Credit card saved.', 'success')

    #get and mask card data
    db_cards = CreditCardItem.query.filter_by(user_id=user.id).all()

    cards = []
    for c in db_cards:
        number_proxy = SecretFieldProxy(c.card_number)
        cvv_proxy = SecretFieldProxy(c.cvv)
        cards.append({
            'id': c.id,
            'cardholder_name': c.cardholder_name,
            'card_number_masked': number_proxy.masked(),
            'card_number_full': number_proxy.unmasked(),
            'cvv_masked': cvv_proxy.masked(),
            'cvv_full': cvv_proxy.unmasked(),
            'expiration': f"{c.expiration_month}/{c.expiration_year}",
        })

    return render_template('vault_cards.html', cards=cards, edit_card=None)


#edit route for credit cards
@app.route('/vault/cards/edit/<int:card_id>', methods=['GET', 'POST'])
def edit_card(card_id):
    user = require_login()
    if user is None:
        return redirect(url_for('login'))
    card = CreditCardItem.query.filter_by(id=card_id, user_id=user.id).first()
    if not card:
        flash('Credit card not found.', 'danger')
        return redirect(url_for('vault_cards'))
    if request.method == 'POST':
        card.cardholder_name = request.form['cardholder_name']
        card.card_number = request.form['card_number']
        card.cvv = request.form['cvv']
        card.expiration_month = request.form['expiration_month']
        card.expiration_year = request.form['expiration_year']
        db.session.commit()
        flash('Credit card updated.', 'success')
        return redirect(url_for('vault_cards'))
    db_cards = CreditCardItem.query.filter_by(user_id=user.id).all()
    cards = []
    for c in db_cards:
        number_proxy = SecretFieldProxy(c.card_number)
        cvv_proxy = SecretFieldProxy(c.cvv)
        cards.append({
            'id': c.id,
            'cardholder_name': c.cardholder_name,
            'card_number_masked': number_proxy.masked(),
            'card_number_full': number_proxy.unmasked(),
            'cvv_masked': cvv_proxy.masked(),
            'cvv_full': cvv_proxy.unmasked(),
            'expiration': f"{c.expiration_month}/{c.expiration_year}",
        })
    return render_template('vault_cards.html', cards=cards, edit_card=card)

#delete route for credit cards
@app.route('/vault/cards/delete/<int:card_id>', methods=['POST'])
def delete_card(card_id):
    user = require_login()
    if user is None:
        return redirect(url_for('login'))
    card = CreditCardItem.query.filter_by(id=card_id, user_id=user.id).first()
    if card:
        db.session.delete(card)
        db.session.commit()
        flash('Credit card deleted.', 'info')
    else:
        flash('Card not found.', 'danger')
    return redirect(url_for('vault_cards'))

#identities page route
@app.route('/vault/identities', methods=['GET', 'POST'])
def vault_identities():
    user = require_login()
    if user is None:
        return redirect(url_for('login'))
    if request.method == 'POST':
        full_name = request.form['full_name']
        passport_number = request.form.get('passport_number', '')
        passport_expiration_month = request.form.get('passport_expiration_month', '')
        passport_expiration_year = request.form.get('passport_expiration_year', '')
        license_number = request.form.get('license_number', '')
        license_expiration_month = request.form.get('license_expiration_month', '')
        license_expiration_year = request.form.get('license_expiration_year', '')
        ssn = request.form.get('ssn', '')
        ident = IdentityItem(
            full_name=full_name,
            passport_number=passport_number,
            passport_expiration_month=passport_expiration_month,
            passport_expiration_year=passport_expiration_year,
            license_number=license_number,
            license_expiration_month=license_expiration_month,
            license_expiration_year=license_expiration_year,
            ssn=ssn,
            user_id=user.id
        )
        db.session.add(ident)
        db.session.commit()
        flash('Identity saved.', 'success')

    #get idenityt and mask sensitive data
    db_identities = IdentityItem.query.filter_by(user_id=user.id).all()
    identities = []
    for ident in db_identities:
        passport_proxy = SecretFieldProxy(ident.passport_number or "")
        license_proxy = SecretFieldProxy(ident.license_number or "")
        ssn_proxy = SecretFieldProxy(ident.ssn or "")
        identities.append({
            'id': ident.id,
            'full_name': ident.full_name,
            'passport_masked': passport_proxy.masked() if ident.passport_number else "",
            'passport_full': passport_proxy.unmasked(),
            'passport_expiration': f"{ident.passport_expiration_month}/{ident.passport_expiration_year}" if ident.passport_expiration_month and ident.passport_expiration_year else "",
            'license_masked': license_proxy.masked() if ident.license_number else "",
            'license_full': license_proxy.unmasked(),
            'license_expiration': f"{ident.license_expiration_month}/{ident.license_expiration_year}" if ident.license_expiration_month and ident.license_expiration_year else "",
            'ssn_masked': ssn_proxy.masked() if ident.ssn else "",
            'ssn_full': ssn_proxy.unmasked(),
        })

    return render_template('vault_identities.html', identities=identities, edit_identity=None)

#identity edit route
@app.route('/vault/identities/edit/<int:ident_id>', methods=['GET', 'POST'])
def edit_identity(ident_id):
    user = require_login()
    if user is None:
        return redirect(url_for('login'))
    ident = IdentityItem.query.filter_by(id=ident_id, user_id=user.id).first()
    if not ident:
        flash('Identity not found.', 'danger')
        return redirect(url_for('vault_identities'))
    if request.method == 'POST':
        ident.full_name = request.form['full_name']
        ident.passport_number = request.form.get('passport_number', '')
        ident.passport_expiration_month = request.form.get('passport_expiration_month', '')
        ident.passport_expiration_year = request.form.get('passport_expiration_year', '')
        ident.license_number = request.form.get('license_number', '')
        ident.license_expiration_month = request.form.get('license_expiration_month', '')
        ident.license_expiration_year = request.form.get('license_expiration_year', '')
        ident.ssn = request.form.get('ssn', '')
        db.session.commit()
        flash('Identity updated.', 'success')
        return redirect(url_for('vault_identities'))
    db_identities = IdentityItem.query.filter_by(user_id=user.id).all()
    identities = []
    for i in db_identities:
        passport_proxy = SecretFieldProxy(i.passport_number or "")
        license_proxy = SecretFieldProxy(i.license_number or "")
        ssn_proxy = SecretFieldProxy(i.ssn or "")
        identities.append({
            'id': i.id,
            'full_name': i.full_name,
            'passport_masked': passport_proxy.masked() if i.passport_number else "",
            'passport_full': passport_proxy.unmasked(),
            'passport_expiration': f"{i.passport_expiration_month}/{i.passport_expiration_year}" if i.passport_expiration_month and i.passport_expiration_year else "",
            'license_masked': license_proxy.masked() if i.license_number else "",
            'license_full': license_proxy.unmasked(),
            'license_expiration': f"{i.license_expiration_month}/{i.license_expiration_year}" if i.license_expiration_month and i.license_expiration_year else "",
            'ssn_masked': ssn_proxy.masked() if i.ssn else "",
            'ssn_full': ssn_proxy.unmasked(),
        })

    return render_template('vault_identities.html', identities=identities, edit_identity=ident)

#identity delete route
@app.route('/vault/identities/delete/<int:ident_id>', methods=['POST'])
def delete_identity(ident_id):
    user = require_login()
    if user is None:
        return redirect(url_for('login'))
    ident = IdentityItem.query.filter_by(id=ident_id, user_id=user.id).first()
    if ident:
        db.session.delete(ident)
        db.session.commit()
        flash('Identity deleted.', 'info')
    else:
        flash('Identity not found.', 'danger')
    return redirect(url_for('vault_identities'))


#Secure notes route - used in case user has data not fitting into predefined categories
@app.route('/vault/notes', methods=['GET', 'POST'])
def vault_notes():
    user = require_login()
    if user is None:
        return redirect(url_for('login'))
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']

        note = SecureNoteItem(
            title=title,
            content=content,
            user_id=user.id
        )
        db.session.add(note)
        db.session.commit()
        flash('Secure note saved.', 'success')
    notes = SecureNoteItem.query.filter_by(user_id=user.id).all()
    return render_template('vault_notes.html', notes=notes, edit_note=None)

#secure note edit route
@app.route('/vault/notes/edit/<int:note_id>', methods=['GET', 'POST'])
def edit_note(note_id):
    user = require_login()
    if user is None:
        return redirect(url_for('login'))
    note = SecureNoteItem.query.filter_by(id=note_id, user_id=user.id).first()
    if not note:
        flash('Note not found.', 'danger')
        return redirect(url_for('vault_notes'))
    if request.method == 'POST':
        note.title = request.form['title']
        note.content = request.form['content']
        db.session.commit()
        flash('Secure note updated.', 'success')
        return redirect(url_for('vault_notes'))
    notes = SecureNoteItem.query.filter_by(user_id=user.id).all()
    return render_template('vault_notes.html', notes=notes, edit_note=note)

#secure note delete route
@app.route('/vault/notes/delete/<int:note_id>', methods=['POST'])
def delete_note(note_id):
    user = require_login()
    if user is None:
        return redirect(url_for('login'))
    note = SecureNoteItem.query.filter_by(id=note_id, user_id=user.id).first()
    if note:
        db.session.delete(note)
        db.session.commit()
        flash('Secure note deleted.', 'info')
    else:
        flash('Note not found.', 'danger')
    return redirect(url_for('vault_notes'))


#password generator route
@app.route('/password-generator', methods=['GET', 'POST'])
def password_generator():
    user = require_login()
    if user is None:
        return redirect(url_for('login'))
    generated = None #hold generated pasword
 
    if request.method == 'POST':
        try:
            length = int(request.form.get('length', 12)) #get length
        except ValueError:
            length = 12

        #check flags
        use_upper = 'use_upper' in request.form
        use_lower = 'use_lower' in request.form
        use_digits = 'use_digits' in request.form
        use_symbols = 'use_symbols' in request.form

        #use passwordBuilder and PasswordDirector to generate
        builder = PasswordBuilder()
        director = PasswordDirector(builder)
        generated = director.construct(length, use_upper, use_lower, use_digits, use_symbols)
        flash('Password generated.', 'success')

    return render_template('password_generator.html', generated=generated)

#start app
if __name__ == '__main__':
    with app.app_context():
        db.create_all()  #create tables

    app.run(debug=True, port=5001) #run flask
