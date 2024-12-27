from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from datetime import datetime
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from config import SECRET_KEY, SQLALCHEMY_DATABASE_URI, SQLALCHEMY_TRACK_MODIFICATIONS

app = Flask(__name__)
app.secret_key = SECRET_KEY

# Настройка подключения к PostgreSQL
app.config['SQLALCHEMY_DATABASE_URI'] = SQLALCHEMY_DATABASE_URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = SQLALCHEMY_TRACK_MODIFICATIONS

db = SQLAlchemy(app)
migrate = Migrate(app, db)

##############################################################################
# МОДЕЛИ
##############################################################################

# models.py

class SystemSetting(db.Model):
    __tablename__ = 'system_settings'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), unique=True, nullable=False, comment="Название настройки")
    value = db.Column(db.Boolean, nullable=False, default=True, comment="Значение настройки")


class Organization(db.Model):
    __tablename__ = 'organizations'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), unique=True, nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False, comment="Статус организации (активна/заблокирована)")

    users = db.relationship('User', back_populates='organization', lazy=True)


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_moderator = db.Column(db.Boolean, default=False, nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False, comment="Статус пользователя (активен/заблокирован)")

    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=True)
    organization = db.relationship("Organization", back_populates="users")

    def set_password(self, password: str):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)


class Object(db.Model):
    __tablename__ = 'objects'
    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    author = db.relationship("User", backref="objects")


class Attribute1(db.Model):
    __tablename__ = 'attribute1'
    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    full_name_information_system = db.Column(db.String(255), nullable=True, comment="Полное наименование информационной системы")
    short_name_information_system = db.Column(db.String(255), nullable=True, comment="Сокращённое наименование информационной системы")

    full_name_operator = db.Column(db.String(255), nullable=True, comment="Полное наименование оператора информационной системы - заявителя")
    short_name_operator = db.Column(db.String(255), nullable=True, comment="Сокращённое наименование оператора информационной системы - заявителя")

    full_names_users = db.Column(db.String(255), nullable=True, comment="Полные наименования пользователей 2 информационной системы")
    short_names_users = db.Column(db.String(255), nullable=True, comment="Сокращённые наименования пользователей информационной системы")

    commissioning_date = db.Column(db.Date, nullable=True, comment="Дата ввода в эксплуатацию")

    responsible_department = db.Column(db.String(255), nullable=True, comment="Наименование структурного подразделения, ответственного за работу с информационной системой")

    head_of_department_details = db.Column(db.String(512), nullable=True, comment="ФИО, телефоны и email руководителя структурного подразделения")
    responsible_person_details = db.Column(db.String(512), nullable=True, comment="ФИО, должность, телефоны и email ответственного лица за работу с информационной системой")

    purpose = db.Column(db.Text, nullable=True, comment="Цель")
    designation = db.Column(db.Text, nullable=True, comment="Назначение")
    area_of_application = db.Column(db.Text, nullable=True, comment="Область применения")
    functions = db.Column(db.Text, nullable=True, comment="Функции")

    author = db.relationship("User", backref="attribute1_records")


class Attribute2(db.Model):
    __tablename__ = 'attribute2'
    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    data1 = db.Column(db.String(255), nullable=True)
    data2 = db.Column(db.String(255), nullable=True)

    author = db.relationship("User", backref="attribute2_records")

class Request(db.Model):
    """
    request_status:
      - 'редактирование'
      - 'направлен на экспертизу'
      - 'принят к учёту'
      - 'не принят к учёту'
      - 'архив'
    """
    __tablename__ = 'requests'
    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    object_id = db.Column(db.Integer, db.ForeignKey('objects.id'), nullable=False)
    request_status = db.Column(db.String(255), default='редактирование')

    attribute1_id = db.Column(db.Integer, db.ForeignKey('attribute1.id'), nullable=True)
    attribute2_id = db.Column(db.Integer, db.ForeignKey('attribute2.id'), nullable=True)
    status_1_enabled = db.Column(db.Boolean, default=False)
    reject_comment = db.Column(db.String(1024), nullable=True)

    author = db.relationship("User", backref="requests")
    object = db.relationship("Object", backref="requests")
    attr1 = db.relationship("Attribute1", backref="requests", uselist=False)
    attr2 = db.relationship("Attribute2", backref="requests", uselist=False)

##############################################################################
# ВСПОМОГАТЕЛЬНОЕ И ДЕКОРАТОРЫ
##############################################################################

def get_current_user():
    if 'user_id' in session:
        return User.query.get(session['user_id'])
    return None

from flask import render_template, request, redirect, url_for, session

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not get_current_user():
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def moderator_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = get_current_user()
        if not user or not user.is_moderator:
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def organization_active_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = get_current_user()
        if not user:
            flash('Вы не авторизованы.', 'error')
            return redirect(url_for('login'))

        if not user.organization:
            flash('Ваша учетная запись не привязана к организации.', 'error')
            return redirect(url_for('index'))

        if not user.organization.is_active:
            flash('Ваша организация заблокирована. Доступ запрещен.', 'error')
            return redirect(url_for('index'))

        return f(*args, **kwargs)

    return decorated_function

@app.context_processor
def inject_datetime():
    return {'datetime': datetime}

@app.before_request
def initialize_settings():
    if not SystemSetting.query.filter_by(name='is_registration_enabled').first():
        db.session.add(SystemSetting(name='is_registration_enabled', value=True))
        db.session.commit()

def create_new_request_with_copy(old_req, new_author_id):
    """
    Создаёт новую заявку (request_status='редактирование'), копируя
    все атрибуты из old_req. При этом old_req переводится в архив.
    Возвращает new_req (уже сохранённую в БД).
    """
    print("DEBUG: Entering create_new_request_with_copy")
    print("DEBUG: old_req.id =", old_req.id, " old_req.status =", old_req.request_status)
    print("DEBUG: old_req.attr1 =", old_req.attr1, " old_req.attr2 =", old_req.attr2)

    # 1. Переводим старую заявку в «архив»
    old_req.request_status = 'архив'
    db.session.commit()
    print("DEBUG: old_req.id =", old_req.id, " now status=архив")

    # 2. Создаём новую заявку
    new_req = Request(
        author_id=new_author_id,
        object_id=old_req.object_id,
        request_status='редактирование',
        status_1_enabled=old_req.status_1_enabled
    )
    db.session.add(new_req)
    db.session.commit()
    print("DEBUG: Created new_req.id =", new_req.id, " with status=редактирование")

    # 3. Копируем Attribute1
    if old_req.attr1:
        print("DEBUG: old_req.attr1 found => id=", old_req.attr1.id)
        old_a1 = old_req.attr1
        attr1_copy = Attribute1(
            author_id=new_author_id,
            full_name_information_system=old_a1.full_name_information_system,
            short_name_information_system=old_a1.short_name_information_system,
            full_name_operator=old_a1.full_name_operator,
            short_name_operator=old_a1.short_name_operator,
            full_names_users=old_a1.full_names_users,
            short_names_users=old_a1.short_names_users,
            commissioning_date=old_a1.commissioning_date,
            responsible_department=old_a1.responsible_department,
            head_of_department_details=old_a1.head_of_department_details,
            responsible_person_details=old_a1.responsible_person_details,
            purpose=old_a1.purpose,
            designation=old_a1.designation,
            area_of_application=old_a1.area_of_application,
            functions=old_a1.functions
        )
        db.session.add(attr1_copy)
        db.session.commit()
        new_req.attribute1_id = attr1_copy.id
        db.session.commit()
        print(f"DEBUG: Copied attr1 => new_req.attribute1_id = {new_req.attribute1_id}")
    else:
        print("DEBUG: old_req.attr1 not found => no copy")

    # 4. Копируем Attribute2 (если необходимо)
    if old_req.attr2:
        print("DEBUG: old_req.attr2 found => id=", old_req.attr2.id)
        old_a2 = old_req.attr2
        attr2_copy = Attribute2(
            author_id=new_author_id,
            data1=old_a2.data1,
            data2=old_a2.data2
        )
        db.session.add(attr2_copy)
        db.session.commit()
        new_req.attribute2_id = attr2_copy.id
        db.session.commit()
        print(f"DEBUG: Copied attr2 => new_req.attribute2_id = {new_req.attribute2_id}")
    else:
        print("DEBUG: old_req.attr2 not found => no copy")

    print("DEBUG: Exiting create_new_request_with_copy => new_req.id =", new_req.id)
    return new_req


##############################################################################
# МАРШРУТЫ АУТЕНТИФИКАЦИИ (login/logout/register)
##############################################################################

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session['user_id'] = user.id
            return redirect(url_for('index'))
        else:
            return render_template('login.html', error="Неверное имя пользователя или пароль")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    registration_setting = SystemSetting.query.filter_by(name='is_registration_enabled').first()
    if not registration_setting or not registration_setting.value:
        flash('Регистрация временно отключена.', 'error')
        return redirect(url_for('login'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        org_name = request.form.get('organization_name', '')

        # Проверка уникальности пользователя
        if User.query.filter_by(username=username).first():
            flash('Имя пользователя занято.', 'error')
            return render_template('register.html')

        # Поиск/создание организации
        organization = None
        if org_name:
            org = Organization.query.filter_by(name=org_name).first()
            if not org:
                org = Organization(name=org_name)
                db.session.add(org)
                db.session.commit()
            organization = org

        new_user = User(username=username, organization=organization)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        session['user_id'] = new_user.id
        flash('Регистрация успешна.', 'success')

##############################################################################
# ГЛАВНАЯ + СОЗДАНИЕ ОБЪЕКТА
##############################################################################

@app.route('/')
@login_required
def index():
    user = get_current_user()
    if user.is_moderator:
        objects = Object.query.order_by(Object.id.desc()).all()
    else:
        org_id = user.organization_id
        objects = (Object.query
                   .join(User, Object.author_id == User.id)
                   .filter(User.organization_id == org_id)
                   .order_by(Object.id.desc())
                   .all())

    object_status_map = {}
    for obj in objects:
        last_req = (Request.query
                    .filter_by(object_id=obj.id)
                    .order_by(Request.id.desc())
                    .first())
        if last_req:
            object_status_map[obj.id] = last_req.request_status
        else:
            object_status_map[obj.id] = 'нет заявки'

    return render_template('index.html', user=user, objects=objects,
                           object_status_map=object_status_map)

@app.route('/create_object', methods=['POST'])
@login_required
@organization_active_required
def create_object():
    user = get_current_user()

    # Создаём новый объект
    new_obj = Object(author_id=user.id)
    db.session.add(new_obj)
    db.session.commit()

    # Создаём черновик заявки
    new_req = Request(
        author_id=user.id,
        object_id=new_obj.id,
        request_status='редактирование'
    )
    db.session.add(new_req)
    db.session.commit()

    # Перенаправление к редактированию
    return redirect(url_for('object_edit', object_id=new_obj.id))


##############################################################################
# РЕДАКТИРОВАНИЕ (GET + POST)
##############################################################################

##############################################################################
# РЕДАКТИРОВАНИЕ (GET + POST)
##############################################################################

@app.route('/object/<int:object_id>/edit', methods=['GET'])
@login_required
@organization_active_required
def object_edit(object_id):
    """
    Страница просмотра/редактирования заявки:
      - Если статус «направлен на экспертизу» => read-only
      - Если статус «принят к учёту» или «не принят к учёту» => read-only,
        НО предлагаем кнопку «Создать новую версию».
      - Если статус «редактирование» => обычная форма
    """
    user = get_current_user()
    obj = Object.query.get_or_404(object_id)

    if not user.is_moderator:
        if user.organization_id != obj.author.organization_id:
            return "Нет прав"

    req = (Request.query
           .filter_by(object_id=obj.id)
           .order_by(Request.id.desc())
           .first())
    if not req:
        return "Не найдена заявка"

    # Если «направлен на экспертизу», «принят к учёту», «не принят к учёту» => показываем read-only,
    # но если «принят»/«не принят», показываем кнопку "Создать новую заявку"
    if req.request_status in ['направлен на экспертизу', 'принят к учёту', 'не принят к учёту']:
        # Вместо автокопирования, рендерим read-only.
        # В этом шаблоне может быть кнопка (POST) "create_new_version", которая вручную вызывает copy.
        return render_template('object_edit_readonly.html',
                               user=user, obj=obj, req=req)

    # Иначе «редактирование» => показываем форму (object_edit.html)
    return render_template('object_edit.html',
                           user=user, obj=obj, req=req,
                           attr1=req.attr1, attr2=req.attr2)

@app.route('/object/<int:object_id>/create_new_version', methods=['POST'])
@login_required
@organization_active_required
def create_new_version(object_id):
    """
    Явный маршрут, который пользователь вызывает при нажатии «Создать новую версию»
    (если заявка принята или отклонена).
    """
    user = get_current_user()
    obj = Object.query.get_or_404(object_id)
    if not user.is_moderator:
        if user.organization_id != obj.author.organization_id:
            return "Нет прав"

    current_req = (Request.query
                   .filter_by(object_id=obj.id)
                   .order_by(Request.id.desc())
                   .first())
    if not current_req:
        return "Заявка не найдена"

    # Копируем только если статус «принят к учёту» или «не принят к учёту»
    if current_req.request_status not in ['принят к учёту','не принят к учёту']:
        return "Нельзя создать новую версию, заявка не 'принята' и не 'не принята'."

    new_req = create_new_request_with_copy(current_req, user.id)
    print(f"DEBUG: Создана новая версия id={new_req.id}")
    return redirect(url_for('object_edit', object_id=obj.id))


@app.route('/object/<int:object_id>/update', methods=['POST'])
@login_required
@organization_active_required
def object_update(object_id):
    """
    POST: «Сохранить» (action=save) или «Отправить» (action=submit).
    Если заявка «на экспертизе» — нельзя редактировать. Если «принята»/«не принята» — нужно
    сначала нажать «Создать новую версию» (create_new_version).
    """
    print("DEBUG: Entering object_update")
    user = get_current_user()
    obj = Object.query.get_or_404(object_id)
    if not user.is_moderator:
        if user.organization_id != obj.author.organization_id:
            return "Нет прав"

    current_req = (Request.query
                   .filter_by(object_id=obj.id)
                   .order_by(Request.id.desc())
                   .first())
    if not current_req:
        print("DEBUG: current_req not found!")
        return "Не найдена заявка"
    print("DEBUG: current_req.id=", current_req.id, " status=", current_req.request_status)

    # Если заявка 'принят к учёту' / 'не принят к учёту' / 'направлен на экспертизу',
    # значит надо было сначала создать новую заявку
    if current_req.request_status in ['принят к учёту', 'не принят к учёту', 'направлен на экспертизу']:
        return "Нельзя редактировать эту заявку. Создайте новую версию."

    # Получаем действие пользователя: 'save' или 'submit'
    action = request.form.get('action')  # 'save' или 'submit'
    print("DEBUG: user clicked action=", action)

    # Сохраняем поля Attribute1
    if not current_req.attribute1_id:
        attr1 = Attribute1(author_id=user.id)
        db.session.add(attr1)
        db.session.commit()
        current_req.attribute1_id = attr1.id
        print("DEBUG: Created new attr1 => id =", attr1.id)
    else:
        attr1 = Attribute1.query.get(current_req.attribute1_id)

    # Обновляем поля Attribute1 из request.form
    attr1.full_name_information_system = request.form.get('full_name_information_system', '')
    attr1.short_name_information_system = request.form.get('short_name_information_system', '')
    attr1.full_name_operator = request.form.get('full_name_operator', '')
    attr1.short_name_operator = request.form.get('short_name_operator', '')
    attr1.full_names_users = request.form.get('full_names_users', '')
    attr1.short_names_users = request.form.get('short_names_users', '')

    # Обработка даты ввода в эксплуатацию
    commissioning_date_str = request.form.get('commissioning_date', '')
    if commissioning_date_str:
        try:
            attr1.commissioning_date = datetime.strptime(commissioning_date_str, '%Y-%m-%d').date()
        except ValueError:
            print("DEBUG: Неверный формат даты ввода в эксплуатацию")
            attr1.commissioning_date = None
    else:
        attr1.commissioning_date = None

    attr1.responsible_department = request.form.get('responsible_department', '')
    attr1.head_of_department_details = request.form.get('head_of_department_details', '')
    attr1.responsible_person_details = request.form.get('responsible_person_details', '')
    attr1.purpose = request.form.get('purpose', '')
    attr1.designation = request.form.get('designation', '')
    attr1.area_of_application = request.form.get('area_of_application', '')
    attr1.functions = request.form.get('functions', '')

    print(f"DEBUG: Updated Attribute1 fields: {attr1}")

    # Обработка status_1_enabled и Attribute2, если необходимо
    checkbox_status = request.form.get('attr2_enabled')  # 'on' или None
    if checkbox_status == 'on':
        current_req.status_1_enabled = True
        # Обработка Attribute2
        data1_a2 = request.form.get('a2_data1', '')
        data2_a2 = request.form.get('a2_data2', '')
        print(f"DEBUG: a2_data1='{data1_a2}', a2_data2='{data2_a2}' => enabling attr2")
        if not current_req.attribute2_id:
            attr2 = Attribute2(author_id=user.id, data1=data1_a2, data2=data2_a2)
            db.session.add(attr2)
            db.session.commit()
            current_req.attribute2_id = attr2.id
            print("DEBUG: Created new attr2 => id =", attr2.id)
        else:
            attr2 = Attribute2.query.get(current_req.attribute2_id)
            attr2.data1 = data1_a2
            attr2.data2 = data2_a2
            db.session.add(attr2)
            print("DEBUG: Updated existing attr2 => id =", attr2.id,
                  " data1=", attr2.data1, " data2=", attr2.data2)
    else:
        current_req.status_1_enabled = False
        current_req.attribute2_id = None
        print("DEBUG: checkbox off => attr2 disabled/cleared")

    db.session.commit()

    if action == 'submit':
        print("DEBUG: user wants to SUBMIT => setting status='направлен на экспертизу'")
        current_req.request_status = 'направлен на экспертизу'
        db.session.commit()
        print("DEBUG: current_req.id=", current_req.id, " status=", current_req.request_status)
        return redirect(url_for('index'))
    else:
        # Сохранить
        print("DEBUG: user wants to SAVE => status=редактирование remains")
        return redirect(url_for('object_edit', object_id=obj.id))


##############################################################################
# ИСТОРИЯ + ПРОСМОТР
##############################################################################

@app.route('/object/<int:object_id>/requests_history')
@login_required
def requests_history(object_id):
    obj = Object.query.get_or_404(object_id)
    user = get_current_user()
    if not user.is_moderator:
        if user.organization_id != obj.author.organization_id:
            return "Нет прав."

    all_requests = (Request.query
                    .filter_by(object_id=obj.id)
                    .order_by(Request.id.desc())
                    .all())
    return render_template('requests_history.html',
                           obj=obj,
                           all_requests=all_requests,
                           user=user)

@app.route('/object/request/<int:request_id>/view', methods=['GET'])
@login_required
def object_edit_readonly_version(request_id):
    req = Request.query.get_or_404(request_id)
    user = get_current_user()
    if not user.is_moderator:
        if user.organization_id != req.object.author.organization_id:
            return "Нет прав"

    return render_template('object_edit_readonly.html',
                           user=user,
                           obj=req.object,
                           req=req)

##############################################################################
# МАРШРУТЫ МОДЕРАТОРА
##############################################################################

@app.route('/moderator')
@login_required
@moderator_required
@organization_active_required
def moderator_panel():
    requests_for_review = Request.query.filter_by(request_status='направлен на экспертизу').all()
    return render_template('moderator.html', user=get_current_user(), requests_for_review=requests_for_review)

@app.route('/moderator/history')
@login_required
@moderator_required
@organization_active_required
def moderator_all_requests():
    all_requests = Request.query.order_by(Request.id.desc()).all()
    return render_template('moderator_all_requests.html', user=get_current_user(), all_requests=all_requests)


@app.route('/moderator/request_view/<int:request_id>', methods=['GET', 'POST'])
@login_required
@moderator_required
@organization_active_required
def moderator_request_view(request_id):
    req = Request.query.get_or_404(request_id)

    # Извлекаем связанный объект. Предполагается, что есть отношение 'object' в модели Request
    obj = req.object

    # Получаем все предыдущие заявки для этого объекта, исключая текущую, сортируем по дате создания
    previous_requests = Request.query.filter(
        Request.object_id == req.object_id,
        Request.id != req.id
    ).order_by(Request.created_at.desc()).all()

    # Извлекаем последнюю предыдущую заявку, если она существует
    prev_req = previous_requests[0] if previous_requests else None

    # Передаём prev_req в шаблон
    return render_template(
        'moderator_request_view.html',
        req=req,
        previous_requests=previous_requests,
        obj=obj,  # Передаём obj в шаблон
        prev_req=prev_req,  # Передаём prev_req в шаблон
        user=get_current_user()  # Предполагается, что есть функция get_current_user()
    )

@app.route('/moderator/approve/<int:request_id>', methods=['POST'])
@login_required
@moderator_required
@organization_active_required
def moderator_approve(request_id):
    req = Request.query.get_or_404(request_id)
    if req.request_status != 'направлен на экспертизу':
        return "Заявка не в статусе 'направлен на экспертизу'."
    req.request_status = 'принят к учёту'
    db.session.commit()
    return redirect(url_for('moderator_panel'))

@app.route('/moderator/reject/<int:request_id>', methods=['POST'])
@login_required
@moderator_required
@organization_active_required
def moderator_reject(request_id):
    req = Request.query.get_or_404(request_id)
    if req.request_status != 'направлен на экспертизу':
        return "Заявка не в статусе 'направлен на экспертизу' для отклонения."
    reject_comment = request.form.get('reject_comment','')
    req.request_status = 'не принят к учёту'
    req.reject_comment = reject_comment
    db.session.commit()
    return redirect(url_for('moderator_panel'))

##############################################################################
# АДМИНКА
##############################################################################

@app.route('/admin', methods=['GET', 'POST'])
@login_required
@moderator_required
@organization_active_required
def admin_panel():
    # Получение всех пользователей и организаций
    users = User.query.order_by(User.username).all()
    organizations = Organization.query.order_by(Organization.name).all()

    # Обработка формы создания пользователя
    if request.method == 'POST':
        if 'create_user' in request.form:
            return redirect(url_for('create_user'))
        elif 'create_organization' in request.form:
            return redirect(url_for('create_organization'))

    return render_template('admin_panel.html', users=users, user=get_current_user(), organizations=organizations)

@app.route('/admin/users/create', methods=['GET', 'POST'])
@login_required
@moderator_required
@organization_active_required
def create_user():
    organizations = Organization.query.filter_by(is_active=True).all()
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        is_moderator = True if request.form.get('is_moderator') == 'on' else False
        organization_id = request.form.get('organization_id') or None

        if User.query.filter_by(username=username).first():
            flash('Имя пользователя уже занято.', 'error')
            return redirect(url_for('create_user'))

        new_user = User(username=username, is_moderator=is_moderator, user=get_current_user(), organization_id=organization_id)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        flash('Пользователь успешно создан.', 'success')
        return redirect(url_for('admin_panel'))

    return render_template('create_user.html', organizations=organizations)

@app.route('/admin/users/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required
@moderator_required
@organization_active_required
def edit_user(user_id):
    user_to_edit = User.query.get_or_404(user_id)  # Изменяем имя переменной
    organizations = Organization.query.filter_by(is_active=True).all()

    if request.method == 'POST':
        user_to_edit.username = request.form.get('username')
        password = request.form.get('password')
        if password:
            user_to_edit.set_password(password)
        user_to_edit.is_moderator = True if request.form.get('is_moderator') == 'on' else False
        user_to_edit.organization_id = request.form.get('organization_id') or None
        user_to_edit.is_active = True if request.form.get('is_active') == 'on' else False

        db.session.commit()
        flash('Пользователь успешно обновлён.', 'success')
        return redirect(url_for('admin_panel'))

    return render_template(
        'edit_user.html',
        user_to_edit=user_to_edit,  # Переименовали для передачи в шаблон
        user=get_current_user(),
        organizations=organizations
    )


@app.route('/admin/organizations/create', methods=['GET', 'POST'])
@login_required
@moderator_required
@organization_active_required
def create_organization():
    if request.method == 'POST':
        name = request.form.get('name')

        if Organization.query.filter_by(name=name).first():
            flash('Организация с таким именем уже существует.', 'error')
            return redirect(url_for('create_organization'))

        new_org = Organization(name=name)
        db.session.add(new_org)
        db.session.commit()
        flash('Организация успешно создана.', 'success')
        return redirect(url_for('admin_panel'))

    return render_template('create_organization.html', user=get_current_user())

@app.route('/admin/organizations/edit/<int:org_id>', methods=['GET', 'POST'])
@login_required
@moderator_required
@organization_active_required
def edit_organization(org_id):
    org = Organization.query.get_or_404(org_id)

    if request.method == 'POST':
        org.name = request.form.get('name')
        org.is_active = True if request.form.get('is_active') == 'on' else False

        db.session.commit()
        flash('Организация успешно обновлена.', 'success')
        return redirect(url_for('admin_panel'))

    return render_template('edit_organization.html', organization=org, user=get_current_user(),)

@app.route('/admin/settings', methods=['GET', 'POST'])
@login_required
@moderator_required
@organization_active_required
def admin_settings():
    registration_setting = SystemSetting.query.filter_by(name='is_registration_enabled').first()
    if not registration_setting:
        registration_setting = SystemSetting(name='is_registration_enabled', value=True)
        db.session.add(registration_setting)
        db.session.commit()

    if request.method == 'POST':
        is_registration_enabled = True if request.form.get('is_registration_enabled') == 'on' else False
        registration_setting.value = is_registration_enabled
        db.session.commit()
        flash('Настройки обновлены.', 'success')
        return redirect(url_for('admin_settings'))

    return render_template('admin_settings.html', registration_enabled=registration_setting.value, user=get_current_user())


##############################################################################
# ЗАПУСК
##############################################################################

if __name__ == '__main__':
    # flask db init
    # flask db migrate -m "Add debug prints"
    # flask db upgrade
    with app.app_context():
        if not SystemSetting.query.filter_by(name='is_registration_enabled').first():
            db.session.add(SystemSetting(name='is_registration_enabled', value=True))
            db.session.commit()
    app.run(debug=True)
