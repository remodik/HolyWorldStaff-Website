import threading
import requests
from datetime import datetime
from sqlalchemy import select
from flask import Flask, render_template, redirect, url_for, request, flash, abort, jsonify, make_response
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from config import Config
from models import db, User, Guide, ResponseTemplate, StaffRole
from discord_bot import get_user_access_level, run_bot
from functools import wraps
from flask_jwt_extended import JWTManager, create_access_token, jwt_required

app = Flask(__name__)
app.config.from_object(Config)
app.config['SQLALCHEMY_FUTURE'] = True
app.config['JWT_SECRET_KEY'] = 'your-secret-key'
jwt = JWTManager(app)
db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

threading.Thread(target=run_bot, daemon=True).start()
API_KEYS = {
    "DISCORD_BOT": "123",
}


def api_key_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-KEY') or request.args.get('api_key')
        if not api_key or api_key not in API_KEYS.values():
            return jsonify({"error": "Хули надо?"}), 403
        return f(*args, **kwargs)
    return decorated_function


def staff_required(access_level=1):
    def decorator(f):
        @wraps(f)
        @login_required
        def decorated_function(*args, **kwargs):
            if current_user.access_level < access_level:
                flash('Недостаточно прав для доступа!', 'danger')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator


@login_manager.user_loader
def load_user(user_id):
    user = db.session.get(User, int(user_id))
    if not user:
        return None

    current_access_level = get_user_access_level(int(user_id))
    if current_access_level != user.access_level:
        user.access_level = current_access_level
        db.session.commit()

    return user


@app.before_request
def create_tables():
    db.create_all()


DISCORD_API_URL = 'https://discord.com/api/v10'


def get_oauth_url():
    return (f"{DISCORD_API_URL}/oauth2/authorize?"
            f"client_id={app.config['DISCORD_CLIENT_ID']}&"
            f"redirect_uri={app.config['DISCORD_REDIRECT_URI']}&"
            f"response_type=code&"
            f"scope=identify%20guilds.members.read")


def exchange_code(code: str):
    data = {
        'client_id': app.config['DISCORD_CLIENT_ID'],
        'client_secret': app.config['DISCORD_CLIENT_SECRET'],
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': app.config['DISCORD_REDIRECT_URI']
    }
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    response = requests.post(f"{DISCORD_API_URL}/oauth2/token", data=data, headers=headers)
    return response.json()


@app.context_processor
def inject_now():
    return {'now': datetime.now()}


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login')
def login():
    return redirect(get_oauth_url())


@app.route('/logout')
@staff_required(access_level=0)
def logout():
    logout_user()
    flash('Вы успешно вышли из системы!', 'info')
    return redirect(url_for('index'))


@app.route('/auth/callback')
def auth_callback():
    code = request.args.get('code')
    if not code:
        return redirect(url_for('index'))

    token_data = exchange_code(code)
    if 'access_token' not in token_data:
        flash('Ошибка авторизации. Попробуйте снова.', 'danger')
        return redirect(url_for('index'))

    access_token = token_data['access_token']
    headers = {"Authorization": f"Bearer {access_token}"}

    user_response = requests.get(f"{DISCORD_API_URL}/users/@me", headers=headers)
    user_data = user_response.json()
    discord_user_id = user_data['id']

    access_level = get_user_access_level(int(discord_user_id))
    if access_level == 0:
        flash('У вас нет доступа к системе! Обратитесь к администратору.', 'danger')
        return redirect(url_for('index'))

    user = User.query.get(discord_user_id)
    avatar_url = f"https://cdn.discordapp.com/avatars/{discord_user_id}/{user_data['avatar']}.png" if user_data[
        'avatar'] else None

    if not user:
        user = User(
            id=discord_user_id,
            username=f"{user_data['username']}",
            avatar=avatar_url,
            access_level=access_level
        )
        db.session.add(user)
    else:
        user.username = f"{user_data['username']}"
        user.avatar = avatar_url
        user.access_level = access_level

    db.session.commit()
    login_user(user)
    return redirect(url_for('dashboard'))


@app.route('/staff-list')
@staff_required()
def staff_list():
    staff_members = User.query.order_by(User.access_level.desc()).all()
    staff_roles = StaffRole.query.order_by(StaffRole.access_level.desc()).all()
    return render_template('staff-list.html',
                         staff_members=staff_members,
                         staff_roles=staff_roles,
                         current_access=current_user.access_level)


@app.route('/dashboard')
@staff_required(access_level=4)
def dashboard():
    categories = db.session.query(Guide.category).distinct().all()

    guides_by_category = {}
    for category in categories:
        guides = db.session.execute(
            select(Guide)
            .filter_by(category=category[0])
            .order_by(Guide.title)
        ).scalars().all()
        guides_by_category[category[0]] = guides

    return render_template(
        'dashboard.html',
        guides_by_category=guides_by_category,
        current_user=current_user
    )


@app.route('/update-staff-roles', methods=['POST'])
@staff_required(access_level=6)
def update_staff_roles():
    if current_user.access_level < 6:
        abort(403)

    role_level = int(request.form.get('role_level'))
    permissions = request.form.get('permissions', '').strip()
    responsibilities = request.form.get('responsibilities', '').strip()

    role = StaffRole.query.filter_by(access_level=role_level).first()

    if role:
        role.permissions = permissions
        role.responsibilities = responsibilities
    else:
        role_name = {
            6: "Куратор дискорда",
            5: "Зам.Куратора дискорда",
            4: "Гл.Модератор дискорда",
            3: "Ст.Модератор дискорда",
            2: "Модератор дискорда",
            1: "Мл.Модератор дискорда"
        }.get(role_level, f"Уровень {role_level}")

        role = StaffRole(
            role_name=role_name,
            permissions=permissions,
            responsibilities=responsibilities,
            access_level=role_level
        )
        db.session.add(role)

    db.session.commit()
    flash('Права и обязанности успешно обновлены!', 'success')
    return redirect(url_for('staff_list'))


@app.route('/guide/<int:guide_id>')
@staff_required()
def view_guide(guide_id):
    guide = db.session.get(Guide, guide_id)
    if not guide:
        abort(404)

    related_guides = Guide.query.filter(
        Guide.category == guide.category,
        Guide.id != guide.id
    ).order_by(Guide.title).all()

    return render_template(
        'guide.html',
        guide=guide,
        related_guides=related_guides
    )


@app.route('/edit/<int:guide_id>', methods=['GET', 'POST'])
@staff_required(access_level=4)
def edit_guide(guide_id):
    if current_user.access_level < 4:
        flash('Недостаточно прав для редактирования!', 'danger')
        return redirect(url_for('dashboard'))

    guide = Guide.query.get_or_404(guide_id)

    if request.method == 'POST':
        guide.title = request.form['title']
        guide.content = request.form['content']
        guide.category = request.form['category']
        db.session.commit()
        flash('Руководство успешно обновлено!', 'success')
        return redirect(url_for('view_guide', guide_id=guide.id))

    return render_template('edit.html', guide=guide)


@app.route('/staff-rules')
@staff_required()
def staff_rules():
    staff_roles = StaffRole.query.order_by(StaffRole.access_level.desc()).all()
    return render_template('staff_rules.html',
                         staff_roles=staff_roles,
                         current_access=current_user.access_level)


@app.route('/get-staff-member')
@staff_required(access_level=4)
def get_staff_member():
    if current_user.access_level < 4:
        return jsonify({'error': 'Недостаточно прав'}), 403

    member_id = request.args.get('id')
    if not member_id:
        return jsonify({'error': 'ID сотрудника не указан'}), 400

    try:
        member_id_int = int(member_id)
    except ValueError:
        return jsonify({'error': 'Неверный формат ID'}), 400

    member = User.query.get(member_id_int)
    if not member:
        return jsonify({'error': 'Сотрудник не найден'}), 404

    return jsonify({
        'id': str(member.id),
        'full_name': member.full_name or '',
        'nickname': member.nickname or '',
        'salary': member.salary or '',
        'warnings': member.warnings or '0/0',
        'vacation_date': member.vacation_date.strftime('%d.%m.%Y') if member.vacation_date else '',
        'join_date': member.join_date.strftime('%d.%m.%Y') if member.join_date else '',
        'vk_link': member.vk_link or ''
    })


@app.route('/update-staff-member', methods=['POST'])
@staff_required(access_level=4)
def update_staff_member():
    try:
        if current_user.access_level < 4:
            return jsonify({'error': 'Недостаточно прав'}), 403

        member_id = request.form.get('member_id')
        if not member_id:
            return jsonify({'error': 'ID сотрудника не указан'}), 400

        member = User.query.get(member_id)
        if not member:
            return jsonify({'error': 'Сотрудник не найден'}), 404

        member.full_name = request.form.get('full_name', '')
        member.nickname = request.form.get('nickname', '')
        member.salary = request.form.get('salary', '')
        member.warnings = request.form.get('warnings', '0/0')
        member.vk_link = request.form.get('vk_link', '')

        vacation_date = request.form.get('vacation_date')
        join_date = request.form.get('join_date')

        member.vacation_date = datetime.strptime(vacation_date, '%d.%m.%Y').date() if vacation_date else None
        member.join_date = datetime.strptime(join_date, '%d.%m.%Y').date() if join_date else None

        db.session.commit()

        flash('Данные обновлены', 'success')
        return redirect(url_for('staff_list'))

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/get-role-data')
@staff_required(access_level=6)
def get_role_data():
    if current_user.access_level < 6:
        abort(403)

    level = request.args.get('level', type=int)
    role = StaffRole.query.filter_by(access_level=level).first()

    if role:
        return jsonify({
            'permissions': role.permissions,
            'responsibilities': role.responsibilities
        })
    else:
        return jsonify({
            'permissions': '',
            'responsibilities': ''
        })


@app.route('/create', methods=['GET', 'POST'])
@staff_required(access_level=4)
def create_guide():
    if current_user.access_level < 4:
        flash('Недостаточно прав для создания!', 'danger')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        new_guide = Guide(
            title=request.form['title'],
            content=request.form['content'],
            category=request.form['category']
        )
        db.session.add(new_guide)
        db.session.commit()
        flash('Руководство успешно создано!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('edit.html', guide=None)


@app.route('/ticket-responses')
@staff_required()
def ticket_responses():
    templates = ResponseTemplate.query.order_by(ResponseTemplate.situation).all()
    return render_template('ticket_responses.html', response_templates=templates)


@app.route('/add-response-template', methods=['GET', 'POST'])
@staff_required(access_level=4)
def add_response_template():
    if current_user.access_level < 4:
        flash('Недостаточно прав для добавления шаблонов!', 'danger')
        return redirect(url_for('ticket_responses'))

    if request.method == 'POST':
        situation = request.form.get('situation')
        response = request.form.get('response')

        if not situation or not response:
            flash('Все поля обязательны для заполнения', 'danger')
            return redirect(url_for('add_response_template'))

        new_template = ResponseTemplate(
            situation=situation,
            response=response
        )
        db.session.add(new_template)
        db.session.commit()

        flash('Шаблон успешно добавлен', 'success')
        return redirect(url_for('ticket_responses'))

    return render_template('edit_response_template.html')


@app.route('/edit-response-template/<int:template_id>', methods=['GET', 'POST'])
@staff_required(access_level=4)
def edit_response_template(template_id):
    if current_user.access_level < 4:
        flash('Недостаточно прав для редактирования шаблонов!', 'danger')
        return redirect(url_for('ticket_responses'))

    template = ResponseTemplate.query.get_or_404(template_id)

    if request.method == 'POST':
        template.situation = request.form.get('situation')
        template.response = request.form.get('response')
        db.session.commit()

        flash('Шаблон успешно обновлен', 'success')
        return redirect(url_for('ticket_responses'))

    return render_template('edit_response_template.html', template=template)


@app.route('/delete-response-template/<int:template_id>', methods=['POST'])
@staff_required(access_level=4)
def delete_response_template(template_id):
    if current_user.access_level < 4:
        flash('Недостаточно прав для удаления шаблонов!', 'danger')
        return redirect(url_for('ticket_responses'))

    template = ResponseTemplate.query.get_or_404(template_id)
    db.session.delete(template)
    db.session.commit()

    flash('Шаблон успешно удален', 'success')
    return redirect(url_for('ticket_responses'))


@app.route('/delete/<int:guide_id>', methods=['POST'])
@staff_required(access_level=4)
def delete_guide(guide_id):
    if current_user.access_level < 4:
        flash('Недостаточно прав для удаления!', 'danger')
        return redirect(url_for('dashboard'))

    guide = Guide.query.get_or_404(guide_id)
    db.session.delete(guide)
    db.session.commit()
    flash('Руководство успешно удалено!', 'success')
    return redirect(url_for('dashboard'))


@app.route('/api/staff', methods=['GET'])
def get_all_staff():
    try:
        staff = User.query.order_by(User.access_level.desc()).all()
        staff_list = []

        for member in staff:
            staff_list.append({
                'id': str(member.id),
                'username': member.username,
                'avatar': member.avatar,
                'access_level': member.access_level,
                'full_name': member.full_name,
                'nickname': member.nickname,
                'salary': member.salary,
                'warnings': member.warnings,
                'vacation_date': member.vacation_date.strftime('%Y-%m-%d') if member.vacation_date else None,
                'join_date': member.join_date.strftime('%Y-%m-%d') if member.join_date else None
            })

        return jsonify({
            'success': True,
            'staff': staff_list,
            'count': len(staff_list)
        })

    except Exception as e:
        return make_response(jsonify({
            'success': False,
            'error': str(e)
        }), 500)


@app.route('/update-warnings', methods=['POST'])
@staff_required(access_level=4)
def update_warnings():
    try:
        data = request.get_json()
        member_id = data.get('id')
        warning_type = data.get('type')
        change = int(data.get('change'))

        if not member_id or warning_type not in ['warn', 'pred'] or change not in [1, -1]:
            return jsonify({'success': False, 'error': 'Неверные параметры запроса'}), 400

        member = User.query.get(member_id)
        if not member:
            return jsonify({'success': False, 'error': 'Сотрудник не найден'}), 404

        current_warnings = member.warnings.split('/') if member.warnings else ['0', '0']
        warn_count = int(current_warnings[0])
        pred_count = int(current_warnings[1])

        if warning_type == 'warn':
            warn_count = max(0, warn_count + change)
        else:
            pred_count = max(0, pred_count + change)

        member.warnings = f"{warn_count}/{pred_count}"
        db.session.commit()

        return jsonify({
            'success': True,
            'new_warnings': member.warnings,
            'warn_count': warn_count,
            'pred_count': pred_count
        })

    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/staff/<string:member_id>', methods=['GET'])
@api_key_required
def get_staff_member_api(member_id):
    try:
        member = User.query.get(int(member_id))
        if not member:
            return make_response(jsonify({
                'success': False,
                'error': 'Сотрудник не найден'
            }), 404)

        return jsonify({
            'success': True,
            'member': {
                'id': str(member.id),
                'username': member.username,
                'avatar': member.avatar,
                'access_level': member.access_level,
                'full_name': member.full_name,
                'nickname': member.nickname,
                'salary': member.salary,
                'warnings': member.warnings,
                'vacation_date': member.vacation_date.strftime('%d.%m.%Y') if member.vacation_date else None,
                'join_date': member.join_date.strftime('%d.%m.%Y') if member.join_date else None,
                'role_name': get_role_name(member.access_level),
                'vk_link': member.vk_link
            }
        })

    except ValueError:
        return make_response(jsonify({
            'success': False,
            'error': 'Неверный формат ID'
        }), 400)
    except Exception as e:
        return make_response(jsonify({
            'success': False,
            'error': str(e)
        }), 500)


def get_role_name(access_level):
    roles = {
        6: "Куратор дискорда",
        5: "Зам.Куратора дискорда",
        4: "Гл.Модератор дискорда",
        3: "Ст.Модератор дискорда",
        2: "Модератор дискорда",
        1: "Мл.Модератор дискорда"
    }
    return roles.get(access_level, "Неизвестная роль")


@app.route('/api/staff/role/<int:access_level>', methods=['GET'])
@api_key_required
def get_staff_by_role(access_level):
    try:
        staff = User.query.filter_by(access_level=access_level).all()
        staff_list = []

        for member in staff:
            staff_list.append({
                'id': str(member.id),
                'username': member.username,
                'avatar': member.avatar,
                'full_name': member.full_name,
                'nickname': member.nickname
            })

        return jsonify({
            'success': True,
            'staff': staff_list,
            'role': get_role_name(access_level),
            'count': len(staff_list)
        })

    except Exception as e:
        return make_response(jsonify({
            'success': False,
            'error': str(e)
        }), 500)


@app.route('/api/auth', methods=['POST'])
def auth_api():
    data = request.get_json()
    user = User.query.filter_by(username=data.get('username')).first()

    if user and user.access_level > 0:
        access_token = create_access_token(identity=user.id)
        return jsonify({
            'success': True,
            'token': access_token,
            'access_level': user.access_level
        })

    return make_response(jsonify({
        'success': False,
        'error': 'Неверные данные или нет доступа'
    }), 401)


if __name__ == '__main__':
    app.run(debug=True)