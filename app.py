import threading
import requests
from datetime import datetime
from sqlalchemy import select
from flask import Flask, render_template, redirect, url_for, request, flash, abort, jsonify, make_response
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from config import Config
from models import db, User, Guide, ResponseTemplate, StaffRole, SalaryHistory, ModeratorStats, PurchaseRequest, VacationRequest
from discord_bot import get_user_access_level, run_bot
from functools import wraps
from flask_jwt_extended import JWTManager, create_access_token
import json

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
                if request.headers.get("X-Requested-With") == "XMLHttpRequest" or request.is_json:
                    return jsonify({"success": False, "error": "Недостаточно прав"}), 403
                flash('Недостаточно прав для доступа!', 'danger')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def api_staff_required(access_level=1):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return jsonify({"success": False, "error": "Не авторизован"}), 401
            if current_user.access_level < access_level:
                return jsonify({"success": False, "error": "Недостаточно прав"}), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator


@login_manager.unauthorized_handler
def unauthorized_callback():
    if request.headers.get("X-Requested-With") == "XMLHttpRequest" or request.is_json:
        return jsonify({"success": False, "error": "Не авторизован"}), 401
    return redirect(url_for("login"))


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

    template = ResponseTemplate.query.get_or_404(template_id)
    db.session.delete(template)
    db.session.commit()

    flash('Шаблон успешно удален', 'success')
    return redirect(url_for('ticket_responses'))


@app.route('/delete/<int:guide_id>', methods=['POST'])
@staff_required(access_level=4)
def delete_guide(guide_id):

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
                'vacation_date': member.vacation_date.strftime('%d.%m.%Y') if member.vacation_date else None,
                'join_date': member.join_date.strftime('%d.%m.%Y') if member.join_date else None
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


@app.route('/salary')
@staff_required()
def salary_page():
    current_month = datetime.now().month
    current_year = datetime.now().year

    current_stats = ModeratorStats.query.filter_by(
        month=current_month,
        year=current_year
    ).all()

    moderators = User.query.filter(User.access_level.between(1, 4)).all()
    for moderator in moderators:
        if not any(stat.user_id == moderator.id for stat in current_stats):
            new_stat = ModeratorStats(
                user_id=moderator.id,
                month=current_month,
                year=current_year,
                punishments=0,
                tickets_closed=0,
                weeks_missed=0
            )
            db.session.add(new_stat)
            current_stats.append(new_stat)

    db.session.commit()

    current_stats = ModeratorStats.query.filter_by(
        month=current_month,
        year=current_year
    ).all()

    calculated_data = calculate_salaries(current_stats)

    available_years = db.session.query(SalaryHistory.year).distinct().all()
    available_years = [year[0] for year in available_years if year[0]]

    return render_template('salary.html',
                           current_stats=current_stats,
                           calculated_data=calculated_data,
                           available_years=available_years,
                           staff_members=moderators,
                           current_month=current_month,
                           current_year=current_year)


@app.route('/payout-salaries', methods=['POST'])
@api_staff_required(access_level=5)
def payout_salaries():
    try:
        current_month = datetime.now().month
        current_year = datetime.now().year

        salaries = SalaryHistory.query.filter_by(
            month=current_month,
            year=current_year
        ).all()

        updated = 0
        for salary in salaries:
            user = User.query.get(salary.user_id)
            if user:
                try:
                    current_val = int(user.salary or 0)
                except (ValueError, TypeError):
                    current_val = 0
                user.salary = str(current_val + int(salary.final_salary or 0))
                updated += 1

        db.session.commit()
        return jsonify({'success': True, 'updated': updated})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)})


def calculate_salaries(stats):
    results = {}

    if not stats:
        return results

    for stat in stats:
        punishments = stat.punishments
        if stat.weeks_missed == 1:
            punishments = max(0, punishments - 50)
        elif stat.weeks_missed == 2:
            punishments = max(0, punishments - 75)
        elif stat.weeks_missed >= 3:
            punishments = max(0, punishments - 90)
        stat.adjusted_punishments = punishments

    sorted_by_punishments = sorted(stats, key=lambda x: x.adjusted_punishments, reverse=True)
    sorted_by_tickets = sorted(stats, key=lambda x: x.tickets_closed, reverse=True)

    ranks = {stat.user_id: i + 1 for i, stat in enumerate(sorted_by_punishments)}

    for stat in stats:
        punishments = stat.adjusted_punishments

        if punishments <= 0:
            base_salary = 100
        elif punishments < 75:
            base_salary = 150
        elif punishments < 100:
            base_salary = 350
        elif punishments < 150:
            base_salary = 500
        elif punishments < 250:
            base_salary = 700
        else:
            base_salary = 1000

        bonus_sum = 0.0
        positive_details = []

        if stat.user.access_level == 4 or stat.user.access_level == 5:
            bonus_sum += 0.3
            positive_details.append("x1.3")
        elif stat.user.access_level == 3:
            bonus_sum += 0.2
            positive_details.append("x1.2")
        elif stat.user.access_level == 2:
            bonus_sum += 0.1
            positive_details.append("x1.1")

        tickets = stat.tickets_closed
        if tickets >= 45:
            bonus_sum += 0.25
            positive_details.append("x1.25")
        elif tickets >= 35:
            bonus_sum += 0.2
            positive_details.append("x1.2")
        elif tickets >= 20:
            bonus_sum += 0.15
            positive_details.append("x1.15")
        elif tickets >= 10:
            bonus_sum += 0.1
            positive_details.append("x1.1")

        rank = ranks.get(stat.user_id, 0)
        if rank == 1:
            bonus_sum += 0.2
            positive_details.append("x1.2")
        elif rank == 2:
            bonus_sum += 0.1
            positive_details.append("x1.1")
        elif rank == 3:
            bonus_sum += 0.05
            positive_details.append("x1.05")

        if sorted_by_tickets and stat == sorted_by_tickets[0]:
            bonus_sum += 0.1
            positive_details.append("x1.1")

        total_visible_multiplier = 1.0 + bonus_sum
        total_visible_multiplier = min(total_visible_multiplier, 1.75)

        final_salary = round(base_salary * total_visible_multiplier)

        results[stat.user_id] = {
            'base_salary': base_salary,
            'final_salary': final_salary,
            'total_multiplier': total_visible_multiplier,
            'total_display': f"x{total_visible_multiplier:.2f}".replace('.', ','),
            'rank': rank,
            'rank_display': "x1.2" if rank == 1 else
                            "x1.1" if rank == 2 else
                            "x1.05" if rank == 3 else "-",
            'position_display': "x1.3" if stat.user.access_level == 4 else
                                "x1.2" if stat.user.access_level == 3 else
                                "x1.1" if stat.user.access_level == 2 else "-",
            'ticket_display': "x1.1" if 10 <= tickets < 20 else
                              "x1.15" if 20 <= tickets < 30 else
                              "x1.2" if 30 <= tickets < 40 else
                              "x1.25" if tickets >= 40 else "-",
            'top_mod_display': "x1.1" if (sorted_by_tickets and stat == sorted_by_tickets[0]) else "-",
            'weeks_missed': stat.weeks_missed,
            'weeks_display': f"-{stat.weeks_missed * 5}%" if stat.weeks_missed > 0 else "-",
            'positive_details': positive_details,
            'negative_details': []
        }

    return results


@app.route('/update-mod-stats', methods=['POST'])
@staff_required(access_level=5)
def update_moderator_stats():
    try:
        user_id = request.form.get('user_id')
        punishments = int(request.form.get('punishments', 0))
        tickets_closed = int(request.form.get('tickets_closed', 0))
        weeks_missed = int(request.form.get('weeks_missed', 0))

        current_month = datetime.now().month
        current_year = datetime.now().year

        stat = ModeratorStats.query.filter_by(
            user_id=user_id,
            month=current_month,
            year=current_year
        ).first()

        if not stat:
            stat = ModeratorStats(
                user_id=user_id,
                month=current_month,
                year=current_year
            )
            db.session.add(stat)

        stat.punishments = punishments
        stat.tickets_closed = tickets_closed
        stat.weeks_missed = weeks_missed

        db.session.commit()

        flash('Статистика обновлена!', 'success')
        return redirect(url_for('salary_page'))

    except Exception as e:
        db.session.rollback()
        flash(f'Ошибка: {str(e)}', 'danger')
        return redirect(url_for('salary_page'))


@app.route('/get-mod-stats')
@staff_required(access_level=5)
def get_mod_stats():
    user_id = request.args.get('user_id')
    current_month = datetime.now().month
    current_year = datetime.now().year

    stat = ModeratorStats.query.filter_by(
        user_id=user_id,
        month=current_month,
        year=current_year
    ).first()

    if stat:
        return jsonify({
            'user_id': stat.user_id,
            'punishments': stat.punishments,
            'tickets_closed': stat.tickets_closed,
            'weeks_missed': stat.weeks_missed
        })
    else:
        return jsonify({
            'user_id': user_id,
            'punishments': 0,
            'tickets_closed': 0,
            'weeks_missed': 0
        })


@app.route('/calculate-salaries', methods=['POST'])
@api_staff_required(access_level=5)
def calculate_salaries_route():
    try:
        current_month = datetime.now().month
        current_year = datetime.now().year

        stats = ModeratorStats.query.filter_by(
            month=current_month,
            year=current_year
        ).all()

        calculated_data = calculate_salaries(stats)

        for user_id, data in calculated_data.items():
            SalaryHistory.query.filter_by(
                user_id=user_id,
                month=current_month,
                year=current_year
            ).delete()

            salary = SalaryHistory(
                user_id=user_id,
                day=datetime.now().day,
                month=current_month,
                year=current_year,
                base_salary=data['base_salary'],
                final_salary=data['final_salary'],
                multiplier=data['total_multiplier'],
                details=json.dumps({
                    'rank': data['rank'],
                    'positive_details': data['positive_details'],
                    'negative_details': data['negative_details'],
                    'weeks_missed': data['weeks_missed']
                })
            )
            db.session.add(salary)

        db.session.commit()

        return jsonify({'success': True})

    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)})


@app.route('/salary-history')
@staff_required(access_level=4)
def salary_history():
    month = request.args.get('month', type=int)
    year = request.args.get('year', type=int)

    query = SalaryHistory.query.join(User)

    if month:
        query = query.filter(SalaryHistory.month == month)
    if year:
        query = query.filter(SalaryHistory.year == year)

    history = query.order_by(SalaryHistory.year.desc(), SalaryHistory.month.desc()).all()

    html = '''
    <table class="table table-striped">
        <thead>
            <tr>
                <th>Месяц/Год</th>
                <th>Модератор</th>
                <th>Базовая ЗП</th>
                <th>Множитель</th>
                <th>Итоговая ЗП</th>
                <th>Детали</th>
            </tr>
        </thead>
        <tbody>
    '''

    for record in history:
        details = json.loads(record.details) if record.details else {}
        html += f'''
            <tr>
                <td>{record.month}/{record.year}</td>
                <td>{record.user.username}</td>
                <td>{record.base_salary}</td>
                <td>x{record.multiplier:.2f}</td>
                <td><strong>{record.final_salary}</strong></td>
                <td>
                    <button class="btn btn-sm btn-info" type="button" data-bs-toggle="collapse" 
                            data-bs-target="#details-{record.id}" aria-expanded="false" 
                            aria-controls="details-{record.id}">
                        Показать детали
                    </button>
                    <div class="collapse" id="details-{record.id}">
                        <div class="card card-body">
                            <strong>Позитивные множители:</strong> {', '.join(details.get('positive_details', [])) if details.get('positive_details') else 'Нет'}<br>
                            <strong>Негативные множители:</strong> {', '.join(details.get('negative_details', [])) if details.get('negative_details') else 'Нет'}<br>
                            <strong>Пропущено недель:</strong> {details.get('weeks_missed', 0)}<br>
                            <strong>Место в рейтинге:</strong> {details.get('rank', 'Н/Д')}
                        </div>
                    </div>
                </td>
            </tr>
        '''

    html += '</tbody></table>'

    return jsonify({'html': html})


@app.route('/purchase-shop')
@staff_required()
def purchase_shop():
    user_requests = PurchaseRequest.query.filter_by(user_id=current_user.id).order_by(
        PurchaseRequest.created_at.desc()).all()

    pending_requests = []
    if current_user.access_level >= 6:
        pending_requests = PurchaseRequest.query.filter_by(status='pending').order_by(PurchaseRequest.created_at).all()

    return render_template('purchase_shop.html',
                           user_requests=user_requests,
                           pending_requests=pending_requests,
                           current_user=current_user)


@app.route('/submit-purchase-request', methods=['POST'])
@staff_required()
def submit_purchase_request():
    try:
        mode = request.form.get('mode')
        nickname = request.form.get('nickname')
        item = request.form.get('item')
        amount = int(request.form.get('amount'))

        if not all([mode, nickname, item, amount]):
            flash('Все поля обязательны для заполнения', 'danger')
            return redirect(url_for('purchase_shop'))

        if amount <= 0:
            flash('Сумма покупки должна быть положительной', 'danger')
            return redirect(url_for('purchase_shop'))

        current_balance = int(current_user.salary) if current_user.salary and current_user.salary.isdigit() else 0
        if current_balance < amount:
            flash('Недостаточно средств на счете', 'danger')
            return redirect(url_for('purchase_shop'))

        purchase_request = PurchaseRequest(
            user_id=current_user.id,
            mode=mode,
            nickname=nickname,
            item=item,
            amount=amount,
            status='pending'
        )

        db.session.add(purchase_request)
        db.session.commit()

        flash('Заявка успешно отправлена на рассмотрение!', 'success')
        return redirect(url_for('purchase_shop'))

    except ValueError:
        db.session.rollback()
        flash('Неверный формат суммы', 'danger')
        return redirect(url_for('purchase_shop'))
    except Exception as e:
        db.session.rollback()
        flash(f'Ошибка при отправке заявки: {str(e)}', 'danger')
        return redirect(url_for('purchase_shop'))


@app.route('/process-purchase-request/<int:request_id>', methods=['POST'])
@staff_required(access_level=6)
def process_purchase_request(request_id):
    try:
        action = request.form.get('action')
        rejection_reason = request.form.get('rejection_reason', '')

        purchase_request = PurchaseRequest.query.get_or_404(request_id)

        if purchase_request.status != 'pending':
            flash('Эта заявка уже обработана', 'warning')
            return redirect(url_for('purchase_shop'))

        if action == 'approve':
            user = User.query.get(purchase_request.user_id)
            current_balance = int(user.salary) if user.salary and user.salary.isdigit() else 0

            if current_balance < purchase_request.amount:
                flash('У пользователя недостаточно средств', 'danger')
                return redirect(url_for('purchase_shop'))

            user.salary = str(current_balance - purchase_request.amount)
            purchase_request.status = 'approved'
            flash('Заявка одобрена, средства списаны', 'success')

        elif action == 'reject':
            if not rejection_reason.strip():
                flash('Укажите причину отказа', 'danger')
                return redirect(url_for('purchase_shop'))

            purchase_request.status = 'rejected'
            purchase_request.rejection_reason = rejection_reason
            flash('Заявка отклонена', 'info')

        purchase_request.processed_by = current_user.id
        purchase_request.processed_at = datetime.now()

        db.session.commit()
        return redirect(url_for('purchase_shop'))

    except Exception as e:
        db.session.rollback()
        flash(f'Ошибка при обработке заявки: {str(e)}', 'danger')
        return redirect(url_for('purchase_shop'))


@app.route('/get-purchase-requests')
@staff_required()
def get_purchase_requests():
    status_filter = request.args.get('status', 'all')

    query = PurchaseRequest.query.filter_by(user_id=current_user.id)

    if status_filter != 'all':
        query = query.filter_by(status=status_filter)

    requests = query.order_by(PurchaseRequest.created_at.desc()).all()

    requests_data = []
    for req in requests:
        requests_data.append({
            'id': req.id,
            'mode': req.mode,
            'nickname': req.nickname,
            'item': req.item,
            'amount': req.amount,
            'status': req.status,
            'rejection_reason': req.rejection_reason,
            'created_at': req.created_at.strftime('%d.%m.%Y %H:%M'),
            'processed_at': req.processed_at.strftime('%d.%m.%Y %H:%M') if req.processed_at else None
        })

    return jsonify({'requests': requests_data})


@app.route('/vacation-requests')
@staff_required()
def vacation_requests():
    user_requests = VacationRequest.query.filter_by(user_id=current_user.id).order_by(
        VacationRequest.created_at.desc()).all()

    pending_requests = []
    if current_user.access_level >= 4:
        pending_requests = VacationRequest.query.filter_by(status='pending').order_by(
            VacationRequest.created_at).all()

    return render_template('vacation_requests.html',
                           user_requests=user_requests,
                           pending_requests=pending_requests,
                           current_user=current_user)


@app.route('/submit-vacation-request', methods=['POST'])
@staff_required()
def submit_vacation_request():
    try:
        start_date_str = request.form.get('start_date')
        end_date_str = request.form.get('end_date')
        reason = request.form.get('reason')

        if not all([start_date_str, end_date_str, reason]):
            flash('Все поля обязательны для заполнения', 'danger')
            return redirect(url_for('vacation_requests'))

        start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()
        end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date()

        if start_date >= end_date:
            flash('Дата окончания должна быть позже даты начала', 'danger')
            return redirect(url_for('vacation_requests'))

        if start_date < datetime.now().date():
            flash('Дата начала не может быть в прошлом', 'danger')
            return redirect(url_for('vacation_requests'))

        existing_requests = VacationRequest.query.filter(
            VacationRequest.user_id == current_user.id,
            VacationRequest.status == 'pending',
            VacationRequest.start_date <= end_date,
            VacationRequest.end_date >= start_date
        ).first()

        if existing_requests:
            flash('У вас уже есть активная заявка на отпуск в этот период', 'danger')
            return redirect(url_for('vacation_requests'))

        vacation_request = VacationRequest(
            user_id=current_user.id,
            start_date=start_date,
            end_date=end_date,
            reason=reason,
            status='pending'
        )

        db.session.add(vacation_request)
        db.session.commit()

        flash('Заявка на отпуск успешно отправлена на рассмотрение!', 'success')
        return redirect(url_for('vacation_requests'))

    except ValueError:
        db.session.rollback()
        flash('Неверный формат даты', 'danger')
        return redirect(url_for('vacation_requests'))
    except Exception as e:
        db.session.rollback()
        flash(f'Ошибка при отправке заявки: {str(e)}', 'danger')
        return redirect(url_for('vacation_requests'))


@app.route('/process-vacation-request/<int:request_id>', methods=['POST'])
@staff_required(access_level=4)
def process_vacation_request(request_id):
    try:
        action = request.form.get('action')
        rejection_reason = request.form.get('rejection_reason', '')

        vacation_request = VacationRequest.query.get_or_404(request_id)

        if vacation_request.status != 'pending':
            flash('Эта заявка уже обработана', 'warning')
            return redirect(url_for('vacation_requests'))

        if action == 'approve':
            vacation_request.status = 'approved'
            flash('Заявка на отпуск одобрена', 'success')

        elif action == 'reject':
            if not rejection_reason.strip():
                flash('Укажите причину отказа', 'danger')
                return redirect(url_for('vacation_requests'))

            vacation_request.status = 'rejected'
            vacation_request.rejection_reason = rejection_reason
            flash('Заявка на отпуск отклонена', 'info')

        vacation_request.processed_by = current_user.id
        vacation_request.processed_at = datetime.now()

        db.session.commit()
        return redirect(url_for('vacation_requests'))

    except Exception as e:
        db.session.rollback()
        flash(f'Ошибка при обработке заявки: {str(e)}', 'danger')
        return redirect(url_for('vacation_requests'))


@app.route('/get-vacation-requests')
@staff_required()
def get_vacation_requests():
    status_filter = request.args.get('status', 'all')

    query = VacationRequest.query.filter_by(user_id=current_user.id)

    if status_filter != 'all':
        query = query.filter_by(status=status_filter)

    requests = query.order_by(VacationRequest.created_at.desc()).all()

    requests_data = []
    for req in requests:
        requests_data.append({
            'id': req.id,
            'start_date': req.start_date.strftime('%d.%m.%Y'),
            'end_date': req.end_date.strftime('%d.%m.%Y'),
            'reason': req.reason,
            'status': req.status,
            'rejection_reason': req.rejection_reason,
            'created_at': req.created_at.strftime('%d.%m.%Y %H:%M'),
            'processed_at': req.processed_at.strftime('%d.%m.%Y %H:%M') if req.processed_at else None,
            'days': (req.end_date - req.start_date).days + 1
        })

    return jsonify({'requests': requests_data})


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