from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime

db = SQLAlchemy()


class ModeratorStats(db.Model):
    __tablename__ = 'moderator_stats'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.BigInteger, db.ForeignKey('user.id'), nullable=False)
    day = db.Column(db.Integer, nullable=False)
    month = db.Column(db.Integer, nullable=False)
    year = db.Column(db.Integer, nullable=False)
    punishments = db.Column(db.Integer, default=0)
    tickets_closed = db.Column(db.Integer, default=0)
    weeks_missed = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.now)

    user = db.relationship('User', backref=db.backref('stats', lazy=True))

    __table_args__ = (db.UniqueConstraint('user_id', 'day', 'month', 'year', name='unique_user_day_month_year'),)


class SalaryHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.BigInteger, db.ForeignKey('user.id'), nullable=False)
    day = db.Column(db.Integer, nullable=False)
    month = db.Column(db.Integer, nullable=False)
    year = db.Column(db.Integer, nullable=False)
    base_salary = db.Column(db.Integer, default=0)
    final_salary = db.Column(db.Integer, default=0)
    multiplier = db.Column(db.Float, default=1.0)
    details = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

    user = db.relationship('User', backref=db.backref('salaries', lazy=True))


class StaffRole(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    role_name = db.Column(db.String(100), nullable=False)
    permissions = db.Column(db.Text, nullable=False)
    responsibilities = db.Column(db.Text, nullable=False)
    access_level = db.Column(db.Integer, nullable=False)


class ResponseTemplate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    situation = db.Column(db.String(200), nullable=False)
    response = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    updated_at = db.Column(db.DateTime, default=db.func.current_timestamp(), onupdate=db.func.current_timestamp())


class User(db.Model, UserMixin):
    def __init__(self, id, username, avatar, access_level):
        self.id = id
        self.username = username
        self.avatar = avatar
        self.access_level = access_level
    id = db.Column(db.BigInteger, primary_key=True)
    username = db.Column(db.String(100))
    avatar = db.Column(db.String(100))
    access_level = db.Column(db.Integer, default=0)
    full_name = db.Column(db.String(100))
    nickname = db.Column(db.String(50))
    salary = db.Column(db.String(20))
    warnings = db.Column(db.String(10))
    vacation_date = db.Column(db.Date)
    join_date = db.Column(db.Date)
    vk_link = db.Column(db.String(100))

    @property
    def has_access(self):
        return self.access_level > 0

    @property
    def is_active(self):
        return True

    @property
    def is_authenticated(self):
        return True

    @property
    def is_anonymous(self):
        return False

    def get_id(self):
        return str(self.id)

class Guide(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(50), default='Общее')
    last_updated = db.Column(db.DateTime, default=db.func.current_timestamp())