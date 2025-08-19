from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

db = SQLAlchemy()


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