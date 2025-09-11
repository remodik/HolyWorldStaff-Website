from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

db = SQLAlchemy()


class StaffTask(db.Model):
    __tablename__ = 'staff_tasks'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    created_by = db.Column(db.BigInteger, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now)
    deadline = db.Column(db.DateTime, nullable=True)
    reward_type = db.Column(db.String(20), default='per_completion')
    reward_amount = db.Column(db.Integer, default=0)
    bonus_percentage = db.Column(db.Float, default=0.0)
    max_completions = db.Column(db.Integer, default=1)
    is_active = db.Column(db.Boolean, default=True)

    creator = db.relationship('User', foreign_keys=[created_by])
    completions = db.relationship('TaskCompletion', backref='task', lazy=True)

    @property
    def is_active2(self):
        if self.deadline and self.deadline < datetime.now():
            return False

        if self.max_completions > 0:
            approved_count = len([c for c in self.completions if c.status == 'approved'])
            return approved_count < self.max_completions

        return True


class TaskCompletion(db.Model):
    __tablename__ = 'task_completions'

    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.Integer, db.ForeignKey('staff_tasks.id'), nullable=False)
    user_id = db.Column(db.BigInteger, db.ForeignKey('user.id'), nullable=False)
    completed_at = db.Column(db.DateTime, default=datetime.now)
    proof = db.Column(db.Text)
    status = db.Column(db.String(20), default='pending')
    reward_type = db.Column(db.String(20))
    is_bonus = db.Column(db.Boolean, default=False)
    reviewed_by = db.Column(db.BigInteger, db.ForeignKey('user.id'), nullable=True)
    reviewed_at = db.Column(db.DateTime, nullable=True)
    review_notes = db.Column(db.Text)


    user = db.relationship('User', foreign_keys=[user_id])
    reviewer = db.relationship('User', foreign_keys=[reviewed_by])


class Dismissal(db.Model):
    __tablename__ = 'dismissals'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.BigInteger, db.ForeignKey('user.id'), nullable=False)
    date = db.Column(db.DateTime, default=datetime.now, nullable=False)
    reason = db.Column(db.String(255), nullable=True)
    previous_access_level = db.Column(db.Integer, nullable=True)
    dismissed_by = db.Column(db.BigInteger, db.ForeignKey('user.id'), nullable=True)

    rehired = db.Column(db.Boolean, default=False, nullable=False)
    rehired_date = db.Column(db.DateTime, nullable=True)
    rehired_by = db.Column(db.BigInteger, db.ForeignKey('user.id'), nullable=True)

    notes = db.Column(db.Text, nullable=True)
    warnings_history = db.Column(db.Text, nullable=True)

    user = db.relationship('User', foreign_keys=[user_id], backref=db.backref('dismissals', lazy=True))
    dismissed_by_user = db.relationship('User', foreign_keys=[dismissed_by], post_update=True)
    rehired_by_user = db.relationship('User', foreign_keys=[rehired_by], post_update=True)


class VacationRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.BigInteger, db.ForeignKey('user.id'), nullable=False)
    start_date = db.Column(db.Date, nullable=False)
    end_date = db.Column(db.Date, nullable=False)
    reason = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='pending')
    rejection_reason = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.now)
    processed_at = db.Column(db.DateTime)
    processed_by = db.Column(db.BigInteger, db.ForeignKey('user.id'))

    user = db.relationship('User', foreign_keys=[user_id], backref=db.backref('vacation_requests', lazy=True))
    processor = db.relationship('User', foreign_keys=[processed_by])


class PurchaseRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.BigInteger, db.ForeignKey('user.id'), nullable=False)
    mode = db.Column(db.String(100), nullable=False)
    nickname = db.Column(db.String(100), nullable=False)
    item = db.Column(db.Text, nullable=False)
    amount = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(20), default='pending')
    rejection_reason = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.now)
    processed_at = db.Column(db.DateTime)
    processed_by = db.Column(db.BigInteger, db.ForeignKey('user.id'))

    user = db.relationship('User', foreign_keys=[user_id], backref=db.backref('purchase_requests', lazy=True))
    processor = db.relationship('User', foreign_keys=[processed_by])


class ModeratorStats(db.Model):
    __tablename__ = 'moderator_stats'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.BigInteger, db.ForeignKey('user.id'), nullable=False)
    month = db.Column(db.Integer, nullable=False)
    year = db.Column(db.Integer, nullable=False)
    punishments = db.Column(db.Integer, default=0)
    tickets_closed = db.Column(db.Integer, default=0)
    weeks_missed = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.now)
    is_top_moderator = db.Column(db.Boolean, default=False)

    user = db.relationship('User', backref=db.backref('stats', lazy=True))

    __table_args__ = (db.UniqueConstraint('user_id', 'month', 'year', name='unique_user_month_year'),)


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
    created_at = db.Column(db.DateTime, default=datetime.now)

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
    created_at = db.Column(db.DateTime, default=datetime.now)
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)


class User(db.Model, UserMixin):
    def __init__(self, _id, username, avatar, access_level):
        self.id = _id
        self.username = username
        self.avatar = avatar
        self.access_level = access_level

    __tablename__ = 'user'

    id = db.Column(db.BigInteger, primary_key=True)
    username = db.Column(db.String(100))
    avatar = db.Column(db.String(255))
    access_level = db.Column(db.Integer, default=0)
    full_name = db.Column(db.String(100))
    nickname = db.Column(db.String(50))
    salary = db.Column(db.String(20))
    warnings = db.Column(db.String(10))
    vacation_date = db.Column(db.Date)
    join_date = db.Column(db.Date)
    vk_link = db.Column(db.String(100))
    additional_data = db.Column(db.Text, nullable=True)
    email = db.Column(db.String(120), nullable=True)

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
    last_updated = db.Column(db.DateTime, default=datetime.now)
