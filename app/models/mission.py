import uuid
from datetime import datetime
from app.extensions import db


class Mission(db.Model):
    __tablename__ = 'missions'

    id = db.Column(db.Uuid, primary_key=True, default=uuid.uuid4)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    briefing = db.Column(db.Text)  # Story/scenario text shown at start
    difficulty = db.Column(db.String(20), nullable=False, default='beginner')
    category = db.Column(db.String(50), nullable=False, default='general')
    icon = db.Column(db.String(50), default='shield')
    points_total = db.Column(db.Integer, default=100)
    time_limit_minutes = db.Column(db.Integer, nullable=True)  # None = no limit
    order = db.Column(db.Integer, default=0)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    challenges = db.relationship('Challenge', back_populates='mission',
                                 order_by='Challenge.order', lazy='dynamic')
    user_progress = db.relationship('UserMissionProgress', back_populates='mission')

    @property
    def challenge_count(self):
        return self.challenges.count()


class Challenge(db.Model):
    __tablename__ = 'challenges'

    id = db.Column(db.Uuid, primary_key=True, default=uuid.uuid4)
    mission_id = db.Column(db.Uuid, db.ForeignKey('missions.id'), nullable=False)
    order = db.Column(db.Integer, nullable=False, default=0)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    task_type = db.Column(db.String(30), nullable=False, default='text_answer')
    # task_type: text_answer, multiple_choice, flag_submission, command_output
    answer = db.Column(db.String(500), nullable=False)  # Correct answer or flag
    answer_is_regex = db.Column(db.Boolean, default=False)
    choices = db.Column(db.JSON, nullable=True)  # For multiple_choice
    hint = db.Column(db.Text, nullable=True)
    explanation = db.Column(db.Text, nullable=True)  # Shown after solving
    points = db.Column(db.Integer, default=10)
    resource_html = db.Column(db.Text, nullable=True)  # Extra content (logs, code, etc.)

    mission = db.relationship('Mission', back_populates='challenges')
    user_completions = db.relationship('UserChallengeCompletion', back_populates='challenge')


class UserMissionProgress(db.Model):
    __tablename__ = 'user_mission_progress'

    id = db.Column(db.Uuid, primary_key=True, default=uuid.uuid4)
    user_id = db.Column(db.Uuid, db.ForeignKey('users.id'), nullable=False)
    mission_id = db.Column(db.Uuid, db.ForeignKey('missions.id'), nullable=False)
    status = db.Column(db.String(20), default='in_progress')  # in_progress, completed
    started_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime, nullable=True)
    points_earned = db.Column(db.Integer, default=0)

    user = db.relationship('User')
    mission = db.relationship('Mission', back_populates='user_progress')

    __table_args__ = (
        db.UniqueConstraint('user_id', 'mission_id', name='uq_user_mission'),
    )


class UserChallengeCompletion(db.Model):
    __tablename__ = 'user_challenge_completions'

    id = db.Column(db.Uuid, primary_key=True, default=uuid.uuid4)
    user_id = db.Column(db.Uuid, db.ForeignKey('users.id'), nullable=False)
    challenge_id = db.Column(db.Uuid, db.ForeignKey('challenges.id'), nullable=False)
    completed_at = db.Column(db.DateTime, default=datetime.utcnow)
    attempts = db.Column(db.Integer, default=1)
    hint_used = db.Column(db.Boolean, default=False)
    points_earned = db.Column(db.Integer, default=0)

    user = db.relationship('User')
    challenge = db.relationship('Challenge', back_populates='user_completions')

    __table_args__ = (
        db.UniqueConstraint('user_id', 'challenge_id', name='uq_user_challenge'),
    )
