import os
from app import create_app
from app.extensions import db
from sqlalchemy import text

config_name = os.environ.get('FLASK_CONFIG', 'development')
app = create_app(config_name)

if __name__ == '__main__':
    with app.app_context():
        try:
            db.session.execute(text('CREATE EXTENSION IF NOT EXISTS vector'))
            db.session.commit()
        except Exception:
            db.session.rollback()
        db.create_all()
        from app.blueprints.missions.routes import seed_missions
        seed_missions()
    app.run(debug=True, port=8080)
