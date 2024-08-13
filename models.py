from app import db

class API(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

class SecurityCheck(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    api_id = db.Column(db.Integer, db.ForeignKey('API.id'), nullable=False)
    check_name = db.Column(db.String(100), nullable=False)
    result = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
