import os
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
 
# Initialisation de l'application Flask
app = Flask(__name__)
 
# Configuration basique
app.config['SECRET_KEY'] = 'secretkey'  # À changer en production
app.config['JWT_SECRET_KEY'] = 'jwtsecretkey'  # Idem ici
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
 
# Configuration de la base de données (SQLite pour simplifier)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
 
db = SQLAlchemy(app)
jwt = JWTManager(app)
 
# Modèle utilisateur
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
 
    def set_password(self, password):
        self.password_hash = generate_password_hash(password, method='pbkdf2:sha256')
 
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
 
# Modèle Patient
class Patient(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nom = db.Column(db.String(64), nullable=False)
    date_naissance = db.Column(db.Date, nullable=False)
 
# Création de la base de données si elle n'existe pas déjà
with app.app_context():
    db.create_all()
    if not User.query.filter_by(username='admin').first():
        admin = User(username='admin')
        admin.set_password('admin123')
        db.session.add(admin)
        db.session.commit()
 
# Route principale
@app.route('/')
def index():
    return jsonify({'message': "Bienvenue sur l'API"}), 200
 
# Route pour la connexion
@app.route('/api/login', methods=['POST'])
def login():
    if not request.is_json:
        return jsonify({'error': 'Le format JSON est requis'}), 400
   
    data = request.get_json()
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({'error': 'Champs requis'}), 400
 
    user = User.query.filter_by(username=data['username']).first()
    if user and user.check_password(data['password']):
        access_token = create_access_token(identity=user.id)
        return jsonify({'access_token': access_token}), 200
    return jsonify({'error': 'Identifiants invalides'}), 401
 
# Route pour récupérer ou ajouter des patients
@app.route('/api/patients', methods=['GET', 'POST'])
@jwt_required()
def patients():
    if request.method == 'GET':
        patients = Patient.query.all()
        return jsonify([{'id': p.id, 'nom': p.nom, 'date_naissance': p.date_naissance.isoformat()} for p in patients]), 200
 
    if not request.is_json:
        return jsonify({'error': 'Le format JSON est requis'}), 400
   
    data = request.get_json()
    if not data or 'nom' not in data or 'date_naissance' not in data:
        return jsonify({'error': 'Champs requis'}), 400
 
    try:
        patient = Patient(nom=data['nom'], date_naissance=datetime.strptime(data['date_naissance'], '%Y-%m-%d').date())
        db.session.add(patient)
        db.session.commit()
        return jsonify({'message': 'Patient ajouté'}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 400
 
# Gestion des erreurs
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Ressource non trouvée'}), 404
 
@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Erreur interne du serveur'}), 500
 
# Lancement de l'application
if __name__ == '__main__':
    app.run(debug=True)
