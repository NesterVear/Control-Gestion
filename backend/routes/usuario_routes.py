from flask import Blueprint, jsonify, request
from extensions import db
from models import Usuario
import bcrypt

usuario_bp = Blueprint('usuario', __name__)

@usuario_bp.route('/usuario', methods=['POST'], endpoint='crear_usuario')
def crear_usuario():
    data = request.get_json()
    usuario = data.get('usuario')
    contrasena = data.get('contrasena')
    rol = data.get('rol', 'Lector')  # Por defecto Lector
    if not usuario or not contrasena or rol not in ['Administrador', 'Lector', 'SuperRoot']:
        return jsonify({'error': 'Datos inválidos'}), 400
    hashed = bcrypt.hashpw(contrasena.encode('utf-8'), bcrypt.gensalt())
    nuevo_usuario = Usuario(usuario=usuario, contrasena=hashed.decode('utf-8'), rol=rol)
    db.session.add(nuevo_usuario)
    db.session.commit()
    return jsonify({'mensaje': 'Usuario creado correctamente', 'id': nuevo_usuario.id}), 201

@usuario_bp.route('/login', methods=['POST'], endpoint='login')
def login():
    data = request.get_json()
    usuario = data.get('usuario')
    contrasena = data.get('contrasena')
    user = Usuario.query.filter_by(usuario=usuario).first()
    if user and bcrypt.checkpw(contrasena.encode('utf-8'), user.contrasena.encode('utf-8')): 
        return jsonify({'mensaje': 'Login Exitoso, Cachirula te ama', 'id': user.id, 'rol': user.rol}), 200 
    return jsonify({'error': 'Crendenciales Invalidas, Ulises te besara en la noche'}), 401


# Creado por: Nester Vear 🐻
# GitHub: github.com/NesterVear