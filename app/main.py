import os
import uuid
import logging
import jwt
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, request, g
from flask_restx import Api, Resource, fields

from app.db import get_connection, init_db

# ---------------- CONFIGURACIÓN DE JWT ----------------
SECRET_KEY = os.environ.get("SECRET_KEY", "6b386721f42077c8438c6819aae62e3afdef4b7065cede3d42318371bc18bf0b")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# ---------------- CONFIGURACIÓN DE LOGGING ----------------
# Configuración básica que escribe en el archivo app.log
logging.basicConfig(
    filename="app.log",
    level=logging.INFO,
    encoding="utf-8",
    filemode="a",
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
# Agregamos un handler para que también se muestre en consola
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s", "%Y-%m-%d %H:%M:%S")
console_handler.setFormatter(console_formatter)
logging.getLogger().addHandler(console_handler)

# ---------------- INICIALIZACIÓN DE FLASK Y API ----------------
app = Flask(__name__)

authorizations = {
    'Bearer': {
        'type': 'apiKey',
        'in': 'header',
        'name': 'Authorization',
        'description': "Ingresa tu token en el formato **Bearer <token>**"
    }
}

api = Api(
    app,
    version='1.0',
    title='Core Bancario API',
    description='API para operaciones bancarias, incluyendo autenticación y operaciones de cuenta.',
    doc='/swagger',
    authorizations=authorizations,
    security='Bearer'
)

# Namespaces
auth_ns = api.namespace('auth', description='Operaciones de autenticación')
bank_ns = api.namespace('bank', description='Operaciones bancarias')

# ---------------- MODELOS DE DATOS (para Swagger) ----------------
login_model = auth_ns.model('Login', {
    'username': fields.String(required=True, description='Nombre de usuario', example='user1'),
    'password': fields.String(required=True, description='Contraseña', example='pass1')
})

deposit_model = bank_ns.model('Deposit', {
    'account_number': fields.Integer(required=True, description='Número de cuenta', example=123),
    'amount': fields.Float(required=True, description='Monto a depositar', example=100)
})

withdraw_model = bank_ns.model('Withdraw', {
    'amount': fields.Float(required=True, description='Monto a retirar', example=100)
})

transfer_model = bank_ns.model('Transfer', {
    'target_username': fields.String(required=True, description='Usuario destino', example='user2'),
    'amount': fields.Float(required=True, description='Monto a transferir', example=100)
})

credit_payment_model = bank_ns.model('CreditPayment', {
    'amount': fields.Float(required=True, description='Monto de la compra a crédito', example=100)
})

pay_credit_balance_model = bank_ns.model('PayCreditBalance', {
    'amount': fields.Float(required=True, description='Monto a abonar a la deuda de la tarjeta', example=50)
})

# ---------------- HOOK PARA LOGGING DE CADA REQUEST ----------------
@app.after_request
def log_request_info(response):
    log_message = (
        f"IP={request.remote_addr} | Action={request.method} {request.path} | Status={response.status_code}"
    )
    user_info = getattr(g, 'user', None)
    if user_info:
        log_message += f" | UserID={user_info['id']} Username={user_info['username']}"
    logging.info(log_message)
    return response

# ---------------- DECORADOR: TOKEN_REQUIRED CON BLACKLIST ----------------
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            api.abort(401, "Authorization header missing or invalid")
        token = auth_header.split(" ")[1]
        try:
            decoded = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        except jwt.ExpiredSignatureError:
            api.abort(401, "Token has expired")
        except jwt.InvalidTokenError:
            api.abort(401, "Invalid token")

        # Verificar que el token no esté revocado (blacklist)
        jti = decoded.get("jti")
        if jti is None:
            api.abort(401, "Token missing jti")
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM bank.blacklist_tokens WHERE jti = %s", (jti,))
        count = cur.fetchone()[0]
        cur.close()
        conn.close()
        if count > 0:
            api.abort(401, "Token has been revoked")

        # Validar información del usuario
        user_id = decoded.get("user_id")
        username = decoded.get("username")
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("""
            SELECT id, username, role, full_name, email 
            FROM bank.users 
            WHERE id = %s AND username = %s
        """, (user_id, username))
        user = cur.fetchone()
        cur.close()
        conn.close()
        if not user:
            api.abort(401, "User not found or token invalid")

        # Guardamos la información del usuario en g
        g.user = {
            "id": user[0],
            "username": user[1],
            "role": user[2],
            "full_name": user[3],
            "email": user[4]
        }
        return f(*args, **kwargs)
    return decorated

# ---------------- ENDPOINTS DE AUTENTICACIÓN ----------------
@auth_ns.route('/login')
class Login(Resource):
    @auth_ns.expect(login_model, validate=True)
    def post(self):
        """Inicia sesión y devuelve un token JWT."""
        data = api.payload
        username = data.get("username")
        password = data.get("password")

        conn = get_connection()
        cur = conn.cursor()
        cur.execute("""
            SELECT id, username, password, role, full_name, email 
            FROM bank.users 
            WHERE username = %s
        """, (username,))
        user = cur.fetchone()
        cur.close()
        conn.close()

        if user and user[2] == password:
            # Generar un jti único para el token
            jti = str(uuid.uuid4())
            payload = {
                "user_id": user[0],
                "username": user[1],
                "role": user[3],
                "jti": jti,
                "exp": datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
                "iat": datetime.utcnow()
            }
            token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
            return {"message": "Login successful", "token": token}, 200
        else:
            api.abort(401, "Invalid credentials")

@auth_ns.route('/logout')
class Logout(Resource):
    @token_required
    def post(self):
        """Invalida el token actual agregando su jti a la blacklist."""
        auth_header = request.headers.get("Authorization", "")
        token = auth_header.split(" ")[1]
        try:
            decoded = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        except jwt.InvalidTokenError:
            api.abort(401, "Invalid token")
        jti = decoded.get("jti")
        if jti is None:
            api.abort(400, "Token missing jti")

        # Insertar el jti en la tabla de blacklist para revocar el token
        conn = get_connection()
        cur = conn.cursor()
        try:
            cur.execute("""
                INSERT INTO bank.blacklist_tokens (jti) VALUES (%s)
            """, (jti,))
            conn.commit()
        except Exception as e:
            conn.rollback()
            cur.close()
            conn.close()
            api.abort(500, f"Error revoking token: {str(e)}")
        cur.close()
        conn.close()
        return {"message": "Logout successful, token revoked"}, 200

# ---------------- ENDPOINTS DE OPERACIONES BANCARIAS ----------------
@bank_ns.route('/deposit')
class Deposit(Resource):
    @bank_ns.expect(deposit_model, validate=True)
    @token_required
    def post(self):
        """Realiza un depósito en la cuenta especificada."""
        data = api.payload
        account_number = data.get("account_number")
        amount = data.get("amount", 0)
        if amount <= 0:
            api.abort(400, "Amount must be greater than zero")
        conn = get_connection()
        cur = conn.cursor()
        cur.execute(
            "UPDATE bank.accounts SET balance = balance + %s WHERE id = %s RETURNING balance",
            (amount, account_number)
        )
        result = cur.fetchone()
        if not result:
            conn.rollback()
            cur.close()
            conn.close()
            api.abort(404, "Account not found")
        new_balance = float(result[0])
        conn.commit()
        cur.close()
        conn.close()
        return {"message": "Deposit successful", "new_balance": new_balance}, 200

@bank_ns.route('/withdraw')
class Withdraw(Resource):
    @bank_ns.expect(withdraw_model, validate=True)
    @token_required
    def post(self):
        """Realiza un retiro de la cuenta del usuario autenticado."""
        data = api.payload
        amount = data.get("amount", 0)
        if amount <= 0:
            api.abort(400, "Amount must be greater than zero")
        user_id = g.user['id']
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT balance FROM bank.accounts WHERE user_id = %s", (user_id,))
        row = cur.fetchone()
        if not row:
            cur.close()
            conn.close()
            api.abort(404, "Account not found")
        current_balance = float(row[0])
        if current_balance < amount:
            cur.close()
            conn.close()
            api.abort(400, "Insufficient funds")
        cur.execute("UPDATE bank.accounts SET balance = balance - %s WHERE user_id = %s RETURNING balance",
                    (amount, user_id))
        new_balance = float(cur.fetchone()[0])
        conn.commit()
        cur.close()
        conn.close()
        return {"message": "Withdrawal successful", "new_balance": new_balance}, 200

@bank_ns.route('/transfer')
class Transfer(Resource):
    @bank_ns.expect(transfer_model, validate=True)
    @token_required
    def post(self):
        """Transfiere fondos desde la cuenta del usuario autenticado a otra cuenta."""
        data = api.payload
        target_username = data.get("target_username")
        amount = data.get("amount", 0)
        if not target_username or amount <= 0:
            api.abort(400, "Invalid data")
        if target_username == g.user['username']:
            api.abort(400, "Cannot transfer to the same account")
        conn = get_connection()
        cur = conn.cursor()
        # Verificar saldo del remitente
        cur.execute("SELECT balance FROM bank.accounts WHERE user_id = %s", (g.user['id'],))
        row = cur.fetchone()
        if not row:
            cur.close()
            conn.close()
            api.abort(404, "Sender account not found")
        sender_balance = float(row[0])
        if sender_balance < amount:
            cur.close()
            conn.close()
            api.abort(400, "Insufficient funds")
        # Encontrar usuario destino
        cur.execute("SELECT id FROM bank.users WHERE username = %s", (target_username,))
        target_user = cur.fetchone()
        if not target_user:
            cur.close()
            conn.close()
            api.abort(404, "Target user not found")
        target_user_id = target_user[0]
        try:
            cur.execute("UPDATE bank.accounts SET balance = balance - %s WHERE user_id = %s", (amount, g.user['id']))
            cur.execute("UPDATE bank.accounts SET balance = balance + %s WHERE user_id = %s", (amount, target_user_id))
            cur.execute("SELECT balance FROM bank.accounts WHERE user_id = %s", (g.user['id'],))
            new_balance = float(cur.fetchone()[0])
            conn.commit()
        except Exception as e:
            conn.rollback()
            cur.close()
            conn.close()
            api.abort(500, f"Error during transfer: {str(e)}")
        cur.close()
        conn.close()
        return {"message": "Transfer successful", "new_balance": new_balance}, 200

@bank_ns.route('/credit-payment')
class CreditPayment(Resource):
    @bank_ns.expect(credit_payment_model, validate=True)
    @token_required
    def post(self):
        """
        Realiza una compra a crédito:
          - Descuenta el monto de la cuenta.
          - Aumenta la deuda de la tarjeta de crédito.
        """
        data = api.payload
        amount = data.get("amount", 0)
        if amount <= 0:
            api.abort(400, "Amount must be greater than zero")
        user_id = g.user['id']
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT balance FROM bank.accounts WHERE user_id = %s", (user_id,))
        row = cur.fetchone()
        if not row:
            cur.close()
            conn.close()
            api.abort(404, "Account not found")
        account_balance = float(row[0])
        if account_balance < amount:
            cur.close()
            conn.close()
            api.abort(400, "Insufficient funds in account")
        try:
            cur.execute("UPDATE bank.accounts SET balance = balance - %s WHERE user_id = %s", (amount, user_id))
            cur.execute("UPDATE bank.credit_cards SET balance = balance + %s WHERE user_id = %s", (amount, user_id))
            cur.execute("SELECT balance FROM bank.accounts WHERE user_id = %s", (user_id,))
            new_account_balance = float(cur.fetchone()[0])
            cur.execute("SELECT balance FROM bank.credit_cards WHERE user_id = %s", (user_id,))
            new_credit_balance = float(cur.fetchone()[0])
            conn.commit()
        except Exception as e:
            conn.rollback()
            cur.close()
            conn.close()
            api.abort(500, f"Error processing credit card purchase: {str(e)}")
        cur.close()
        conn.close()
        return {
            "message": "Credit card purchase successful",
            "account_balance": new_account_balance,
            "credit_card_debt": new_credit_balance
        }, 200

@bank_ns.route('/pay-credit-balance')
class PayCreditBalance(Resource):
    @bank_ns.expect(pay_credit_balance_model, validate=True)
    @token_required
    def post(self):
        """
        Realiza un abono a la deuda de la tarjeta:
          - Descuenta el monto (o el máximo posible) de la cuenta.
          - Reduce la deuda de la tarjeta de crédito.
        """
        data = api.payload
        amount = data.get("amount", 0)
        if amount <= 0:
            api.abort(400, "Amount must be greater than zero")
        user_id = g.user['id']
        conn = get_connection()
        cur = conn.cursor()
        # Verificar fondos de la cuenta
        cur.execute("SELECT balance FROM bank.accounts WHERE user_id = %s", (user_id,))
        row = cur.fetchone()
        if not row:
            cur.close()
            conn.close()
            api.abort(404, "Account not found")
        account_balance = float(row[0])
        if account_balance < amount:
            cur.close()
            conn.close()
            api.abort(400, "Insufficient funds in account")
        # Obtener deuda actual de la tarjeta de crédito
        cur.execute("SELECT balance FROM bank.credit_cards WHERE user_id = %s", (user_id,))
        row = cur.fetchone()
        if not row:
            cur.close()
            conn.close()
            api.abort(404, "Credit card not found")
        credit_debt = float(row[0])
        payment = min(amount, credit_debt)
        try:
            cur.execute("UPDATE bank.accounts SET balance = balance - %s WHERE user_id = %s", (payment, user_id))
            cur.execute("UPDATE bank.credit_cards SET balance = balance - %s WHERE user_id = %s", (payment, user_id))
            cur.execute("SELECT balance FROM bank.accounts WHERE user_id = %s", (user_id,))
            new_account_balance = float(cur.fetchone()[0])
            cur.execute("SELECT balance FROM bank.credit_cards WHERE user_id = %s", (user_id,))
            new_credit_debt = float(cur.fetchone()[0])
            conn.commit()
        except Exception as e:
            conn.rollback()
            cur.close()
            conn.close()
            api.abort(500, f"Error processing credit balance payment: {str(e)}")
        cur.close()
        conn.close()
        return {
            "message": "Credit card debt payment successful",
            "account_balance": new_account_balance,
            "credit_card_debt": new_credit_debt
        }, 200

# ---------------- INICIALIZACIÓN DE LA BASE DE DATOS ----------------
@app.before_first_request
def initialize_db():
    init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
