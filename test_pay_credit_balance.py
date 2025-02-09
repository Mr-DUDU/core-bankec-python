import pytest
import jwt
from main import app, SECRET_KEY, ALGORITHM
from app.db import get_connection

@pytest.fixture
def client():
    """Crea un cliente de pruebas para Flask."""
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client

def get_auth_token(user_id, username):
    """Genera un token JWT de prueba."""
    payload = {
        "user_id": user_id,
        "username": username,
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def create_test_user():
    """Crea un usuario de prueba con cuenta y tarjeta."""
    conn = get_connection()
    cur = conn.cursor()

    # Insertar usuario
    cur.execute("""
        INSERT INTO bank.users (username, password, role, full_name, email) 
        VALUES ('testuser', 'password', 'cliente', 'Test User', 'test@example.com') 
        RETURNING id;
    """)
    user_id = cur.fetchone()[0]

    # Insertar cuenta con saldo 1000
    cur.execute("INSERT INTO bank.accounts (balance, user_id) VALUES (1000, %s);", (user_id,))

    # Insertar tarjeta de crédito con deuda 500
    cur.execute("INSERT INTO bank.credit_cards (limit_credit, balance, user_id) VALUES (5000, 500, %s);", (user_id,))

    conn.commit()
    cur.close()
    conn.close()
    return user_id

def test_pay_own_credit_card(client):
    """Prueba que el usuario pueda pagar su propia tarjeta."""
    user_id = create_test_user()
    token = get_auth_token(user_id, "testuser")

    response = client.post(
        "/bank/pay-credit-balance",
        json={"amount": 100},
        headers={"Authorization": f"Bearer {token}"}
    )

    assert response.status_code == 200
    assert response.json["message"] == "Credit card debt payment successful"
    assert response.json["amount_paid"] == 100

def test_pay_other_user_credit_card(client):
    """Prueba que un usuario NO pueda pagar la tarjeta de otro usuario."""
    user_id = create_test_user()
    token = get_auth_token(user_id, "testuser")

    # Crear otro usuario con tarjeta
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("INSERT INTO bank.users (username, password, role) VALUES ('otheruser', 'password', 'cliente') RETURNING id;")
    other_user_id = cur.fetchone()[0]
    cur.execute("INSERT INTO bank.credit_cards (limit_credit, balance, user_id) VALUES (5000, 500, %s);", (other_user_id,))
    conn.commit()
    cur.close()
    conn.close()

    response = client.post(
        "/bank/pay-credit-balance",
        json={"amount": 100},
        headers={"Authorization": f"Bearer {token}"}
    )

    assert response.status_code == 404  # No debería encontrar la tarjeta del usuario

def test_pay_without_credit_card(client):
    """Prueba que un usuario sin tarjeta no pueda pagar."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("INSERT INTO bank.users (username, password, role) VALUES ('notestuser', 'password', 'cliente') RETURNING id;")
    no_card_user_id = cur.fetchone()[0]
    conn.commit()
    cur.close()
    conn.close()

    token = get_auth_token(no_card_user_id, "notestuser")

    response = client.post(
        "/bank/pay-credit-balance",
        json={"amount": 50},
        headers={"Authorization": f"Bearer {token}"}
    )

    assert response.status_code == 404  # No tiene tarjeta
    assert response.json["message"] == "No credit card found for this user"

def test_pay_more_than_debt(client):
    """Prueba que el usuario no pueda pagar más de su deuda."""
    user_id = create_test_user()
    token = get_auth_token(user_id, "testuser")

    response = client.post(
        "/bank/pay-credit-balance",
        json={"amount": 1000},  # La deuda es solo 500
        headers={"Authorization": f"Bearer {token}"}
    )

    assert response.status_code == 200
    assert response.json["amount_paid"] == 500  # Solo permite pagar lo que debe

def test_pay_with_insufficient_funds(client):
    """Prueba que el usuario no pueda pagar con saldo insuficiente."""
    user_id = create_test_user()
    token = get_auth_token(user_id, "testuser")

    # Reducimos el saldo a 0
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("UPDATE bank.accounts SET balance = 0 WHERE user_id = %s;", (user_id,))
    conn.commit()
    cur.close()
    conn.close()

    response = client.post(
        "/bank/pay-credit-balance",
        json={"amount": 50},
        headers={"Authorization": f"Bearer {token}"}
    )

    assert response.status_code == 400
    assert response.json["message"] == "Insufficient funds in account"
