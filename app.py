from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from ldap3 import Server, Connection, ALL, MODIFY_REPLACE, MODIFY_DELETE, MODIFY_ADD
import re, secrets, logging, os, sqlite3, string
import bcrypt
from urllib.parse import urlparse
from datetime import datetime
from logging.handlers import TimedRotatingFileHandler

app = Flask(__name__)
app.secret_key = 'CHAVE DE SEGREDO'  # Troque por algo realmente secreto

DATABASE = 'app.db'

# Cria o diretório "log" se não existir
if not os.path.exists("log"):
    os.makedirs("log")

class DailyFileHandler(logging.FileHandler):
    def __init__(self, base_filename, mode='a', encoding=None, delay=False):
        # base_filename deve ser o caminho base sem a data e a extensão, ex.: "log/log"
        self.base_filename = base_filename
        self.current_date = datetime.now().strftime("%Y-%m-%d")
        filename = f"{base_filename}-{self.current_date}.txt"
        super().__init__(filename, mode, encoding, delay)

    def emit(self, record):
        current_date = datetime.now().strftime("%Y-%m-%d")
        if current_date != self.current_date:
            self.current_date = current_date
            # Fecha o arquivo atual e reabre com o novo nome
            self.baseFilename = os.path.abspath(f"{self.base_filename}-{self.current_date}.txt")
            if self.stream:
                self.stream.close()
                self.stream = None
            self.stream = self._open()
        super().emit(record)

# Configura o logger específico para operações do gerenciador de usuários
user_logger = logging.getLogger("user_manager")
user_logger.setLevel(logging.INFO)

log_file_base = os.path.join("log", "log")  # o arquivo será "log-YYYY-MM-DD.txt"
handler = DailyFileHandler(log_file_base)
handler.setLevel(logging.INFO)
formatter = logging.Formatter("%(asctime)s %(levelname)s: %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
handler.setFormatter(formatter)
user_logger.addHandler(handler)

# Opcional: eleva o nível de log do Werkzeug para suprimir os logs de acesso
logging.getLogger("werkzeug").setLevel(logging.ERROR)

def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password, hashed):
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cur = conn.cursor()
    # Tabela de administradores locais
    cur.execute('''
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    # Tabela para configuração do LDAP
    cur.execute('''
        CREATE TABLE IF NOT EXISTS ldap_config (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            server TEXT NOT NULL,
            ad_user TEXT NOT NULL,
            ad_password TEXT NOT NULL,
            base_dn TEXT NOT NULL,
            allowed_group TEXT NOT NULL
        )
    ''')
    # Cria um admin local default se nenhum existir (usuário: admin / senha: admin)
    cur.execute("SELECT * FROM admins")
    if cur.fetchone() is None:
        cur.execute("INSERT INTO admins (username, password) VALUES (?, ?)",
            ('admin', hash_password('admin')))
        print("Admin default criado: admin/admin")
    # Configuração LDAP default – atualize conforme necessário.
    cur.execute("SELECT * FROM ldap_config")
    if cur.fetchone() is None:
        cur.execute("INSERT INTO ldap_config (server, ad_user, ad_password, base_dn, allowed_group) VALUES (?, ?, ?, ?, ?)",
                    ('ldap://seu.ad.server', 'usuario@dominio', 'senha', 'dc=dominio,dc=com', 'TESTE'))
        print("Configuração LDAP default criada. Atualize conforme necessário.")
    conn.commit()
    conn.close()

def get_ldap_config():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM ldap_config LIMIT 1")
    row = cur.fetchone()
    conn.close()
    if row:
        return {
            'server': row['server'],
            'ad_user': row['ad_user'],
            'ad_password': row['ad_password'],
            'base_dn': row['base_dn'],
            'allowed_group': row['allowed_group']
        }
    else:
        return None

# Conexão LDAP com opção de usar conexão segura (LDAPS)
def get_ldap_connection(user=None, password=None, secure=False):
    config = get_ldap_config()
    if not config or not config.get('server'):
        raise Exception("Configuração LDAP não encontrada ou incompleta.")

    server_value = config['server']
    # Se o valor não contém protocolo, adiciona conforme secure
    protocol = "ldaps" if secure else "ldap"
    if not server_value.startswith("ldap://") and not server_value.startswith("ldaps://"):
        server_value = f"{protocol}://{server_value}"
    
    parsed = urlparse(server_value)
    host = parsed.hostname
    port = parsed.port
    # Se secure=True e a porta não estiver definida ou for 389, usa 636
    if secure and (port is None or port == 389):
        port = 636
    server = Server(host, port=port, get_info=ALL, use_ssl=secure)
    try:
        if user and password:
            conn = Connection(server, user=user, password=password, auto_bind=True)
        else:
            conn = Connection(server, user=config['ad_user'], password=config['ad_password'], auto_bind=True)
        return conn
    except Exception as e:
        print(f"Erro ao conectar em {server_value}: {e}")
        raise e

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
         if 'user' not in session:
             return redirect(url_for('login'))
         return f(*args, **kwargs)
    return decorated_function

# Apenas usuários que, ao logar, forem validados como membros do grupo permitido (role "ad_admin")
def ad_admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
         if 'user' not in session or session.get('role') != 'ad_admin':
             flash("Você não possui permissão para acessar essa área.")
             return redirect(url_for('index'))
         return f(*args, **kwargs)
    return decorated_function

def local_admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
         if 'user' not in session or session.get('role') != 'local_admin':
             return redirect(url_for('login'))
         return f(*args, **kwargs)
    return decorated_function

@app.route('/favicon.ico')
def favicon():
    return redirect(url_for('static', filename='favicon.ico'))

@app.route('/')
@login_required
def index():
    role = session.get('role')
    return render_template('index.html', user=session['user'], role=role)

# Rota de login: qualquer usuário do AD (filtrado por (&(objectClass=user)(objectCategory=person)...)) pode logar.
# Se pertencer ao grupo configurado, recebe role "ad_admin"; caso contrário, "ad_user".
@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username_input = request.form['username']
        password = request.form['password']
        error = None
        # Verifica se é admin local
        conn_db = get_db_connection()
        cur = conn_db.execute("SELECT * FROM admins WHERE username = ?", (username_input,))
        admin_local = cur.fetchone()
        conn_db.close()

        if admin_local is None:
            config = get_ldap_config()
            if '@' not in username_input:
                domain = config['ad_user'].split('@')[1]
                username_ad = f"{username_input}@{domain}"
            else:
                username_ad = username_input
        else:
            username_ad = username_input

        try:
            conn_ad = get_ldap_connection(user=username_ad, password=password)
            sam = username_ad.split('@')[0]
            config = get_ldap_config()
            conn_ad.search(
                search_base=config['base_dn'], 
                search_filter=f'(&(objectClass=user)(objectCategory=person)(sAMAccountName={sam}))', 
                attributes=['memberOf']
            )
            if len(conn_ad.entries) == 0:
                error = "Usuário não encontrado no AD."
                raise Exception(error)
            entry = conn_ad.entries[0]
            groups = entry.memberOf.values if 'memberOf' in entry else []
            if any(config['allowed_group'] in g for g in groups):
                role = 'ad_admin'
            else:
                role = 'ad_user'
            session['user'] = username_ad
            session['role'] = role
            return redirect(url_for('index'))
        except Exception as e:
            err_str = str(e)
            if "invalidCredentials" in err_str:
                error = "Credenciais inválidas."
            else:
                error = error or "Credenciais inválidas."
            # Se existir admin_local e a senha local estiver correta, permite login como admin local
            if admin_local and admin_local['password'] and verify_password(password, admin_local['password']):
                session['user'] = username_input
                session['role'] = 'local_admin'
                return redirect(url_for('config'))

        return render_template('login.html', error=error)
    else:
        return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/config', methods=['GET', 'POST'])
@local_admin_required
def config():
    conn_db = get_db_connection()
    cur = conn_db.cursor()
    if request.method == 'POST':
         server_conf = request.form['server']
         ad_user_conf = request.form['ad_user']
         ad_password_conf = request.form['ad_password']
         base_dn_conf = request.form['base_dn']
         allowed_group_conf = request.form['allowed_group']
         cur.execute("UPDATE ldap_config SET server = ?, ad_user = ?, ad_password = ?, base_dn = ?, allowed_group = ? WHERE id = 1",
                     (server_conf, ad_user_conf, ad_password_conf, base_dn_conf, allowed_group_conf))
         conn_db.commit()
         flash("Configuração LDAP atualizada com sucesso!")
    cur.execute("SELECT * FROM ldap_config LIMIT 1")
    config_data = cur.fetchone()
    conn_db.close()
    return render_template('config.html', config=config_data)

@app.route('/config/test_connection', methods=['POST'])
@local_admin_required
def test_connection():
    data = request.get_json()
    if not data:
        return jsonify({'success': False, 'message': 'Nenhum dado enviado.'}), 400
    try:
        server = data.get('server')
        ad_user = data.get('ad_user')
        ad_password = data.get('ad_password')
        base_dn = data.get('base_dn')
        ldap_server = Server(server, get_info=ALL)
        conn = Connection(ldap_server, user=ad_user, password=ad_password, auto_bind=True)
        conn.search(search_base=base_dn, search_filter='(objectClass=*)', attributes=['cn'], size_limit=1)
        conn.unbind()
        return jsonify({'success': True, 'message': 'Conexão bem-sucedida!'})
    except Exception as e:
        return jsonify({'success': False, 'message': f'Erro na conexão: {str(e)}'}), 500

# Página de gerenciamento de usuários (IDs) – somente para usuários com role "ad_admin"
@app.route('/usuarios', methods=['GET'])
@ad_admin_required
def usuarios_page():
    return render_template('usuarios.html')

# API para buscar usuários: retorna apenas os usuários que correspondem ao termo buscado
@app.route('/api/usuarios', methods=['GET'])
@ad_admin_required
def buscar_usuarios():
    q = request.args.get("q", "").strip()
    if not q:
        return jsonify([])  # Sem termo de busca, retorna lista vazia
    try:
        config = get_ldap_config()
        conn = get_ldap_connection()
        # Busca por sAMAccountName ou CN contendo o termo buscado (case-insensitive)
        search_filter = f'(&(objectClass=user)(|(sAMAccountName=*{q}*)(cn=*{q}*)))'
        conn.search(
            search_base=config['base_dn'], 
            search_filter=search_filter, 
            attributes=['cn', 'sAMAccountName', 'userAccountControl']
        )
        usuarios = []
        for entry in conn.entries:
            uac = entry.userAccountControl.value
            blocked = bool(int(uac) & 2) if uac is not None else False
            usuarios.append({
                'cn': entry.cn.value,
                'sAMAccountName': entry.sAMAccountName.value,
                'blocked': blocked
            })
        conn.unbind()
        return jsonify(usuarios)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/usuarios', methods=['POST'])
@ad_admin_required
def criar_usuario():
    try:
        dados = request.json
        cn = dados.get('cn')
        sAMAccountName = dados.get('sAMAccountName')
        if not cn or not sAMAccountName:
            return jsonify({'error': 'Dados insuficientes. Informe cn e sAMAccountName.'}), 400
        
        config = get_ldap_config()
        dn = f'CN={cn},{config["base_dn"]}'
        conn = get_ldap_connection()
        atributos = {
            'objectClass': ['top', 'person', 'organizationalPerson', 'user'],
            'cn': cn,
            'sAMAccountName': sAMAccountName,
        }
        if not conn.add(dn, attributes=atributos):
            conn.unbind()
            return jsonify({'error': 'Erro ao criar usuário', 'details': conn.result}), 500
        conn.unbind()
        return jsonify({'message': 'Usuário criado com sucesso!'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/usuarios/<usuario_cn>', methods=['PUT'])
@ad_admin_required
def atualizar_usuario(usuario_cn):
    try:
        dados = request.json
        config = get_ldap_config()
        dn = f'CN={usuario_cn},{config["base_dn"]}'
        conn = get_ldap_connection()
        new_sAMAccountName = dados.get('sAMAccountName')
        if not new_sAMAccountName:
            return jsonify({'error': 'Nenhum atributo para atualizar'}), 400
        
        if not conn.modify(dn, {'sAMAccountName': [(MODIFY_REPLACE, [new_sAMAccountName])]}):
            conn.unbind()
            return jsonify({'error': 'Erro ao atualizar usuário', 'details': conn.result}), 500
        conn.unbind()
        return jsonify({'message': 'Usuário atualizado com sucesso!'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/usuarios/<usuario_cn>', methods=['DELETE'])
@ad_admin_required
def deletar_usuario(usuario_cn):
    try:
        config = get_ldap_config()
        dn = f'CN={usuario_cn},{config["base_dn"]}'
        conn = get_ldap_connection()
        if not conn.delete(dn):
            conn.unbind()
            return jsonify({'error': 'Erro ao deletar usuário', 'details': conn.result}), 500
        conn.unbind()
        return jsonify({'message': 'Usuário deletado com sucesso!'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Rota para troca de senha: apenas usuários logados podem alterar sua própria senha.
@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    """
    Nova lógica: O usuário não precisa informar a senha atual. 
    O sistema utiliza as credenciais do Domain Admin (armazenadas no banco de configuração LDAP) 
    para alterar a senha do usuário no AD.
    """
    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        username = session['user']
        role = session.get('role')
        
        if new_password != confirm_password:
            return render_template('change_password.html', error="Nova senha e confirmação não conferem.")
        
        # Validação robusta para senhas
        # Para usuários do AD (ad_admin e ad_user), usa-se a validação com pelo menos:
        # 1 letra minúscula, 1 letra maiúscula, 1 dígito, 1 caractere especial e tamanho mínimo de 8
        if role in ['ad_admin', 'ad_user']:
            if not re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,}$', new_password):
                return render_template('change_password.html', 
                                       error="A nova senha deve ter no mínimo 8 caracteres, com letras maiúsculas, minúsculas, números e caracteres especiais.")
        else:
            # Para local_admin, uma regra simples (ajuste conforme necessário)
            if not re.match(r'^(?=.*[A-Za-z])(?=.*\d).{8,}$', new_password):
                return render_template('change_password.html', 
                                       error="A nova senha deve ter mais de 8 caracteres, com letras e números.")
        
        if role == 'local_admin':
            conn = get_db_connection()
            cur = conn.execute("SELECT password FROM admins WHERE username = ?", (username,))
            user_db = cur.fetchone()
            if not user_db or not user_db['password'] or not verify_password(request.form['current_password'], user_db['password']):
                return render_template('change_password.html', error="Senha atual incorreta.")
            new_hash = hash_password(new_password)
            conn.execute("UPDATE admins SET password = ? WHERE username = ?", (new_hash, username))
            conn.commit()
            conn.close()
            flash("Senha alterada com sucesso!")
            return redirect(url_for('index'))
        elif role in ['ad_admin', 'ad_user']:
            # Para alteração de senha no AD, usamos as credenciais do Domain Admin configuradas no banco local.
            config = get_ldap_config()
            domain_admin_user = config['ad_user']
            domain_admin_pass = config['ad_password']
            
            try:
                # Conecta ao AD com as credenciais do Domain Admin
                conn_ad = get_ldap_connection(user=domain_admin_user, password=domain_admin_pass, secure=True)
            except Exception as e:
                logging.error("Erro de conexão ao AD com Domain Admin: %s", e)
                return render_template('change_password.html', error="Falha na conexão ao AD.")
            
            # Busca o DN do usuário a partir do sAMAccountName (parte antes do '@')
            sam = username.split('@')[0]
            conn_ad.search(
                search_base=config['base_dn'],
                search_filter=f'(&(objectClass=user)(objectCategory=person)(sAMAccountName={sam}))',
                attributes=['distinguishedName']
            )
            if not conn_ad.entries:
                conn_ad.unbind()
                return render_template('change_password.html', error="Usuário não encontrado no AD.")
            user_dn = conn_ad.entries[0].distinguishedName.value
            
            # Como Domain Admin, o sistema pode alterar a senha sem exigir o password atual do usuário.
            # Utilizamos o método extend.microsoft.modify_password passando o novo valor em texto puro.
            if not conn_ad.extend.microsoft.modify_password(user_dn, new_password, None):
                error_details = conn_ad.result
                logging.error("Erro ao atualizar a senha no AD para o usuário %s (DN: %s): %s", username, user_dn, error_details)
                conn_ad.unbind()
                return render_template('change_password.html', 
                                       error=f"Falha ao atualizar a senha no AD: {error_details.get('message', 'Erro desconhecido')}")
            conn_ad.unbind()
            flash("Senha do AD alterada com sucesso!")
            return redirect(url_for('index'))
    return render_template('change_password.html')


# Rota para resetar a senha: admin informa a nova senha manualmente.
@app.route('/usuarios/reset_senha/<usuario_cn>', methods=['POST'])
@ad_admin_required
def resetar_senha(usuario_cn):
    try:
        data = request.get_json() or {}
        force_change = data.get('force_change', False)
        config = get_ldap_config()
        # Conexão via LDAPS
        conn = get_ldap_connection(secure=True)
        search_filter = f'(&(|(cn={usuario_cn})(sAMAccountName={usuario_cn}))(objectCategory=person))'
        conn.search(
            search_base=config['base_dn'],
            search_filter=search_filter,
            attributes=['distinguishedName']
        )
        if not conn.entries:
            conn.unbind()
            return jsonify({'error': 'Usuário não encontrado.'}), 404
        user_dn = conn.entries[0].distinguishedName.value
        # Gera a senha aleatória
        new_password = generate_random_password()
        new_pwd_formatted = f'"{new_password}"'.encode('utf-16-le')
        if not conn.modify(user_dn, {'unicodePwd': [(MODIFY_REPLACE, [new_pwd_formatted])]}):
            error_details = conn.result
            print("Erro ao modificar unicodePwd:", error_details)
            conn.unbind()
            return jsonify({'error': 'Falha ao resetar a senha', 'details': error_details}), 500
        # Desbloqueia a conta
        if not conn.modify(user_dn, {'lockoutTime': [(MODIFY_REPLACE, [0])]}):
            error_details = conn.result
            print("Erro ao modificar lockoutTime:", error_details)
            conn.unbind()
            return jsonify({'error': 'Falha ao desbloquear a conta', 'details': error_details}), 500
        # Se for forçar a troca de senha no próximo logon
        if force_change:
            if not conn.modify(user_dn, {'pwdLastSet': [(MODIFY_REPLACE, [0])]}):
                error_details = conn.result
                print("Erro ao forçar troca de senha:", error_details)
                # Opcional: apenas logar o erro sem interromper
        conn.unbind()
        
        # Registro no log:
        # Recupera o usuário que fez o reset (sessão) e seu role
        # Após realizar o reset com sucesso, registre a operação:
        reset_by = session.get('user', 'unknown')
        reset_by_role = session.get('role', 'unknown')
        change_flag = "com troca no próximo logon" if force_change else "sem troca no próximo logon"
        user_logger.info(f"{reset_by} ({reset_by_role}) resetou senha de {usuario_cn} {change_flag}.")

        
        return jsonify({'message': 'Senha resetada com sucesso!', 'new_password': new_password})
    except Exception as e:
        print("Exceção:", str(e))
        return jsonify({'error': str(e)}), 500


# Função para Gerar senha aleatória.
def generate_random_password(length=10):
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()"
    password = ''.join(secrets.choice(alphabet) for _ in range(length))
    # Garante que há ao menos um de cada
    if not any(c.islower() for c in password):
        password += secrets.choice(string.ascii_lowercase)
    if not any(c.isupper() for c in password):
        password += secrets.choice(string.ascii_uppercase)
    if not any(c.isdigit() for c in password):
        password += secrets.choice(string.digits)
    if not any(c in "!@#$%^&*()" for c in password):
        password += secrets.choice("!@#$%^&*()")
    return password


if __name__ == '__main__':
    if not os.path.exists(DATABASE):
        init_db()
    app.run(port=5001, host='0.0.0.0', debug=True)
