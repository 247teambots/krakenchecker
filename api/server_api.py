import http.server
import socketserver
import argparse
from urllib.parse import urlparse, parse_qs
import os
import configparser
import base64
import hmac # Для безопасного сравнения паролей
import json # Для ответа в формате JSON

class RequestHandler(http.server.BaseHTTPRequestHandler):
    # Инициализация с параметрами из конфига и командной строки
    def __init__(self, *args, output_filepath, users_filepath, secret_key, admin_user, admin_pass, **kwargs):
        self.output_filepath = output_filepath
        self.users_filepath = users_filepath
        self.secret_key = secret_key
        self.admin_user = admin_user
        self.admin_pass = admin_pass
        super().__init__(*args, **kwargs)

    # Проверка Basic Authentication
    def _check_auth(self):
        auth_header = self.headers.get('Authorization')
        if auth_header is None or not auth_header.lower().startswith('basic '):
            return False
        try:
            encoded_credentials = auth_header.split(' ')[1]
            decoded_bytes = base64.b64decode(encoded_credentials)
            decoded_string = decoded_bytes.decode('utf-8')
            username, password = decoded_string.split(':', 1)
            is_user_ok = hmac.compare_digest(username.encode('utf-8'), self.admin_user.encode('utf-8'))
            is_pass_ok = hmac.compare_digest(password.encode('utf-8'), self.admin_pass.encode('utf-8'))
            return is_user_ok and is_pass_ok
        except Exception:
            print("[!] Ошибка декодирования или сравнения Basic Auth")
            return False

    # Запрос аутентификации
    def _request_auth(self):
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm="Admin Area"')
        self.send_header('Content-type', 'text/plain; charset=utf-8')
        self.end_headers()
        self.wfile.write("Требуется аутентификация".encode('utf-8'))
        print(f"[-] Запрошена аутентификация для {self.path} от {self.client_address[0]}")

    # Отправка JSON ответа
    def _send_json_response(self, status_code, data):
        self.send_response(status_code)
        self.send_header('Content-type', 'application/json; charset=utf-8')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode('utf-8'))

    # Обработка GET запросов
    def do_GET(self):
        parsed_url = urlparse(self.path)
        path = parsed_url.path
        query_params = parse_qs(parsed_url.query)

        # --- /upload ---
        if path == '/upload':
            key = query_params.get('key', [None])[0]
            login = query_params.get('login', [None])[0]
            password = query_params.get('password', [None])[0]

            safe_key = key.encode('utf-8') if key else b""
            if not hmac.compare_digest(safe_key, self.secret_key.encode('utf-8')):
                self._send_json_response(401, {"success": False, "message": "Ошибка: Неверный API ключ."})
                print(f"[-] Отклонен запрос /upload: неверный ключ от {self.client_address[0]}")
                return

            if not login or not password:
                self._send_json_response(400, {"success": False, "message": "Ошибка: Параметры 'login' и 'password' обязательны."})
                print(f"[-] Отклонен запрос /upload: отсутствуют параметры от {self.client_address[0]}")
                return

            try:
                with open(self.output_filepath, 'a', encoding='utf-8') as f:
                    f.write(f"{login}:{password}\n")
                self._send_json_response(200, {"success": True, "message": "Данные успешно записаны."})
                print(f"[+] Данные '{login}:******' записаны в {self.output_filepath} от {self.client_address[0]}")
            except IOError as e:
                self._send_json_response(500, {"success": False, "message": f"Ошибка сервера: Не удалось записать в файл. {e}"})
                print(f"[!] Ошибка записи в файл {self.output_filepath}: {e}")

        # --- /users ---
        elif path == '/users':
            if not self._check_auth():
                self._request_auth()
                return

            print(f"[+] Успешная аутентификация для /users от {self.client_address[0]}")

            if not os.path.exists(self.users_filepath):
                self.send_response(404)
                self.send_header('Content-type', 'text/html; charset=utf-8') # Отдаем HTML ошибку
                self.end_headers()
                self.wfile.write(f"<html><body><h1>Ошибка 404</h1><p>Файл пользователей '{self.users_filepath}' не найден.</p></body></html>".encode('utf-8'))
                print(f"[!] Файл пользователей {self.users_filepath} не найден для запроса от {self.client_address[0]}")
                return

            try:
                with open(self.users_filepath, 'r', encoding='utf-8') as f:
                    user_lines = f.readlines()

                # --- Генерация HTML с Bootstrap 5.2 и кнопкой Удалить ---
                html_content = f"""
                <!DOCTYPE html>
                <html lang="ru">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>Пользователи (Админка)</title>
                    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-rbsA2VBKQhggwzxH7pPCaAqO46MgnOM80zW1RWuH61DGLwZJEdK2Kadq2F9CUG65" crossorigin="anonymous">
                    <style>
                        td {{ word-wrap: break-word; word-break: break-all; }}
                        .btn-danger {{ --bs-btn-hover-bg: #dc3545; --bs-btn-hover-border-color: #dc3545; }}
                    </style>
                </head>
                <body>
                    <div class="container mt-4">
                        <h1 class="mb-3">Список пользователей</h1>
                        <div class="table-responsive">
                            <table class="table table-striped table-hover table-bordered table-sm" id="usersTable">
                                <thead class="table-light">
                                    <tr>
                                        <th>Username</th>
                                        <th>Password</th>
                                        <th>Address</th>
                                        <th>BTC Format</th>
                                        <th>City</th>
                                        <th>Average</th>
                                        <th>Last Buy</th>
                                        <th>Dispute</th>
                                        <th>Balance</th>
                                        <th>Удалить</th>
                                    </tr>
                                </thead>
                                <tbody>
                """ # Конец заголовка HTML

                for line_num, line in enumerate(user_lines): # Используем enumerate для уникального ID строки
                    line = line.strip()
                    if not line: continue

                    # Инициализация переменных
                    username = "parse error"
                    password = "parse error"
                    btc_address = "parse error"
                    btc_format = "error"
                    city = "parse error"
                    average = "parse error"
                    last_buy = "parse error"
                    dispute = "parse error"
                    balance = "parse error"
                    row_id = f"user-row-{line_num}" # Уникальный ID для строки TR

                    try:
                        parts1 = line.split(':', 1)
                        if len(parts1) < 2:
                            print(f"[!] Строка без ':' пропущена: {line}")
                            continue
                        username = parts1[0].strip()
                        rest_of_line = parts1[1]

                        parts_right = rest_of_line.rsplit(':', 6)
                        if len(parts_right) == 7:
                            password = parts_right[0].strip()
                            btc_address = parts_right[1].strip()
                            city = parts_right[2].strip()
                            average = parts_right[3].strip()
                            last_buy = parts_right[4].strip()
                            dispute = parts_right[5].strip()
                            balance = parts_right[6].strip()

                            if btc_address.startswith('bc1q'): btc_format = "Bech32"
                            elif btc_address.startswith('bc1p'): btc_format = "Bech32m"
                            elif btc_address.startswith('1'): btc_format = "Legacy (P2PKH)"
                            elif btc_address.startswith('3'): btc_format = "Script (P2SH)"
                            elif btc_address == "parse error": btc_format = "error"
                            else: btc_format = "Other/Unknown"
                        else:
                             print(f"[!] Не удалось разобрать строку (rsplit): {line}")
                             username = "parse error"


                    except Exception as e:
                        print(f"[!] Исключение при парсинге строки '{line}': {e}")
                        username = "parse error"

                    # Формируем строку таблицы с кнопкой
                    safe_username = username.replace('"', '&quot;')
                    delete_button_html = ""
                    if username != "parse error":
                        delete_button_html = f'<button class="btn btn-danger btn-sm delete-btn" data-username="{safe_username}" data-rowid="{row_id}">Удалить</button>'

                    html_content += f"""
                        <tr id="{row_id}">
                            <td>{username}</td>
                            <td>{password}</td>
                            <td>{btc_address}</td>
                            <td>{btc_format}</td>
                            <td>{city}</td>
                            <td>{average}</td>
                            <td>{last_buy}</td>
                            <td>{dispute}</td>
                            <td>{balance}</td>
                            <td>{delete_button_html}</td>
                        </tr>
                    """

                # --- Завершение HTML, добавление Модального окна и JS ---
                html_content += """
                                </tbody>
                            </table>
                        </div>
                    </div>

                    <div class="modal fade" id="deleteConfirmModal" tabindex="-1" aria-labelledby="deleteModalLabel" aria-hidden="true">
                      <div class="modal-dialog">
                        <div class="modal-content">
                          <div class="modal-header">
                            <h5 class="modal-title" id="deleteModalLabel">Подтверждение удаления</h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                          </div>
                          <div class="modal-body">
                            Вы уверены, что хотите удалить пользователя <strong id="usernameToDelete"></strong>? Это действие необратимо.
                          </div>
                          <div class="modal-footer">
                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Отмена</button>
                            <button type="button" class="btn btn-danger" id="confirmDeleteBtn">Удалить</button>
                          </div>
                        </div>
                      </div>
                    </div>

                    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/js/bootstrap.bundle.min.js" integrity="sha384-kenU1KFdBIe4zVF0s0G1M5b4hcpxyD9F7jL+jjXkk+Q2h455rYXK/7HAuoJl+0I4" crossorigin="anonymous"></script>

                    <script>
                        const deleteModalElement = document.getElementById('deleteConfirmModal');
                        const deleteModal = new bootstrap.Modal(deleteModalElement);
                        const confirmDeleteBtn = document.getElementById('confirmDeleteBtn');
                        const usernameToDeleteSpan = document.getElementById('usernameToDelete');
                        const usersTableBody = document.querySelector('#usersTable tbody');

                        let userToDelete = null;
                        let rowToDelete = null;

                        usersTableBody.addEventListener('click', function(event) {
                            if (event.target.classList.contains('delete-btn')) {
                                userToDelete = event.target.dataset.username;
                                const rowId = event.target.dataset.rowid;
                                rowToDelete = document.getElementById(rowId);

                                if (userToDelete && rowToDelete) {
                                    usernameToDeleteSpan.textContent = userToDelete;
                                    deleteModal.show();
                                } else {
                                     console.error("Не удалось получить username или rowId для удаления.");
                                     alert("Ошибка: Не удалось получить данные пользователя для удаления.");
                                }
                            }
                        });

                        confirmDeleteBtn.addEventListener('click', function() {
                            if (!userToDelete || !rowToDelete) {
                                console.error("Нет данных для удаления в обработчике подтверждения.");
                                deleteModal.hide();
                                return;
                            }

                            fetch('/delete_user', {
                                method: 'POST',
                                headers: {
                                    'Content-Type': 'application/x-www-form-urlencoded',
                                },
                                body: 'username=' + encodeURIComponent(userToDelete)
                            })
                            .then(response => {
                                if (!response.ok) {
                                    return response.json().then(errData => {
                                        throw new Error(errData.message || `Ошибка сервера: ${response.statusText} (${response.status})`);
                                    }).catch(() => {
                                        throw new Error(`Ошибка сервера: ${response.statusText} (${response.status})`);
                                    });
                                }
                                return response.json();
                            })
                            .then(data => {
                                if (data.success) {
                                    rowToDelete.remove();
                                    console.log(`Пользователь ${userToDelete} удален.`);
                                } else {
                                    alert('Ошибка при удалении: ' + (data.message || 'Неизвестная ошибка.'));
                                }
                            })
                            .catch(error => {
                                console.error('Ошибка fetch:', error);
                                alert('Не удалось выполнить запрос на удаление: ' + error.message);
                            })
                            .finally(() => {
                                deleteModal.hide();
                                userToDelete = null;
                                rowToDelete = null;
                            });
                        });

                        deleteModalElement.addEventListener('hidden.bs.modal', function () {
                            userToDelete = null;
                            rowToDelete = null;
                            usernameToDeleteSpan.textContent = '';
                        });

                    </script>
                </body>
                </html>
                """

                # Отправка ответа
                self.send_response(200)
                self.send_header('Content-type', 'text/html; charset=utf-8')
                self.end_headers()
                self.wfile.write(html_content.encode('utf-8'))
                print(f"[+] Отправлен список пользователей из {self.users_filepath} для {self.client_address[0]}")

            except IOError as e:
                self._send_json_response(500, {"success": False, "message": f"Ошибка сервера: Не удалось прочитать файл пользователей. {e}"})
                print(f"[!] Ошибка чтения файла {self.users_filepath}: {e}")

        # --- Другие пути ---
        else:
            self.send_response(404)
            self.send_header('Content-type', 'text/plain; charset=utf-8')
            self.end_headers()
            self.wfile.write("Ошибка 404: Ресурс не найден.".encode('utf-8'))
            print(f"[-] Запрос на несуществующий путь '{path}' от {self.client_address[0]}")

    # --- Обработка POST запросов (для удаления) ---
    def do_POST(self):
        parsed_url = urlparse(self.path)
        path = parsed_url.path

        if path == '/delete_user':
            # 1. Проверка аутентификации
            if not self._check_auth():
                self._send_json_response(401, {"success": False, "message": "Требуется аутентификация"})
                return

            # 2. Чтение тела POST запроса
            username_to_delete = None
            try:
                content_length = int(self.headers.get('Content-Length', 0))
                if content_length == 0:
                    raise ValueError("Пустое тело запроса")

                post_body_bytes = self.rfile.read(content_length)
                post_body_str = post_body_bytes.decode('utf-8')
                parsed_data = parse_qs(post_body_str)
                username_list = parsed_data.get('username', [])
                if not username_list:
                    raise ValueError("Параметр 'username' не найден в теле запроса")
                username_to_delete = username_list[0]
                if not username_to_delete:
                     raise ValueError("Значение 'username' пустое")

            except Exception as e:
                print(f"[!] Ошибка парсинга POST запроса на /delete_user: {e}")
                self._send_json_response(400, {"success": False, "message": f"Ошибка разбора запроса: {e}"})
                return

            # 3. Чтение, фильтрация и перезапись файла users.txt
            print(f"[*] Попытка удаления пользователя '{username_to_delete}'...")
            try:
                lock_file_path = self.users_filepath + ".lock"
                if os.path.exists(lock_file_path):
                     print("[!] Файл заблокирован, повторите попытку позже.")
                     self._send_json_response(503, {"success": False, "message": "Операция уже выполняется, попробуйте позже."})
                     return
                try:
                    open(lock_file_path, 'w').close()

                    if not os.path.exists(self.users_filepath):
                         raise FileNotFoundError("Файл пользователей не найден при попытке удаления.")

                    with open(self.users_filepath, 'r', encoding='utf-8') as f:
                        lines = f.readlines()

                    initial_line_count = len(lines)
                    lines_to_keep = [line for line in lines if not line.strip().startswith(username_to_delete + ':')]
                    lines_deleted_count = initial_line_count - len(lines_to_keep)

                    if lines_deleted_count == 0:
                        print(f"[!] Пользователь '{username_to_delete}' не найден в файле.")
                        self._send_json_response(404, {"success": False, "message": f"Пользователь '{username_to_delete}' не найден."})
                        return

                    with open(self.users_filepath, 'w', encoding='utf-8') as f:
                        f.writelines(lines_to_keep)

                    print(f"[+] Пользователь '{username_to_delete}' успешно удален. Удалено строк: {lines_deleted_count}.")
                    self._send_json_response(200, {"success": True})

                finally:
                    if os.path.exists(lock_file_path):
                        os.remove(lock_file_path)

            except FileNotFoundError as e:
                 print(f"[!] Ошибка: {e}")
                 self._send_json_response(404, {"success": False, "message": str(e)})
            except IOError as e:
                print(f"[!] Ошибка ввода/вывода при удалении пользователя '{username_to_delete}': {e}")
                self._send_json_response(500, {"success": False, "message": f"Ошибка сервера при доступе к файлу: {e}"})
            except Exception as e:
                print(f"[!] Непредвиденная ошибка при удалении пользователя '{username_to_delete}': {e}")
                self._send_json_response(500, {"success": False, "message": f"Внутренняя ошибка сервера: {e}"})

        else:
            self.send_response(405)
            self.send_header('Allow', 'GET')
            self.end_headers()

# Функция запуска сервера
def run_server(host, port, output_filepath, users_filepath, secret_key, admin_user, admin_pass):
    if not os.path.exists(output_filepath):
       try:
           open(output_filepath, 'a').close()
           print(f"[*] Файл {output_filepath} не найден, создан пустой файл.")
       except IOError as e:
           print(f"[!] КРИТИЧЕСКАЯ ОШИБКА: Не удалось создать файл {output_filepath}: {e}")
           return
    if not os.path.exists(users_filepath):
       print(f"[!] ВНИМАНИЕ: Файл пользователей {users_filepath} не найден.")

    handler_factory = lambda *args, **kwargs: RequestHandler(
        *args, output_filepath=output_filepath, users_filepath=users_filepath,
        secret_key=secret_key, admin_user=admin_user, admin_pass=admin_pass, **kwargs
    )

    with socketserver.ThreadingTCPServer((host, port), handler_factory) as httpd:
        print(f"Сервер запущен на http://{host}:{port}")
        print(f" - Конфигурация: config.ini")
        print(f" - Логирование (/upload): {output_filepath}")
        print(f" - Данные пользователей (/users): {users_filepath} (требуется логин/пароль)")
        print(f"   -> Пользователь админки: {admin_user}")
        print("Нажмите Ctrl+C для остановки сервера.")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[!] Сервер останавливается...")
            httpd.shutdown()
            print("[*] Сервер остановлен.")


# Основной блок выполнения
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='HTTP сервер с логированием и админкой пользователей из config.ini.')
    parser.add_argument('output_file', help='Путь к файлу для записи данных (username:password)')
    parser.add_argument('users_file', help='Путь к файлу с данными пользователей для парсинга')
    parser.add_argument('--config', default='config.ini', help='Путь к файлу конфигурации (по умолчанию: config.ini)')
    parser.add_argument('--port', type=int, default=8000, help='Порт сервера (по умолчанию: 8000)')
    parser.add_argument('--host', default='0.0.0.0', help='Хост сервера (по умолчанию: 0.0.0.0)')
    args = parser.parse_args()

    config_path = os.path.abspath(args.config)
    if not os.path.exists(config_path):
        print(f"[!] КРИТИЧЕСКАЯ ОШИБКА: Файл конфигурации '{config_path}' не найден.")
        exit(1)

    config = configparser.ConfigParser()
    SECRET_KEY = None
    ADMIN_USER = None
    ADMIN_PASS = None
    try:
        config.read(config_path, encoding='utf-8')
        SECRET_KEY = config.get('API', 'secret_key', fallback=None)
        ADMIN_USER = config.get('Admin', 'username', fallback=None)
        ADMIN_PASS = config.get('Admin', 'password', fallback=None)
        if not SECRET_KEY or not ADMIN_USER or not ADMIN_PASS:
            raise ValueError("Не все параметры найдены в config.ini ([API]secret_key, [Admin]username, [Admin]password)")
    except Exception as e:
        print(f"[!] КРИТИЧЕСКАЯ ОШИБКА: Не удалось прочитать файл конфигурации '{config_path}': {e}")
        exit(1)

    output_abs_path = os.path.abspath(args.output_file)
    users_abs_path = os.path.abspath(args.users_file)

    run_server(args.host, args.port, output_abs_path, users_abs_path, SECRET_KEY, ADMIN_USER, ADMIN_PASS)
