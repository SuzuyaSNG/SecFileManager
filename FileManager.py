import sqlite3
import hashlib
import os
import sys
import shutil
import random
from concurrent.futures.thread import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from time import sleep
from urllib.parse import uses_relative
import psutil
import json
from jsonschema import validate, ValidationError
from defusedxml.ElementTree import parse, fromstring, tostring
import xml.etree.ElementTree as ET
import zipfile
import threading
import subprocess
from traceback import print_exc

# Получение пути с базой данных ( для Pyinstaller ) 
def get_database_path():
    if getattr(sys, 'frozen', False):
        base_path = Path(sys.executable).parent
    else:
        base_path = Path(__file__).parent

    db_path = base_path / "file_manager.db"
    print(f"Путь к базе данных: {db_path}")
    return str(db_path)
"""Создание БД """
class DatabaseManager:
    def __init__(self, db_path=None):
        if db_path is None:
            self.db_path = get_database_path()
        else:
            self.db_path = db_path
        self.init_db()
    def get_connection(self):
        return sqlite3.connect(self.db_path)
    def init_db(self):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS Users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL
                )
            ''')

            cursor.execute(''' 
                CREATE TABLE IF NOT EXISTS Files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                size INTEGER,
                location TEXT NOT NULL,
                owner_id INTEGER,
                FOREIGN KEY (owner_id) REFERENCES Users (id) 
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS Operations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                operation_type TEXT CHECK(operation_type IN ('create', 'update', 'delete', 'read',
                'move', 'copy', 'dir', 'cd', 'parse_json', 'parse_xml', 'json_dump', 'dump_xml',
                'zip_create', 'unzip', 'icacls_deny_R', 'icacls_deny_D', 'icacls_deny_W')) NOT NULL,
                file_id INTEGER,
                user_id INTEGER,
                FOREIGN KEY (file_id) REFERENCES Files (id),
                FOREIGN KEY (user_id) REFERENCES Users (id)
                )    
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS FilePerm (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_path TEXT NOT NULL,
                username TEXT NOT NULL,
                read_perm BOOLEAN DEFAULT 1,
                write_perm BOOLEAN DEFAULT 1,
                delete_perm BOOLEAN DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(file_path, username)
                )
            ''')

            conn.commit()

    """Создание пользователей и выдача ролей ( прав ) 
    дефолтный юзер и админ, а также аутентификация"""
    def create_user(self, username, password):
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        if len(password) < 1:
            print("Пароль не должен быть пустым")
            return False
        if username != "admin":
            role = "user"
            try:
                with self.get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute("INSERT INTO Users (username, password_hash, role) VALUES (?, ?, ?)",
                                   (username, password_hash, role))
                    conn.commit()
                    print("Пользователь создан")
                    return True
            except sqlite3.IntegrityError:
                print("Пользователь уже существует")
                return False
        else:
            role = "root"
            try:
                with self.get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute("INSERT INTO Users (username, password_hash, role) VALUES (?, ?, ?)",
                                   (username, password_hash, role))
                    conn.commit()
                    print("Пользователь admin создан")
                    return True
            except sqlite3.IntegrityError:
                print("admin уже существует")
                return False
    def verify_user(self, username, password):
        password_hash = hashlib.sha256(password.encode()).hexdigest()

        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT password_hash FROM Users WHERE username = ?",
                           (username,))
            res = cursor.fetchone()
            if res is not None:
                if res[0] == password_hash:
                    return True
            return False

    def rm_user(self, username):
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM Users WHERE username = ?", (username,))
                conn.commit()
                print(f"Пользователь {username} удален из БД")
                return True
        except Exception as e:
            print(f"Ошибка 1 {e}")
            return False
    """Выдача прав в БД"""
    def set_perm(self, file_path, username, read_perm, write_perm, delete_perm):
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT read_perm, write_perm, delete_perm FROM FilePerm WHERE file_path = ? AND username = ?
                ''', (file_path, username))
                res = cursor.fetchone()
                if res:
                    read_new = read_perm if read_perm is not None else bool(res[0])
                    write_new = write_perm if write_perm is not None else bool(res[1])
                    delete_new = delete_perm if delete_perm is not None else bool(res[2])
                else:
                    read_new = read_perm if read_perm is not None else True
                    write_new = write_perm if write_perm is not None else True
                    delete_new = delete_perm if delete_perm is not None else True
                cursor.execute('''
                    INSERT OR REPLACE INTO FilePerm (file_path, username, read_perm, write_perm, delete_perm)
                        VALUES (?, ?, ?, ?, ?)
                ''', (file_path, username, read_new, write_new, delete_new))
                conn.commit()
        except Exception as e:
            print(f"Ошибка 2 {e}")
            #print_exc()
            return False
    def get_perm(self, username, file_path):
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                            SELECT read_perm, write_perm, delete_perm FROM FilePerm
                            WHERE file_path = ? AND username = ?
                        ''', (file_path, username))
                result = cursor.fetchone()
                if result is None:
                    return True, True, True
                read = bool(result[0])
                write = bool(result[1])
                delete = bool(result[2])
                return read, write, delete
        except Exception as e:
            print(f"Ошибка 3 в get_perm: {e}")
            return True, True, True
    def log_operation(self, operation_type, file_path, username):
        file_path = Path(file_path)

        with self.get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute("SELECT id FROM Users WHERE username = ?", (username,))
            user_result = cursor.fetchone()
            if not user_result:
                return False
            user_id = user_result[0]

            cursor.execute("SELECT id FROM Files WHERE filename = ? AND location = ?",
                           (file_path.name, str(file_path.parent)))
            file_result = cursor.fetchone()

            if file_result:
                file_id = file_result[0]
            else:
                file_size = file_path.stat().st_size if file_path.exists() else 0
                cursor.execute("INSERT INTO Files (filename, size, location, owner_id) VALUES (?, ?, ?, ?)",
                               (file_path.name, file_size, str(file_path.parent), user_id))
                file_id = cursor.lastrowid

                cursor.execute("INSERT INTO Operations (operation_type, file_id, user_id) VALUES (?, ?, ?)",
                               (operation_type, file_id, user_id))
                conn.commit()
                return True

    def get_user_operations(self, username, limit: int = 10):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(''' SELECT Operations.timestamp,
            Operations.operation_type, Files.filename, Files.location
            FROM Operations JOIN Users ON Operations.user_id = Users.id
            JOIN Files ON Operations.file_id = Files.id
            WHERE Users.username = ? ORDER BY Operations.timestamp DESC
            LIMIT ?
            ''', (username, limit))
            result = cursor.fetchall()
            return result
    def getusers(self):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM Users")
            res = cursor.fetchall()
            return res
# Защита от уязвимости Path traversal
def path_traversal(user_input):
    base = Path("C:/Users").resolve()
    user_path = Path(user_input)

    #if ".." in user_path.parts:
    #    raise ValueError("Недопустимый путь")
    full_path = (base / user_path).resolve()
    if not full_path.is_relative_to(base):
        raise ValueError("Доступ запрещен")

    return True

schema = {
    "properties": {
        "name": {"type": "string", "maxLength": 100, "pattern": "^[A-Za-zА-Яа-я\\s]+$"},
        "age": {"type": "integer", "minimum": 0, "maximum": 100},
        "email": {"type": "string", "format": "email"},
        "roles": {"type": "array", "items": {"type": "string", "enum": ["user", "admin"]}}
    },
    "required": ["name"],
    "additionalProperties": False
}
# Санитизация 
def validate_json(json_string, schema):
    max_size = 1024*1024
    try:
        if len(json_string) > max_size:
            return False
        validate(instance=json_string, schema=schema)
        return json_string
    except ValidationError as e:
        print(f"Ошибка 4 валидации файла: {e}")
        return False
def validate_xml(xml_file):
    try:
        tree = parse(xml_file)
        return tree
    except Exception as e:
        print(f"Ошибка валидации xml файла: {e}")
        return False

def zip_bomb(file_zip, end_pathzip):
    max_size = 100 * 1024 * 1024

    with zipfile.ZipFile(file_zip, 'r') as zf:
        total_size = sum(f.file_size for f in zf.filelist)
        if total_size > max_size:
            raise ValueError("Слишком большой архив")

        return zf.extractall(end_pathzip)

lock = threading.Lock()
def safe_processes(state):
    if state == "start":
        return lock.acquire()
    elif state == "end":
        return lock.release()
# Основной класс с функциями файлового менеджера 
class FileManager:
    def __init__(self):
        self.db = DatabaseManager()
        self.current_user = None
    def login(self, username, password):
        if self.db.verify_user(username, password):
            self.current_user = username
            print("Успешный вход")
            return True
        print("Неправильное имя пользователя или пароль")
        return False
    def create_file(self, file_path):
        if not self.current_user:
            return False
        try:
            if not path_traversal(file_path):
                return path_traversal(file_path)
            Path(file_path).parent.mkdir(parents=True, exist_ok=True)
            content = input()
            safe_processes("start")
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            safe_processes("end")
            self.db.log_operation("create", file_path, self.current_user)
            print(f"Создан файл: {file_path}")
            return True
        except Exception as e:
            print(f"Ошибка при создании файла: {e}")
            return False
    def mkdir(self, dir_path):
        if not self.current_user:
            return False
        try:
            if not path_traversal(dir_path):
                return path_traversal(dir_path)
            Path(dir_path).mkdir(parents=True, exist_ok=True)
            print(f"Директория создана {dir_path}")
            return True
        except Exception as e:
            print(f"Ошибка при создании файла: {e}")
            return False
    def delete_file(self, file_path):
        if ".db" in file_path:
            print("Вы не можете удалить этот файл")
            return False
        if not self.current_user:
            return False
        read, write, delete = self.db.get_perm(self.current_user, file_path)
        if delete is False:
            return False, "У вас нет прав для удаления этого файла"
        try:
            if not path_traversal(file_path):
                return path_traversal(file_path)
            if os.path.exists(file_path):
                if os.path.isfile(file_path):
                    os.remove(file_path)
                    self.db.log_operation("delete", file_path, self.current_user)
                    print(f"Удален файл: {file_path}")
                    return True
                else:
                    print(f"{file_path} не является файлом")
                    return False
            else:
                print(f"{file_path} не существует")
                return False
        except Exception as e:
            print(f"Ошибка при удалении файла: {e}")
            return False

    def update_file(self, file_path):
        if not self.current_user:
            return False
        read, write, delete = self.db.get_perm(self.current_user, file_path)
        if write is False:
            return False, "У вас нет прав изменять этот файл"
        try:
            if not path_traversal(file_path):
                return path_traversal(file_path)
            if os.path.exists(file_path):
                content = input()
                safe_processes("start")
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                safe_processes("end")
                self.db.log_operation("update", file_path, self.current_user)
                print(f"Обновлен файл: {file_path}")
                return True
            else:
                print("Файла не существует")
                return False
        except Exception as e:
            print(f"Ошибка при обновлении файла: {e}")
            return False
    def read_file(self, file_path):
        if not self.current_user:
            return False
        read, write, delete = self.db.get_perm(self.current_user, file_path)
        if read is False:
            return False, "У вас нет прав читать этот файл"
        try:
            if not path_traversal(file_path):
                return path_traversal(file_path)
            if os.path.exists(file_path):
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                self.db.log_operation("read", file_path, self.current_user)
                print(content)
                return True
            else:
                print(f"Файл {file_path} не существует")
                return False
        except Exception as e:
            print(f"Ошибка чтения файла: {e}")
            return False

    def directory(self, file_path, command=''):
        if not self.current_user:
            return False
        try:
            if not path_traversal(file_path):
                return path_traversal(file_path)
            if command == "dir":
                current_dir = Path.cwd()
                path = Path(file_path)
                self.db.log_operation("dir", file_path, self.current_user)
                print(path.absolute())
                items = list(path.iterdir())
                dirs = [item for item in items if item.is_dir()]
                files = [item for item in items if item.is_file()]

                for directory in sorted(dirs):
                    print(f" {directory.name}/")

                for file in sorted(files):
                    size = file.stat().st_size
                    print(f" {file.name}")
                return True
            elif command == "cd":
                if file_path == "..":
                    new_path = current_dir.parent
                else:
                    new_path = Path(file_path)
                subprocess.run(f'cd /d "{new_path}"', shell=True, check=True)
                self.db.log_operation("cd", file_path, self.current_user)
                return new_path
            elif command == "pwd":
                current_dir = Path.cwd(file_path)
                print(current_dir)
                return True
            else:
                print("Недопустимая команда")
                return False
        except Exception as e:
            print(f"Ошибка 6 {e}")
            return False
    def copy(self, file_path, end_pathfile):
        if not self.current_user:
            return False
        try:
            if not path_traversal(file_path):
                return path_traversal(file_path)

            self.db.log_operation("copy", file_path, self.current_user)
            print(f"Файл {file_path} скопирован в {end_pathfile}")
            return shutil.copy(file_path, end_pathfile)
        except Exception as e:
            print("Ошибка 7")
            return False
    def move(self, file_path, end_pathfile):
        if not self.current_user:
            return False
        try:
            if not path_traversal(file_path):
                return path_traversal(file_path)
            if not path_traversal(end_pathfile):
                return path_traversal(end_pathfile)
            self.db.log_operation("move", file_path, self.current_user)
            print(f"Файл {file_path} перемещен в {end_pathfile}")
            return shutil.move(file_path, end_pathfile)
        except Exception as e:
            print("Ошибка 8")
            return False
    def parts_disk(self):
        if not self.current_user:
            return False
        partitions = psutil.disk_partitions()
        for part in partitions:
            print(part.device, part.mountpoint)
        usage = psutil.disk_usage("C:/")
        usage2 = psutil.disk_usage("D:/")
        total = usage.total / 1073741824
        free = usage.free / 1073741824
        total2 = usage2.total / 1073741824
        free2 = usage2.free / 1073741824
        print("Disk C \n" f"Total: {round(total, 1)} Gb, Free: {round(free, 1)} Gb, Used: {usage.percent}%")
        print("Disk D \n" f"Total: {round(total2, 1)} Gb, Free: {round(free2, 1)} Gb, Used: {usage2.percent}%")
        return True

    def json_parse(self, file_path):
        if not self.current_user:
            return False
        try:
            if not validate_json(file_path, schema):
                return validate_json(file_path, schema)
            if not path_traversal(file_path):
                return path_traversal(file_path)

            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            print(json.dumps(data, ensure_ascii=False, indent=2))
            return True
        except Exception as e:
            print(f"Ошибка 9: {e}")
            return False

    def xml_parse(self, file_path):
        if not self.current_user:
            return False
        try:
            if not validate_xml(file_path):
                return validate_xml(file_path)
            if not path_traversal(file_path):
                return path_traversal(file_path)
            root = ET.fromstring(file_path)

            self.db.log_operation("parse_xml", file_path, self.current_user)
            return root.text
        except Exception as e:
            print(f"Ошибка 10: {e}")
            return False

    def json_dump(self, file_path, data):
        if not self.current_user:
            return False
        try:
            if not path_traversal(file_path):
                return path_traversal(file_path)
            if os.path.exists(file_path):
                safe_processes("start")
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(data, f, ensure_ascii=False, indent=2, default=str)
                    safe_processes("end")
                    print(f"Данные записаны в {file_path}")
                    self.db.log_operation("json_dump", file_path, self.current_user)
                    return True
            else:
                Path(file_path).parent.mkdir(parents=True, exist_ok=True)
                safe_processes("start")
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(data, f, ensure_ascii=False, indent=2, default=str)
                    safe_processes("end")
                    print(f"Данные записаны в  {file_path}")
                    self.db.log_operation("json_dump", file_path, self.current_user)
                    return True
        except Exception as e:
            print(f"Ошибка 11: {e}")
            return False

    def zip_create(self, file_path, out_path):
        if not self.current_user:
            return False
        try:
            if not os.path.exists(file_path):
                raise FileNotFoundError(f"Директория не существует: {file_path}")
            if not path_traversal(file_path):
                return path_traversal(file_path)
            if not path_traversal(out_path):
                return path_traversal(out_path)
            file_path = Path(file_path)
            out_path = Path(out_path)

            with zipfile.ZipFile(out_path, 'w', zipfile.ZIP_DEFLATED) as zf:
                for root, dirs, files in os.walk(file_path):
                    for file in files:
                        file_abs = Path(root) / file
                        arcname = file_abs.relative_to(file_path.parent)
                        zf.write(file_abs, arcname)

                print(f"Директория {file_path} заархивирована в {out_path}")
                self.db.log_operation("zip_create", file_path, self.current_user)
                return True
        except Exception as e:
            print(f"Ошибка 12 {e}")
            return False
    def zip_unpack(self, file_path, end_path):
        if not self.current_user:
            return False
        try:
            if not path_traversal(file_path):
                return path_traversal(file_path)
            if not path_traversal(end_path):
                return path_traversal(end_path)
            self.db.log_operation("unzip", file_path, self.current_user)
            print(f"Архив распакован в {end_path}")
            return zip_bomb(file_path, end_path)
        except Exception as e:
            print(f"Ошибка 13: {e}")
            return False
    def admin_op(self, file_path, username, command):
        if self.current_user == "admin":
            try:
                if command == "chmodR":
                    self.db.set_perm(file_path, username, False, True, True)
                    self.db.log_operation("icacls_deny_R", file_path, self.current_user)
                    print(f"Успешно")
                elif command == "chmodW":
                    self.db.set_perm(file_path, username, True, False, True)
                    self.db.log_operation("icacls_deny_W", file_path, self.current_user)
                    print(f"Успешно")
                elif command == "chmodD":
                    self.db.set_perm(file_path, username, True, True, False)
                    self.db.log_operation("icacls_deny_D", file_path, self.current_user)
                    print(f"Успешно")
                elif command == "chmodW+":
                    self.db.set_perm(file_path, username, None, True, None)
                    self.db.log_operation("icacls_deny_W", file_path, self.current_user)
                    print(f"Успешно")
                elif command == "chmodD+":
                    self.db.set_perm(file_path, username, None, None, True)
                    self.db.log_operation("icacls_deny_W", file_path, self.current_user)
                    print(f"Успешно")
                elif command == "chmodR+":
                    self.db.set_perm(file_path, username, True, None, None)
                    self.db.log_operation("icacls_deny_W", file_path, self.current_user)
                    print(f"Успешно")
            except Exception as e:
                print(f"Ошибка 14 {e}")
                return False
        else:
            return False, "Вы не являетесь админом"
# Интерактивное взаимодействие с пользователем 
def start_menu():
    subprocess.run(f'cd /d "C:/Users"', shell=True, check=True)
    print("\n\nДопустимые команды")
    print("cd \t смена директории")
    print("dir \t содержимое директории")
    print("pwd \t путь до текущей директории")
    print("create \t создать файл")
    print("update \t обновить файл")
    print("delete \t удалить файл")
    print("read \t прочитать файл")
    print("move \t переместить файл")
    print("zip_create \t создать архив")
    print("unpack \t распаковать архив")
    print("copy \t скорпировать файл")
    print("disk \t показать информацию о диске")
    print("jsonread \t прочитать json файл")
    print("jsoncreate \t создать json файл")
    print("mkdir \t создать директорию")
    print("log \t посмотреть историю")
    print("logout \t сменить пользователя")
    print("\n Текущая директория C:/Users")
    sleep(2)
def authorize():
    db = DatabaseManager()
    fm = FileManager()
    print("Авторизуйтесь или зарегистрируйтесь")
    while True:
        user_input = input("Для авторизации введите: вход \n Для регистрации введите: рег: ")
        if user_input.lower() == "вход":
            nameent = input("Введите имя пользователя: ")
            passwdent = input("Введите пароль: ")
            if db.verify_user(nameent, passwdent):
                print("Вы успешно авторизовались")
                return nameent, passwdent
        elif user_input.lower() == "рег":
            name = input("Введите имя пользователя: ")
            passwd = input("Введите пароль: ")
            if db.create_user(name, passwd):
                return name, passwd
        else:
            print("Недопустимая команда")

def admin():
    print("\n\t Возможные действия с правами admin")
    print("history username - посмотреть операции пользователя username")
    print("rm username - удалить пользователя username")
    print("chmodR filepath username - запретить чтение файла")
    print("chmodW filepath username - запретить изменение файла")
    print("chmodD filepath username - запретить удаление файла")
    print("chmodR+ filepath username - разрешить чтение файла")
    print("chmodW+ filepath username - разрешить изменение файла")
    print("chmodD+ filepath username - разрешить удаление файла")
    print("getuser - получить список пользователей")
    sleep(2)

def main():
    fm = FileManager()
    db = DatabaseManager()
    auth_res = authorize()
    if auth_res:
        username, password = auth_res
        if username == "admin":
            adminka = True
            admin()
        fm.login(username, password)
        start_menu()
        current_dir = Path("C:/Users")
        run = True
        while run:
            try:
                user_input = input()
                cmd = user_input.split()
                if cmd[0] == "logout":
                    run = False
                    auth_res = ""
                    return main()
                elif cmd[0] == "cd":
                    if cmd[1] == "..":
                        new_path = current_dir.parent
                        current_dir = new_path
                        print(current_dir)
                    else:
                        new_path = current_dir / cmd[1]
                        res = fm.directory(str(new_path), cmd[0])
                        current_dir = new_path
                        print(res)
                elif cmd[0] == "dir":
                    res = fm.directory(current_dir, cmd[0])
                    print(res)
                elif cmd[0] == "pwd":
                    print(current_dir)
                elif cmd[0] == "create":
                    new_path = current_dir / cmd[1]
                    res = fm.create_file(str(new_path))
                    print(res)
                elif cmd[0] == "update":
                    new_path = current_dir / cmd[1]
                    res = fm.update_file(str(new_path))
                    print(res)
                elif cmd[0] == "delete":
                    new_path = current_dir / cmd[1]
                    res = fm.delete_file(str(new_path))
                    print(res)
                elif cmd[0] == "read":
                    new_path = current_dir / cmd[1]
                    res = fm.read_file(str(new_path))
                    print(res)
                elif cmd[0] == "move":
                    new_path = current_dir / cmd[1]
                    res = fm.move(str(new_path), cmd[2])
                    print(res)
                elif cmd[0] == "copy":
                    new_path = current_dir / cmd[1]
                    res = fm.copy(str(new_path), cmd[2])
                    print(res)
                elif cmd[0] == "zip_create":
                    res = fm.zip_create(cmd[1], cmd[2])
                    print(res)
                elif cmd[0] == "unpack":
                    res = fm.zip_unpack(cmd[1], cmd[2])
                    print(res)
                elif cmd[0] == "jsonread":
                    res = fm.json_parse(cmd[1])
                    print(res)
                elif cmd[0] == "jsoncreate":
                    res = fm.json_dump(cmd[1], cmd[2])
                    print(res)
                elif cmd[0] == "disk":
                    res = fm.parts_disk()
                    print(res)
                elif cmd[0] == "log":
                    res = db.get_user_operations(username)
                    print(res)
                elif cmd[0] == "mkdir":
                    new_path = current_dir / cmd[1]
                    res = fm.mkdir(str(new_path))
                    print(res)
                elif adminka:
                    if cmd[0] == "history":
                        res = db.get_user_operations(cmd[1])
                        print(res)
                    elif cmd[0] == "rm":
                        res = db.rm_user(cmd[1])
                        print(res)
                    elif cmd[0] == "chmodW":
                        new_path = current_dir / cmd[1]
                        res = fm.admin_op(str(new_path), cmd[2], cmd[0])
                        print(res)
                    elif cmd[0] == "chmodR":
                        new_path = current_dir / cmd[1]
                        res = fm.admin_op(str(new_path), cmd[2], cmd[0])
                        print(res)
                    elif cmd[0] == "chmodD":
                        new_path = current_dir / cmd[1]
                        res = fm.admin_op(str(new_path), cmd[2], cmd[0])
                        print(res)
                    elif cmd[0] == "chmodW+":
                        new_path = current_dir / cmd[1]
                        res = fm.admin_op(str(new_path), cmd[2], cmd[0])
                        print(res)
                    elif cmd[0] == "chmodR+":
                        new_path = current_dir / cmd[1]
                        res = fm.admin_op(str(new_path), cmd[2], cmd[0])
                        print(res)
                    elif cmd[0] == "chmodD+":
                        new_path = current_dir / cmd[1]
                        res = fm.admin_op(str(new_path), cmd[2], cmd[0])
                        print(res)
                    elif cmd[0] == "getuser":
                        res = db.getusers()
                        print(res)
                else:
                    print("Неверно введена команда")
            except Exception as e:
                print(f"Ошибка 20 {e}")
                return main()

if __name__ == "__main__":
    main()
    input()




