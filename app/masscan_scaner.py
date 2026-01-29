"""
Docstring для app.masscan_scaner
Основной модуль для сканирования портов с использованием masscan.
В нем реализовано классами:
1. Logging - для настройки логирования. +
2. Config - для загрузки и управления конфигурацией сканирования. +
3. TelegramNotifier - для отправки уведомлений через Telegram.
4. BannerGrabber - для захвата баннеров с открытых портов. +
5. MasscanScanner - для выполнения сканирования с помощью masscan и обработки результатов. +
6. ScanHistory - для ведения истории сканирований. +
7. PortScannerOrchestrator - для координации всех компонентов и управления процессом сканирования. +
8. main - точка входа для запуска сканирования. +
"""

# Imports
import json
from typing import List, Dict, Any
import logging
import sys
from telegram import Bot
import asyncio
from datetime import datetime
import nmap
import subprocess
from pathlib import Path
import os
from dotenv import load_dotenv



# === 1. Logging Setup === 
def setup_logging():
    """Настройка логирования для приложения в файл и консоль."""
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler("scan.log", encoding='utf-8'),
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    # Подавляем INFO-логи от httpx (используется python-telegram-bot)
    logging.getLogger("httpx").setLevel(logging.WARNING)


# === 2. Config Class === 
class Config:
    """
    Класс для загрузки и управления конфигурацией сканирования.
    Загрузка конфига при помощи _load_config и базовая валидация в _validate.
    Предоставляет свойства для доступа к параметрам конфигурации.
    """

    def __init__(self, config_file: str = "config.json"):
        self.config_file = config_file
        self.data = self._load_config()
        self._validate()
        
    def _load_config(self) -> dict:
        """Загружает конфигурацию из JSON файла."""
        try:
            with open(self.config_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except FileNotFoundError:
            logging.error(f"Конфиг файл: {self.config_file} - не найден.")
            sys.exit(1)
        except json.JSONDecodeError as e:
            logging.error(f"Ошибка парсинга JSON в конфиг файле: {e}")
            sys.exit(1)
            
    def _validate(self):
        """Базовая валидация конфигурации."""
        required_keys = ["scan_target", "masscan_config", "telegram", "schedule"]
        for key in required_keys:
            if key not in self.data:
                raise ValueError(f"Отсутствует обязательный ключ в конфиге: {key}")
            
        if not self.data["scan_target"]:
            raise ValueError("Список scan_targets не может быть пустым.")
        
        if not isinstance(self.data["scan_target"], list):
            raise ValueError("scan_target должен быть списком.")
    
    @property
    def scan_targets(self) -> List[Dict[str, Any]]:
        return self.data["scan_target"]
    
    @property
    def scan_target_name(self) -> str:
        return self.data["scan_target"].get("name", "Unknown")
    
    @property
    def scan_ports(self) -> str:
        return self.data["scan_target"]["ports"]
    
    @property
    def masscan_rate(self) -> int:
        return self.data["masscan_config"].get("rate", 1000)
    
    @property
    def masscan_timeout(self) -> int:
        return self.data["masscan_config"].get("timeout", 30)
        
    @property
    def telegram_token(self) -> str:
        return self.data["telegram"].get("bot_token", "")
    
    @property
    def telegram_chat_id(self) -> str:
        return self.data["telegram"].get("chat_id", "")
    
    @property
    def schedule_enabled(self) -> bool:
        return self.data["schedule"].get("enabled", False)
    
    @property
    def schedule_interval_hours(self) -> int:
        return self.data["schedule"].get("interval_hours", 24)


# === 3. Telegram Notifier Class ===
class TelegramNotifier:
    """Отправка уведомлений через Telegram в бота."""
    
    def __init__(self):
        self._bot = None
        load_dotenv()
        self._bot_token = os.getenv("TELEGRAM_API_TOKEN")
        self._chat_id = os.getenv("TELEGRAM_CHAT_ID")
        
    async def _get_bot(self):
        """Инициализация бота асинхронно."""
        if not self._bot:
            self._bot = Bot(token=self._bot_token)
        return self._bot
    
    async def send_message(self, message: str) -> bool:
        """Отправка сообщения в Telegram чат асинхронно."""
        try:
            logging.debug(f"Попытка отправки сообщения в Telegram... (длина: {len(message)} символов)")
            bot = await self._get_bot()
            await bot.send_message(
                chat_id=self._chat_id,
                text=message,
                parse_mode='HTML',
            )
            logging.info("Сообщение успешно отправлено в Telegram.")
            return True
        except asyncio.CancelledError:
            # Если задача была отменена, пытаемся отправить синхронно
            logging.warning("Асинхронная операция была прервана, попытка синхронной отправки...")
            try:
                import requests
                token = self._bot_token
                chat_id = self._chat_id
                url = f"https://api.telegram.org/bot{token}/sendMessage"
                payload = {
                    "chat_id": chat_id,
                    "text": message,
                    "parse_mode": "HTML"
                }
                response = requests.post(url, json=payload, timeout=5)
                if response.status_code == 200:
                    logging.info("Сообщение отправлено синхронно (запасной вариант).")
                    return True
                else:
                    logging.error(f"Ошибка синхронной отправки: HTTP {response.status_code}")
                    return False
            except Exception as sync_error:
                logging.error(f"Синхронная отправка также не удалась: {sync_error}")
                return False
        except Exception as e:
            logging.error(f"Ошибка отправки сообщения в Telegram: {type(e).__name__}: {e}")
            return False
        
    async def notify_new_ports(self, ip: str, new_ports: list[int], services: dict):
        """ Отправка уведомления о новых открытых портах. """
        if not new_ports:
            return
        
        message = f"<b>Обнаружены новые открытые порты!</b>\n\n"
        message += f"<b>IP:</b> {ip}\n"
        message += f"<b>Время:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        message += f"<b>Новые порты ({len(new_ports)}):</b>\n"
        
        for port in new_ports:
            service = services.get(str(port), "Неизвестно")
            message += f" - Порт {port}/tcp: {service}\n"
            
        await self.send_message(message)
    
    async def notify_changed_services(self, ip: str, changed_ports: dict):
        """Отправка уведомления об изменении сервисов на портах."""
        if not changed_ports:
            return
        
        message = f"<b>Изменение сервисов на портах!</b>\n\n"
        message += f"<b>IP:</b> {ip}\n"
        message += f"<b>Время:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        message += f"<b>Измененные порты ({len(changed_ports)}):</b>\n"
        
        for port, (old_service, new_service) in changed_ports.items():
            message += f" - Порт {port}/tcp:\n"
            message += f"   Было: {old_service}\n"
            message += f"   Стало: {new_service}\n"
            
        await self.send_message(message)
    
    async def notify_scan_results_single(self, target_name: str, target: str, ports_info: dict):
        """Отправка полной информации о результатах разового сканирования."""
        if not ports_info:
            message = f"<b>Сканирование завершено!</b>\n\n"
            message += f"<b>Цель:</b> {target_name}\n"
            message += f"<b>Адрес:</b> {target}\n"
            message += f"<b>Результат:</b> Открытых портов не обнаружено\n"
            message += f"<b>Время:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            
            await self.send_message(message)
            return
        
        message = f"<b>Результаты сканирования:</b>\n\n"
        message += f"<b>Цель:</b> {target_name}\n"
        message += f"<b>Адрес:</b> {target}\n"
        message += f"<b>Время:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        message += f"<b>Открытые порты ({len(ports_info)}):</b>\n"
        
        for port, service in ports_info.items():
            message += f" - Порт {port}/tcp: {service}\n"
            
        await self.send_message(message)
    
    async def notify_schedule_started(self, target_name: str, target: str, ports: str, interval_hours: float):
        """Уведомление о начале планового сканирования."""
        message = f"<b>Начало планового сканирования!</b>\n\n"
        message += f"<b>Цель:</b> {target_name}\n"
        message += f"<b>Адрес:</b> {target}\n"
        message += f"<b>Порты:</b> {ports}\n"
        message += f"<b>Интервал:</b> каждые {interval_hours} часов\n"
        message += f"<b>Время:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        
        await self.send_message(message)
    
    async def notify_schedule_stopped(self, scan_count: int, total_cycles: int) -> bool:
        """Уведомление о завершении планового сканирования."""
        message = f"<b>Плановое сканирование остановлено!</b>\n\n"
        message += f"<b>Завершено циклов:</b> {total_cycles}\n"
        message += f"<b>Проведено проверок портов:</b> {scan_count}\n"
        message += f"<b>Время остановки:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        
        return await self.send_message(message)
        
    async def notify_scan_complete(self, target_name: str, total_ports: int):
        """Отправка уведомления об окончании сканирования."""
        
        message = f"<b>Сканирование завершено!</b>\n\n"
        message += f"<b>Цель:</b> {target_name}\n"
        message += f"<b>Всего открытых портов:</b> {total_ports}\n"
        message += f"<b>Время:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        
        await self.send_message(message)
        
    async def notify_scan_start(self, target_name: str, target: str, ports: str):
        """Отправка уведомления о начале сканирования."""
        
        message = f"<b>Начало сканирования!</b>\n\n"
        message += f"<b>Цель:</b> {target_name}\n"
        message += f"<b>Адрес:</b> {target}\n"
        message += f"<b>Порты:</b> {ports}\n"
        message += f"<b>Время:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        
        await self.send_message(message)


# === 4. Banner Grabber Class ===
class BannerGrabber:
    """Получение баннеров с открытых портов при помощи nmap."""
    
    def __init__(self, nmap_args: List[str] = None):
        self.nm = nmap.PortScanner()
        self.nmap_args = nmap_args or ['-sV', '--version-intensity=1', '-T5', '--open', '-n', '-Pn', '--max-hostgroup=256']
        
    def identify_open_ports(self, ip: str, ports: List[int]) -> Dict[int, str]:
        """Получение баннеров для всех портов сразу."""
        if not ports:
            return {}
        
        try:
            ports_str = ','.join(map(str, ports))
            
            logging.debug(f"Сканирование {len(ports)} портов на {ip} за одну операцию: {ports_str}")
            
            scan_nmap_result = self.nm.scan(
                hosts=ip,
                ports=ports_str,
                arguments=' '.join(self.nmap_args)
            )

            # Извлечение данных о сервисах
            host_data = scan_nmap_result.get('scan', {}).get(ip, {})
            if not host_data:
                logging.warning(f"Нет данных от Nmap для {ip}")
                return {port: "Нет ответа" for port in ports}
            
            tcp_info = host_data.get('tcp', {})
            services = {}
            
            # Обработка каждого порта из результатов
            for port in ports:
                port_info = tcp_info.get(port, {})
                
                if not port_info:
                    services[port] = "Порт не сканирован"
                    continue
                
                # Проверяем статус открытости портов
                port_status = port_info.get('state', 'unknown')
                if port_status != 'open':
                    services[port] = f"Закрыт ({port_status})"
                    continue
                
                service_name = port_info.get('name', 'Unknown')
                product = port_info.get('product', '').strip()
                version = port_info.get('version', '').strip()
                extrainfo = port_info.get('extrainfo', '').strip()
                
                # Формируем полное описание сервиса
                banner_parts = [service_name]
                if product:
                    banner_parts.append(product)
                if version:
                    banner_parts.append(version)
                if extrainfo:
                    banner_parts.append(f"({extrainfo})")
                
                services[port] = " ".join(banner_parts).strip()
            
            return services

        except nmap.PortScannerError as e:
            # Обработка ошибок сканирования Nmap
            logging.warning(f"Ошибка сканирования Nmap для {ip} (порты: {ports}): {e}")
            return {port: "Ошибка сканирования (Nmap)" for port in ports}
        except Exception as e:
            logging.debug(f"Общая ошибка при получении информации о портах на {ip}: {type(e).__name__}: {e}")
            return {port: "Ошибка при сканировании" for port in ports}
        

# === 5. Masscan Scanner Class ===
class MasscanScanner:
    """Сканирование портов с использованием masscan и обработка результатов."""
    
    def __init__(self, rate: int = 1000, timeout: int = 5):
        self.rate = rate
        self.timeout = timeout
        self._check_masscan_installed()
        
    def _check_masscan_installed(self):
        """Проверка установки masscan в системе."""
        try:
            result = subprocess.run(
                ['sudo', 'which', 'masscan'], 
                check=True,
                capture_output=True,
                timeout=self.timeout
            )
            
            masscan_path = result.stdout.decode().strip()
            logging.info(f"Masscan установлен и доступен по пути {masscan_path}.")  
            
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired) as e:
            logging.error(f"Ошибка при проверке наличия masscan: {e}")
            sys.exit(1)
    
    def scan(self, target: str, ports: str) -> List[Dict]:
        """Выполнение сканирования с помощью masscan и возврат результатов."""
        
        logging.info(f"Запуск masscan для цели: {target} на портах: {ports} с rate: {self.rate}")
        
        # Временный файл для вывода результатов
        output_file = f"app/scan_history/masscan_output_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        # Построение команды masscan
        cmd = [
            #'sudo', # Запуск от суперпользователя для доступа к низкоуровневым сетевым функциям
            'masscan',
            target,
            '-p', ports,
            '--rate', str(self.rate),
            '--open-only',
            '--wait', '0',
            '--output-format', 'json',
            '--output-filename', output_file
        ]
        
        try:
            logging.info(f"Команда: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True
            )

            if result.returncode not in [0, 1]:  # 0 - успешное выполнение, 1 - некоторые хосты недоступны
                logging.error(f"Ошибка при выполнении masscan: {result.stderr}")
                return []
            
            if not Path(output_file).exists():
                logging.warning("Файл с результатами сканирования не был создан.")
                return []
            
            with open(output_file, 'r', encoding='utf-8') as f:
                scan_results_lines = f.readlines()
                
            results = []
            
            for line in scan_results_lines:
                line = line.strip()
                if not line or line in [',', '[', ']', '{', '}']:
                    continue
                if line.endswith(','):
                    line = line[:-1]
                if len(line) < 10:
                    continue
                    
                try:
                    data = json.loads(line)
                    if 'ip' in data and 'ports' in data:
                        for port_info in data['ports']:
                            results.append({
                                'ip': data['ip'],
                                'port': port_info['port'],
                                'protocol': port_info.get('proto', 'tcp'),
                                'status': port_info.get('status', 'open')
                            })
                except json.JSONDecodeError as e:
                    logging.debug(f"Ошибка парсинга JSON (строка: '{line[:50]}'): {e}")
                    continue
                
            try:
                os.remove(output_file)
            except OSError as e:
                logging.warning(f"Не удалось удалить временный файл: {e}")
                
            logging.info(f"Masscan завершил сканирование. Найдено {len(results)} открытых портов.")
            return results

        except subprocess.TimeoutExpired:
            logging.error(f"Время ожидания истекло при выполнении masscan {self.timeout} секунд.")
            return []
        except Exception as e:
            logging.error(f"Неизвестная ошибка при выполнении masscan: {e}")
            return []
        

# === 6. Scan History Class ===
class ScanHistory:
    """Управление историей сканирований и хранение данных о найденных портах."""
    
    def __init__(self, history_file: str = "app/scan_history/scan_history.json"):
        self.history_file = history_file
        self.data = self._load_history()
        
    def _load_history(self) -> dict:
        """Загрузка истории сканирований из JSON файла."""
        if not Path(self.history_file).exists():
            return {}
        
        try:
            with open(self.history_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except json.JSONDecodeError as e:
            logging.error(f"Ошибка парсинга JSON в файле истории создаём новую историю: {e}")
            return {}
        
    def _save_history(self):
        """Сохранение истории сканирований в JSON файл."""
        
        try:
            with open(self.history_file, 'w', encoding='utf-8') as f:
                json.dump(self.data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logging.error(f"Ошибка при сохранении истории сканирований: {e}")
        
    def get_previous_ports(self, ip: str) -> set:
        """Получение множества ранее найденных портов для данного IP."""
        return set(self.data.get(ip, {}).get("ports", []))
    
    def update_ports(self, ip: str, ports: List[int], services: dict):
        """Обновление информации о портах для указанного IP."""
        if ip not in self.data:
            self.data[ip] = {
                "first_scanned": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                "ports": [],
                "services": {}
            }
            
        self.data[ip]["ports"] = sorted(list(set(ports)))
        self.data[ip]["services"].update(services)
        self.data[ip]["last_scanned"] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self._save_history()
        
    def find_new_ports(self, ip: str, current_ports: List[int]) -> List[int]:
        """Определение новых портов, которых не было в предыдущих сканированиях."""
        previous_p = self.get_previous_ports(ip)
        current_p = set(current_ports)
        new_ports = current_p - previous_p
        return sorted(list(new_ports))
    
    def find_changed_services(self, ip: str, current_services: dict) -> dict:
        """Определение портов, на которых изменились сервисы."""
        if ip not in self.data:
            return {}
        
        previous_services = self.data[ip].get("services", {})
        changed = {}
        
        for port, new_service in current_services.items():
            port_str = str(port)
            old_service = previous_services.get(port_str, "")
            
            # Сравниваем новый сервис со старым
            if old_service and old_service != new_service:
                changed[port] = (old_service, new_service)
        
        return changed


# === 7. Port Scanner Orchestrator Class ===
class PortScannerOrchestrator:
    """Координация всех компонентов для выполнения сканирования портов."""
    
    def __init__(self, config_path: str = "config.json"):
        self.config = Config(config_path)
        self.history = ScanHistory()
        self.masscan_scanner = MasscanScanner(
            rate=self.config.masscan_rate,
            timeout=self.config.masscan_timeout
            )
        self.notifier = TelegramNotifier()
        self.banner_grabber = BannerGrabber()

    async def process_scan_result(self, results: List[Dict], target_name: str, is_scheduled: bool = False) -> dict:
        """
        Обработка результатов сканирования:
        - Группировка по IP
        - Получение баннеров для каждого порта
        - Сравнение с историей
        - Возврат информации об изменениях
        
        Возвращает словарь с информацией об изменениях для каждого IP
        """
        if not results:
            logging.info("Нет открытых портов для обработки.")
            return {}
        
        # Группировка результатов по IP
        ports_by_ip: Dict[str, List[int]] = {}
        
        for result in results:
            ip = result['ip']
            port = result['port']
            
            if ip not in ports_by_ip:
                ports_by_ip[ip] = []
            ports_by_ip[ip].append(port)
            
        logging.info(f"Обнаружено {len(ports_by_ip)} уникальных IP адресов с открытыми портами.")
        
        changes_detected = {}
        
        # Обработка каждого IP
        for ip, ports in ports_by_ip.items():
            logging.info("="*60)
            logging.info(f"Обработка {target_name} c IP: {ip} с портами: {ports}")
            logging.info("="*60)
            logging.info(f"Сканирование {len(ports)} портов на {ip}...")
            
            services_int_keys = self.banner_grabber.identify_open_ports(ip, ports)
            
            services = {str(port): service_info for port, service_info in services_int_keys.items()}
            
            for port, service_info in services.items():
                logging.info(f"-> {ip}:{port}/tcp: {service_info}")
            
            # Определение новых портов
            new_ports = self.history.find_new_ports(ip, ports)
            
            # Определение измененных сервисов
            changed_services = self.history.find_changed_services(ip, services)
            
            ip_changes = {
                'has_new_ports': bool(new_ports),
                'new_ports': new_ports,
                'has_changed_services': bool(changed_services),
                'changed_services': changed_services,
                'services': services,
                'all_ports': ports
            }
            
            if is_scheduled:
                # При плановом сканировании отправляем только если есть изменения
                if new_ports:
                    logging.warning(f"Обнаружены НОВЫЕ открытые порты на {ip}: {new_ports}")
                    await self.notifier.notify_new_ports(ip, new_ports, services)
                
                if changed_services:
                    logging.warning(f"На {ip} изменились сервисы: {changed_services}")
                    await self.notifier.notify_changed_services(ip, changed_services)
                
                if not new_ports and not changed_services:
                    logging.info(f"На {ip} нет изменений (новых портов и измененных сервисов).")
            else:
                # При разовом сканировании собираем информацию без отправки
                if new_ports:
                    logging.warning(f"Обнаружены НОВЫЕ открытые порты на {ip}: {new_ports}")
                
                if changed_services:
                    logging.warning(f"На {ip} изменились сервисы: {changed_services}")
                
                logging.info(f"История сканирования для {ip} обновлена (режим разового сканирования).")
            
            # Обновление истории сканирования
            self.history.update_ports(ip, ports, services)
            
            changes_detected[ip] = ip_changes
        
        return changes_detected
            
    async def run_scan(self, target_config: Dict[str, str], is_scheduled: bool = False):
        """Запуск полного цикла сканирования."""
        
        target_name = target_config.get("name", "Unknown")
        target = target_config["target"]
        ports = target_config["ports"]
        
        logging.info("="*60)
        logging.info(f"Запуск сканирования")
        logging.info(f"Цель: {target_name}")
        logging.info(f"Адрес: {target}")
        logging.info(f"Порты: {ports}")
        logging.info(f"Rate: {self.config.masscan_rate} пакетов/сек")
        logging.info("="*60)
        
        # Для разового сканирования отправляем уведомление о начале
        if not is_scheduled:
            await self.notifier.notify_scan_start(target_name, target, ports)
        
        # Выполнение сканирования masscan
        scan_results = self.masscan_scanner.scan(target, ports)
        
        if not scan_results:
            logging.info("Сканирование завершено. Открытых портов не обнаружено.")
            if not is_scheduled:
                await self.notifier.notify_scan_results_single(target_name, target, {})
            return {}
        
        # Обработка результатов сканирования (возвращает информацию об изменениях)
        changes = await self.process_scan_result(scan_results, target_name, is_scheduled=is_scheduled)
        
        # Для разового сканирования отправляем полную информацию
        if not is_scheduled and scan_results:
            # Собираем все порты и сервисы для отправки
            ports_info = {}
            for ip, ip_info in changes.items():
                for port_str, service in ip_info['services'].items():
                    ports_info[f"{ip}:{port_str}"] = service
            
            await self.notifier.notify_scan_results_single(target_name, target, ports_info)
        
        logging.info("="*60)
        logging.info("Сканирование завершено.")
        logging.info(f"Обнаружено {len(scan_results)} открытых портов на {target_name}")
        logging.info("="*60)
        
        return changes

    async def run_all_scans(self, is_scheduled: bool = False):
        """Запуск сканирования для всех целей из конфигурации."""
        
        targets = self.config.scan_targets
        total_targets = len(targets)
        
        logging.info("="*60)
        logging.info(f"Начало сканирования всех целей. Всего целей: {total_targets}")
        logging.info("="*60)
        
        for idx, target_config in enumerate(targets, 1):
            try:
                logging.info(f">>> Сканирование цели {idx} из {total_targets} <<<")
                await self.run_scan(target_config, is_scheduled=is_scheduled)
            except Exception as e:
                target_name = target_config.get("name", "Unknown")
                logging.error(f"Ошибка при сканировании цели {target_name}: {e}", exc_info=True)
                continue
        
        logging.info("="*60)
        logging.info("Сканирование всех целей завершено.")
        logging.info(f"Просканировано целей: {total_targets}")
        logging.info("="*60)
            
    async def run_scheduled_scans(self):
        """Запуск сканирования по расписанию."""
        
        if not self.config.schedule_enabled:
            logging.info("Планировщик сканирования отключен в конфиге.")
            logging.info("Выполняется одноразовое сканирование всех целей.")
            await self.run_all_scans(is_scheduled=False)
            return
        
        interval = self.config.schedule_interval_hours
        interval_seconds = interval * 3600
        
        logging.info(f"Режим рассписания включен.")
        logging.info(f"Сканирование будет выполняться каждые {interval} часов.")
        logging.info("Для остановки сканирования нажмите Ctrl+C.")
        
        # Отправляем уведомление о начале планового сканирования
        targets = self.config.scan_targets
        if targets:
            first_target = targets[0]
            await self.notifier.notify_schedule_started(
                first_target.get("name", "Unknown"),
                first_target["target"],
                first_target["ports"],
                interval
            )
        
        scan_count = 0
        total_cycles = 0
        
        try:
            while True:
                total_cycles += 1
                logging.info("="*60)
                logging.info(f"Цикл сканирования #{total_cycles} начат.")
                logging.info("="*60)
                
                await self.run_all_scans(is_scheduled=True)
                
                # Подсчитываем все открытые порты для статистики
                for target_config in targets:
                    target = target_config["target"]
                    previous_ports = self.history.get_previous_ports(target)
                    scan_count += len(previous_ports)
                
                next_scan_time = datetime.now().timestamp() + interval_seconds
                next_scan_datetime = datetime.fromtimestamp(next_scan_time).strftime('%Y-%m-%d %H:%M:%S')
                logging.info(f"Следующее сканирование запланировано на: {next_scan_datetime}")
                logging.info(f"Ожидание {interval} часов до следующего сканирования...\n")
                
                try:
                    await asyncio.sleep(interval_seconds)
                except (KeyboardInterrupt, asyncio.CancelledError):
                    raise KeyboardInterrupt()
                
        except KeyboardInterrupt:
            logging.info(">>> Сканирование остановлено пользователем.")
            logging.info(f"Статистика: {total_cycles} циклов, {scan_count} проверок")
            
            # Отправляем финальное уведомление в Telegram
            await self.notifier.notify_schedule_stopped(scan_count, total_cycles)
            
            
# === 8. Main Entry Point ===
async def main():
    """Точка входа для запуска сканирования портов."""
    
    setup_logging()
    
    logging.info("="*60)
    logging.info("  PORT SCANNER - Автоматизированное сканирование портов")
    logging.info("  Использует: Masscan + Nmap + Telegram")
    logging.info("="*60)
    
    orchestrator = PortScannerOrchestrator(config_path="app/config.json")
    await orchestrator.run_scheduled_scans()

    
if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as e:
        logging.error(f"Критическая ошибка: {e}", exc_info=True)
        sys.exit(1)
    finally:
        logging.info("="*60)
        logging.info(">>> Программа завершена\n")