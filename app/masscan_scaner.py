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
    
    def __init__(self, bot_token: str, chat_id: str):
        self.bot_token = bot_token
        self.chat_id = chat_id
        self._bot = None
        
    async def _get_bot(self):
        """Инициализация бота асинхронно."""
        if not self._bot:
            self._bot = Bot(token=self.bot_token)
        return self._bot
    
    async def send_message(self, message: str) -> bool:
        """Отправка сообщения в Telegram чат асинхронно."""
        try:
            bot = await self._get_bot()
            await bot.send_message(
                chat_id=self.chat_id,
                text=message,
                parse_mode='HTML',
            )
            logging.info("Уведомление отправлено в Telegram.")
            return True
        except Exception as e:
            logging.error(f"Не удалось отправить уведомление в Telegram: {e}")
            return False
        
    async def notify_new_ports(self, ip: str, new_ports: list[int], services: dict):
        """ ОТправка уведомления о новых открытых портах. """
        if not new_ports:
            return
        
        message = f"🚨 <b>Обнаружены новые открытые порты!</b>\n\n"
        message += f"<b>IP:</b> {ip}\n"
        message += f"<b>Время:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        message += f"<b>Новые порты ({len(new_ports)}):</b>\n"
        
        for port in new_ports:
            service = services.get(port, "Неизвестно")
            message += f" - Порт {port}/tcp: {service}\n"
            
        await self.send_message(message)
        
    async def notify_scan_complete(self, target_name: str, total_ports: int):
        """Отправка уведомления об окончании сканирования."""
        
        message = f"✅ <b>Сканирование завершено!</b>\n\n"
        message += f"<b>Цель:</b> {target_name}\n"
        message += f"<b>Всего открытых портов:</b> {total_ports}\n"
        message += f"<b>Время:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        
        await self.send_message(message)
        
    async def notify_scan_start(self, target_name: str, target: str, ports: str):
        """Отправка уведомления о начале сканирования."""
        
        message = f"🚀 <b>Начало сканирования!</b>\n\n"
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
        self.nmap_args = nmap_args or ['-sV', '--version-intensity=2', '-T4', '--open', '-n', '-Pn']
        
    def identify_open_ports(self, ip: str, port: int) -> str:
        """Получение баннеров с открытых портов."""
        try:
            # Сканируем 
            scan_nmap_result = self.nm.scan(
                hosts=ip,
                ports=str(port),
                arguments=' '.join(self.nmap_args)
            )

            # Извлечение данных о сервисах
            host_data = scan_nmap_result.get('scan', {}).get(ip, {})
            if not host_data:
                return "Нет ответа"
            
            tcp_info = host_data.get('tcp', {})

            port_info = tcp_info.get(port, {})
            if not port_info:
                return f"Порт {port} не открыт или ошибка"
            
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
            
            return " ".join(banner_parts).strip()

        except Exception as e:
            logging.error(f"Ошибка при получении информации о порту {port} на {ip}: {e}")
            return f"Ошибка при сканировании порта {port}"
        

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
            logging.info(f"Возврат кода masscan: {result.returncode}")
            logging.info(f"Stdout: {result.stdout[:200]}...")
            logging.info(f"Stderr: {result.stderr[:200]}...")

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
                if not line or line == ',':
                    continue
                if line.endswith(','):
                    line = line[:-1]
                    
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
                    logging.error(f"Ошибка парсинга строки JSON: {e}")
                    continue
                
            try:
                pass
                #os.remove(output_file)
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
        self.notifier = TelegramNotifier(
            bot_token=self.config.telegram_token,
            chat_id=self.config.telegram_chat_id
            )
        self.banner_grabber = BannerGrabber()

    async def process_scan_result(self, results: List[Dict], target_name: str):
        """
        Обработка результатов сканирования:
        - Группировка по IP
        - Получение баннеров для каждого порта
        - Сравнение с историей
        - Отправка уведомлений о новых портах
        """
        if not results:
            logging.info("Нет открытых портов для обработки.")
            return
        
        # Группировка результатов по IP
        ports_by_ip: Dict[str, List[int]] = {}
        
        for result in results:
            ip = result['ip']
            port = result['port']
            
            if ip not in ports_by_ip:
                ports_by_ip[ip] = []
            ports_by_ip[ip].append(port)
            
        logging.info(f"Обнаружено {len(ports_by_ip)} уникальных IP адресов с открытыми портами.")
        
        # Обработка каждого IP
        for ip, ports in ports_by_ip.items():
            logging.info(f"{'='*60}")
            logging.info(f"Обработка {target_name} c IP: {ip} с портами: {ports}")
            logging.info(f"{'='*60}")
            
            # Получение баннеров для каждого порта
            services = {}
            for port in ports:
                logging.info(f"Получение баннера для {ip}:{port}")
                service_info = self.banner_grabber.identify_open_ports(ip, port)
                services[port] = service_info
                logging.info(f"-> {ip}:{port}/tcp: {service_info}")
            
            # Определение новых портов
            new_ports = self.history.find_new_ports(ip, ports)
            
            if new_ports:
                logging.warning(f"Обноружены НОВЫЕ открытые порты на {ip}: {new_ports}")
                await self.notifier.notify_new_ports(ip, new_ports, services)
            else:
                logging.info(f"Новых открытых портов на {ip} не обнаружено.")
                
            # Обновление истории сканирования
            self.history.update_ports(ip, ports, services)
            logging.info(f"История сканирования для {ip} обновлена.")
            
    async def run_scan(self, target_config: Dict[str, str]):
        """Запуск полного цикла сканирования."""
        
        target_name = target_config.get("name", "Unknown")
        target = target_config["target"]
        ports = target_config["ports"]
        
        logging.info(f"{'='*60}")
        logging.info(f"Запуск сканирования")
        logging.info(f"Цель: {target_name}")
        logging.info(f"Адрес: {target}")
        logging.info(f"Порты: {ports}")
        logging.info(f"Rate: {self.config.masscan_rate} пакетов/сек")
        logging.info(f"{'='*60}")
        
        await self.notifier.notify_scan_start(target_name, target, ports)
        
        # Выполнение сканирования masscan
        scan_results = self.masscan_scanner.scan(target, ports)
        
        if not scan_results:
            logging.info("Сканирование завершено. Открытых портов не обнаружено.")
            await self.notifier.notify_scan_complete(target_name, 0)
            return
        
        # Обработка результатов сканирования
        await self.process_scan_result(scan_results, target_name)
        
        # Уведомление об окончании сканирования
        await self.notifier.notify_scan_complete(target_name, len(scan_results))
        
        logging.info(f"{'='*60}")
        logging.info("Сканирование завершено.")
        logging.info(f"Обнаружено {len(scan_results)} открытых портов на {target_name}")
        logging.info(f"{'='*60}\n")

    async def run_all_scans(self):
        """Запуск сканирования для всех целей из конфигурации."""
        
        targets = self.config.scan_targets
        total_targets = len(targets)
        
        logging.info(f"{'='*60}")
        logging.info(f"Начало сканирования всех целей. Всего целей: {total_targets}")
        logging.info(f"{'='*60}\n")
        
        for idx, target_config in enumerate(targets, 1):
            try:
                logging.info(f">>> Сканирование цели {idx} из {total_targets} <<<")
                await self.run_scan(target_config)
            except Exception as e:
                target_name = target_config.get("name", "Unknown")
                logging.error(f"Ошибка при сканировании цели {target_name}: {e}", exc_info=True)
                continue
        
        logging.info(f"{'='*60}")
        logging.info("Сканирование всех целей завершено.")
        logging.info(f"Просканировано целей: {total_targets}")
        logging.info(f"{'='*60}\n")
            
    async def run_scheduled_scans(self):
        """Запуск сканирования по расписанию."""
        
        if not self.config.schedule_enabled:
            logging.info("Планировщик сканирования отключен в конфиге.")
            logging.info("Выполняется одноразовое сканирование всех целей.")
            await self.run_all_scans()
            return
        
        interval = self.config.schedule_interval_hours
        interval_seconds = interval * 3600
        
        logging.info(f"Режим рассписания включен.")
        logging.info(f"Сканирование будет выполняться каждые {interval} часов.")
        logging.info("Для остановки сканирования нажмите Ctrl+C.")
        
        scan_count = 0
        
        try:
            while True:
                scan_count += 1
                logging.info(f"\n{'#'*60}")
                logging.info(f"Цикл сканирования #{scan_count} начат.")
                logging.info(f"{'#'*60}\n")
                
                await self.run_all_scans()
                
                next_scan_time = datetime.now().timestamp() + interval_seconds
                next_scan_datetime = datetime.fromtimestamp(next_scan_time).strftime('%Y-%m-%d %H:%M:%S')
                logging.info(f"Следующее сканирование запланировано на: {next_scan_datetime}")
                logging.info(f"Ожидание {interval} часов до следующего сканирования...\n")
                
                await asyncio.sleep(interval_seconds)
                
        except KeyboardInterrupt:
            logging.info("\n\n Сканирование по расписанию остановлено пользователем.")
            logging.info("Выполнено циклов сканирования: {scan_count}")
            logging.info("Завершение работы.")
            
            
# === 8. Main Entry Point ===
async def main():
    """Точка входа для запуска сканирования портов."""
    
    # Настройка логирования
    setup_logging()
    
    logging.info("="*60)
    logging.info("  PORT SCANNER - Автоматизированное сканирование портов")
    logging.info("  Использует: Masscan + Nmap + Telegram")
    logging.info("="*60 + "\n")
    
    try:
        #Инициализация оркестратора сканирования
        orchestrator = PortScannerOrchestrator(config_path="app/config.json")
        
        # Выбрать запускаемый режим выполнения
        # Запуск сканирования (автоматически определяет режим из конфига)
        # Если schedule.enabled = false -> однократное сканирование всех целей
        # Если schedule.enabled = true -> периодическое сканирование по расписанию
        await orchestrator.run_scheduled_scans()
        
    except KeyboardInterrupt:
        logging.info(">>> Сканирование остановлено пользователем.")
    except Exception as e:
        logging.error(f"Неизвестная ошибка в основном цикле: {e}", exc_info=True)
        sys.exit(1)
    finally:
        logging.info("="*60)
        logging.info(">>> Программа завершена " + "\n")

    
if __name__ == "__main__":
    # Запуск основного цикла
    asyncio.run(main())