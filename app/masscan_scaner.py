"""
Docstring для app.masscan_scaner
Основной модуль для сканирования портов с использованием masscan.
В нем реализовано классами:
1. Config - для загрузки и управления конфигурацией сканирования. +
2. ScanHistory - для ведения истории сканирований.
3. MasscanScanner - для выполнения сканирования с помощью masscan и обработки результатов.
4. BannerGrabber - для захвата баннеров с открытых портов.
5. TelegramNotifier - для отправки уведомлений через Telegram. +
6. PortScannerOrchestrator - для координации всех компонентов и управления процессом сканирования.
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


# === Logging Setup === 
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


# === Config Class === 
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
    
    @property
    def scan_target(self) -> str:
        return self.data["scan_target"]["target"]
    
    @property
    def scan_ports(self) -> str:
        return self.data["scan_target"]["ports"]
    
    @property
    def masscan_rate(self) -> int:
        return self.data["masscan_config"].get("rate", 1000)
    
    @property
    def telegram_token(self) -> str:
        return self.data["telegram"].get("bot_token", "")
    
    @property
    def telegram_chat_id(self) -> str:
        return self.data["telegram"].get("chat_id", "")


# === Telegram Notifier Class ===
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
                text=message
                parse_mode='HTML'
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


# === Banner Grabber Class ===
class BannerGrabber:
    """Получение баннеров с открытых портов при помощи nmap."""
    
    def __init__(self, nmap_args: List[str] = None):
        self.nm = nmap.PortScanner()
        self.nmap_args = nmap_args or ['-sV', '-T4', '--open']
        
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

            port_info = tcp_info.get('port', {})
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