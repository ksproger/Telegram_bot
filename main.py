#!/usr/bin/env python3
"""
Telegram бот CyberInvestigator для OSINT разведки
Разработан для развертывания на Render.com
"""

import os
import logging
import json
import asyncio
from datetime import datetime
from urllib.parse import urlparse

import requests
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application, CommandHandler, MessageHandler, CallbackQueryHandler,
    ContextTypes, filters
)
from telegram.error import TelegramError

from cyberinvestigator import CyberInvestigator

# Настройка логирования
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# Конфигурация
BOT_TOKEN = os.environ.get('BOT_TOKEN')
if not BOT_TOKEN:
    raise ValueError("Не установлен BOT_TOKEN в переменных окружения")

# Инициализация OSINT инструмента
investigator = CyberInvestigator(
    shodan_api_key=os.environ.get('SHODAN_API_KEY'),
    virustotal_api_key=os.environ.get('VIRUSTOTAL_API_KEY')
)

class TelegramBot:
    def __init__(self):
        self.application = Application.builder().token(BOT_TOKEN).build()
        self.setup_handlers()
        self.user_sessions = {}

    def setup_handlers(self):
        """Настройка обработчиков команд"""
        self.application.add_handler(CommandHandler("start", self.start_command))
        self.application.add_handler(CommandHandler("help", self.help_command))
        self.application.add_handler(CommandHandler("domain", self.domain_command))
        self.application.add_handler(CommandHandler("ip", self.ip_command))
        self.application.add_handler(CommandHandler("email", self.email_command))
        self.application.add_handler(CommandHandler("phone", self.phone_command))
        
        self.application.add_handler(CallbackQueryHandler(self.button_handler))
        self.application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, self.handle_message))

    async def start_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Обработчик команды /start"""
        user = update.effective_user
        welcome_text = f"""
👋 Привет, {user.first_name}!

Я *CyberInvestigator* - мощный OSINT бот для сбора информации из открытых источников.

🔍 *Доступные команды:*
/domain <адрес> - Разведка домена
/ip <адрес> - Разведка IP адреса  
/email <адрес> - Разведка email
/phone <номер> - Разведка телефона
/help - Справка по использованию

*Примеры:*
/domain google.com
/ip 8.8.8.8
/email test@example.com
/phone +79123456789

⚠️ *Внимание:* Используйте инструмент только в законных целях!
        """
        
        keyboard = [
            [InlineKeyboardButton("🔍 Разведка домена", callback_data="domain_scan")],
            [InlineKeyboardButton("🌐 Разведка IP", callback_data="ip_scan")],
            [InlineKeyboardButton("📧 Разведка email", callback_data="email_scan")],
            [InlineKeyboardButton("📞 Разведка телефона", callback_data="phone_scan")],
            [InlineKeyboardButton("📖 Помощь", callback_data="help")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await update.message.reply_text(
            welcome_text, 
            parse_mode='Markdown',
            reply_markup=reply_markup
        )

    async def help_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Обработчик команды /help"""
        help_text = """
📖 *Справка по использованию CyberInvestigator*

*Основные команды:*

🔍 *Разведка домена*
/domain <domain.com>
• WHOIS информация
• DNS записи  
• Поддомены
• Технологии
• Email адреса
• Социальные сети

🌐 *Разведка IP адреса*
/ip <IP-адрес>
• Геолокация
• Открытые порты
• Shodan информация
• Провайдер

📧 *Разведка email*
/email <email@example.com>
• Проверка утечек
• Gravatar
• Социальные профили

📞 *Разведка телефона*
/phone <номер>
• Информация об операторе
• Геолокация
• Социальные профили
• Проверка на спам

*Примеры использования:*
/domain google.com
/ip 8.8.8.8  
/email test@example.com
/phone +79123456789

*Поддерживаемые операторы:*
• Россия: MTS, Beeline, MegaFon, Tele2, Yota
• Армения: Ucom, Viva-MTS, Team Telecom
• Международные операторы

⚠️ *Важно:* Используйте инструмент ответственно и в рамках законодательства.
        """
        await update.message.reply_text(help_text, parse_mode='Markdown')

    async def domain_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Обработчик команды /domain"""
        if not context.args:
            await update.message.reply_text(
                "❌ Укажите домен для исследования\nПример: /domain example.com"
            )
            return

        domain = context.args[0].lower()
        await self.perform_domain_scan(update, domain)

    async def ip_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Обработчик команды /ip"""
        if not context.args:
            await update.message.reply_text(
                "❌ Укажите IP адрес для исследования\nПример: /ip 8.8.8.8"
            )
            return

        ip_address = context.args[0]
        await self.perform_ip_scan(update, ip_address)

    async def email_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Обработчик команды /email"""
        if not context.args:
            await update.message.reply_text(
                "❌ Укажите email для исследования\nПример: /email test@example.com"
            )
            return

        email = context.args[0]
        await self.perform_email_scan(update, email)

    async def phone_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Обработчик команды /phone"""
        if not context.args:
            await update.message.reply_text(
                "❌ Укажите номер телефона для исследования\nПример: /phone +79123456789"
            )
            return

        phone = context.args[0]
        await self.perform_phone_scan(update, phone)

    async def button_handler(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Обработчик нажатий кнопок"""
        query = update.callback_query
        await query.answer()

        user_id = query.from_user.id
        data = query.data

        if data == "domain_scan":
            self.user_sessions[user_id] = "waiting_domain"
            await query.edit_message_text(
                "🔍 Введите домен для исследования:\nПример: example.com"
            )
        elif data == "ip_scan":
            self.user_sessions[user_id] = "waiting_ip" 
            await query.edit_message_text(
                "🌐 Введите IP адрес для исследования:\nПример: 8.8.8.8"
            )
        elif data == "email_scan":
            self.user_sessions[user_id] = "waiting_email"
            await query.edit_message_text(
                "📧 Введите email для исследования:\nПример: test@example.com"
            )
        elif data == "phone_scan":
            self.user_sessions[user_id] = "waiting_phone"
            await query.edit_message_text(
                "📞 Введите номер телефона для исследования:\nПример: +79123456789"
            )
        elif data == "help":
            await self.help_command(update, context)

    async def handle_message(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Обработчик текстовых сообщений"""
        user_id = update.effective_user.id
        text = update.message.text.strip()

        if user_id in self.user_sessions:
            session_type = self.user_sessions[user_id]
            del self.user_sessions[user_id]

            if session_type == "waiting_domain":
                await self.perform_domain_scan(update, text)
            elif session_type == "waiting_ip":
                await self.perform_ip_scan(update, text)
            elif session_type == "waiting_email":
                await self.perform_email_scan(update, text)
            elif session_type == "waiting_phone":
                await self.perform_phone_scan(update, text)
        else:
            await update.message.reply_text(
                "🤔 Используйте команды или кнопки для начала работы.\n"
                "Нажмите /start для отображения меню."
            )

    async def perform_domain_scan(self, update: Update, domain: str):
        """Выполнение сканирования домена"""
        try:
            # Валидация домена
            if not investigator.validate_domain(domain):
                await self.send_message(update, "❌ Неверный формат домена")
                return

            message = await self.send_message(update, "🔍 *Начинаем разведку домена...*\nЭто может занять несколько секунд ⏳")

            # Выполнение сканирования
            results = await asyncio.get_event_loop().run_in_executor(
                None, investigator.domain_investigation, domain
            )

            # Форматирование и отправка результатов
            await self.send_domain_results(update, results, message.message_id)

        except Exception as e:
            logger.error(f"Domain scan error: {e}")
            await self.send_message(update, f"❌ Ошибка при сканировании домена: {str(e)}")

    async def perform_ip_scan(self, update: Update, ip_address: str):
        """Выполнение сканирования IP"""
        try:
            # Валидация IP
            if not investigator.validate_ip(ip_address):
                await self.send_message(update, "❌ Неверный формат IP адреса")
                return

            message = await self.send_message(update, "🌐 *Начинаем разведку IP...*\nЭто может занять несколько секунд ⏳")

            # Выполнение сканирования
            results = await asyncio.get_event_loop().run_in_executor(
                None, investigator.ip_investigation, ip_address
            )

            # Форматирование и отправка результатов
            await self.send_ip_results(update, results, message.message_id)

        except Exception as e:
            logger.error(f"IP scan error: {e}")
            await self.send_message(update, f"❌ Ошибка при сканировании IP: {str(e)}")

    async def perform_email_scan(self, update: Update, email: str):
        """Выполнение сканирования email"""
        try:
            # Валидация email
            if not investigator.validate_email(email):
                await self.send_message(update, "❌ Неверный формат email")
                return

            message = await self.send_message(update, "📧 *Начинаем разведку email...*\nЭто может занять несколько секунд ⏳")

            # Выполнение сканирования
            results = await asyncio.get_event_loop().run_in_executor(
                None, investigator.email_investigation, email
            )

            # Форматирование и отправка результатов
            await self.send_email_results(update, results, message.message_id)

        except Exception as e:
            logger.error(f"Email scan error: {e}")
            await self.send_message(update, f"❌ Ошибка при сканировании email: {str(e)}")

    async def perform_phone_scan(self, update: Update, phone: str):
        """Выполнение сканирования телефона"""
        try:
            # Валидация телефона
            if not investigator.validate_phone(phone):
                await self.send_message(update, "❌ Неверный формат номера телефона")
                return

            message = await self.send_message(update, "📞 *Начинаем разведку номера...*\nЭто может занять несколько секунд ⏳")

            # Выполнение сканирования
            results = await asyncio.get_event_loop().run_in_executor(
                None, investigator.phone_investigation, phone
            )

            # Форматирование и отправка результатов
            await self.send_phone_results(update, results, message.message_id)

        except Exception as e:
            logger.error(f"Phone scan error: {e}")
            await self.send_message(update, f"❌ Ошибка при сканировании номера: {str(e)}")

    async def send_domain_results(self, update: Update, results: dict, original_message_id: int):
        """Отправка результатов сканирования домена"""
        try:
            domain = results['domain']
            text = f"🏠 *Результаты разведки домена:* `{domain}`\n"
            text += "═" * 40 + "\n"

            # WHOIS информация
            if results.get('whois_info'):
                whois_info = results['whois_info']
                text += "\n📋 *WHOIS информация:*\n"
                if whois_info.get('registrar'):
                    text += f"• Регистратор: `{whois_info['registrar']}`\n"
                if whois_info.get('creation_date'):
                    text += f"• Дата создания: `{whois_info['creation_date']}`\n"
                if whois_info.get('name_servers'):
                    text += f"• NS серверы: `{', '.join(whois_info['name_servers'][:3])}`\n"

            # DNS записи
            if results.get('dns_records'):
                text += "\n🌐 *DNS записи:*\n"
                for record_type, records in results['dns_records'].items():
                    if records:
                        text += f"• {record_type}: `{', '.join(records[:2])}`\n"

            # Поддомены
            if results.get('subdomains'):
                text += f"\n🔎 *Поддомены ({len(results['subdomains'])}):*\n"
                for subdomain in results['subdomains'][:5]:
                    text += f"• `{subdomain}`\n"
                if len(results['subdomains']) > 5:
                    text += f"• ... и еще {len(results['subdomains']) - 5}\n"

            # Технологии
            if results.get('technologies'):
                text += f"\n⚙️ *Технологии ({len(results['technologies'])}):*\n"
                for tech in results['technologies'][:8]:
                    text += f"• `{tech}`\n"

            # Email адреса
            if results.get('emails'):
                text += f"\n📧 *Email адреса ({len(results['emails'])}):*\n"
                for email in results['emails'][:3]:
                    text += f"• `{email}`\n"

            text += f"\n🕐 *Время сканирования:* `{results['timestamp']}`"

            # Кнопки для дополнительных действий
            keyboard = [
                [InlineKeyboardButton("🔄 Новый запрос", callback_data="domain_scan")],
            ]
            reply_markup = InlineKeyboardMarkup(keyboard)

            await self.edit_message(update, text, original_message_id, reply_markup)

        except Exception as e:
            logger.error(f"Error sending domain results: {e}")
            await self.edit_message(update, "❌ Ошибка при форматировании результатов", original_message_id)

    async def send_ip_results(self, update: Update, results: dict, original_message_id: int):
        """Отправка результатов сканирования IP"""
        try:
            ip_addr = results['ip']
            text = f"🌐 *Результаты разведки IP:* `{ip_addr}`\n"
            text += "═" * 40 + "\n"

            # Геолокация
            if results.get('geo_info'):
                geo = results['geo_info']
                text += "\n🗺️ *Геолокация:*\n"
                text += f"• Страна: `{geo.get('country', 'N/A')}`\n"
                text += f"• Город: `{geo.get('city', 'N/A')}`\n"
                text += f"• Провайдер: `{geo.get('isp', 'N/A')}`\n"
                text += f"• Организация: `{geo.get('org', 'N/A')}`\n"

            # Открытые порты
            if results.get('open_ports'):
                text += f"\n🔒 *Открытые порты ({len(results['open_ports'])}):*\n"
                text += f"• `{', '.join(map(str, results['open_ports'][:10]))}`\n"
                if len(results['open_ports']) > 10:
                    text += f"• ... и еще {len(results['open_ports']) - 10}\n"

            # Shodan информация
            if results.get('shodan_data') and results['shodan_data'].get('services'):
                text += "\n🔍 *Shodan данные:*\n"
                for service in results['shodan_data']['services'][:5]:
                    text += f"• `{service}`\n"

            text += f"\n🕐 *Время сканирования:* `{results['timestamp']}`"

            keyboard = [[InlineKeyboardButton("🔄 Новый запрос", callback_data="ip_scan")]]
            reply_markup = InlineKeyboardMarkup(keyboard)

            await self.edit_message(update, text, original_message_id, reply_markup)

        except Exception as e:
            logger.error(f"Error sending IP results: {e}")
            await self.edit_message(update, "❌ Ошибка при форматировании результатов", original_message_id)

    async def send_email_results(self, update: Update, results: dict, original_message_id: int):
        """Отправка результатов сканирования email"""
        try:
            email = results['email']
            text = f"📧 *Результаты разведки email:* `{email}`\n"
            text += "═" * 40 + "\n"

            # Gravatar
            if results.get('gravatar'):
                text += f"\n🖼️ *Gravatar:*\n`{results['gravatar']}`\n"

            # Социальные профили
            if results.get('social_profiles'):
                text += f"\n👥 *Социальные профили ({len(results['social_profiles'])}):*\n"
                for profile in results['social_profiles']:
                    text += f"• `{profile}`\n"

            # Утечки данных
            if results.get('breaches'):
                text += f"\n🔓 *Утечки данных ({len(results['breaches'])}):*\n"
                for breach in results['breaches'][:3]:
                    text += f"• `{breach}`\n"
            else:
                text += f"\n🔓 *Утечки данных:* не обнаружено\n"

            text += f"\n🕐 *Время сканирования:* `{results['timestamp']}`"

            keyboard = [[InlineKeyboardButton("🔄 Новый запрос", callback_data="email_scan")]]
            reply_markup = InlineKeyboardMarkup(keyboard)

            await self.edit_message(update, text, original_message_id, reply_markup)

        except Exception as e:
            logger.error(f"Error sending email results: {e}")
            await self.edit_message(update, "❌ Ошибка при форматировании результатов", original_message_id)

    async def send_phone_results(self, update: Update, results: dict, original_message_id: int):
        """Отправка результатов сканирования телефона"""
        try:
            phone = results['phone']
            text = f"📞 *Результаты разведки номера:* `{phone}`\n"
            text += "═" * 40 + "\n"

            # Информация об операторе
            if results.get('carrier_info'):
                carrier = results['carrier_info']
                text += "\n🏢 *Информация об операторе:*\n"
                text += f"• Страна: `{carrier.get('country', 'Не определено')}`\n"
                text += f"• Оператор: `{carrier.get('carrier', 'Не определено')}`\n"
                text += f"• Тип линии: `{carrier.get('line_type', 'Не определено')}`\n"
                text += f"• Валидность: `{'Да' if carrier.get('valid') else 'Нет'}`\n"

            # Геолокация
            if results.get('geo_info'):
                geo = results['geo_info']
                text += "\n🗺️ *Геолокация:*\n"
                for key, value in geo.items():
                    if value and value != 'Не определено':
                        text += f"• {key}: `{value}`\n"

            # Социальные профили
            if results.get('social_profiles'):
                text += f"\n👥 *Социальные профили ({len(results['social_profiles'])}):*\n"
                for profile in results['social_profiles']:
                    text += f"• `{profile}`\n"

            # Информация о спаме
            if results.get('spam_info'):
                spam = results['spam_info']
                text += f"\n⚠️ *Информация о спаме:*\n"
                text += f"• Уровень риска: `{spam.get('risk_level', 'неизвестно')}`\n"
                text += f"• Жалоб: `{spam.get('spam_reports', 0)}`\n"
                text += f"• Репутация: `{spam.get('reputation', 'неизвестно')}`\n"

            text += f"\n🕐 *Время сканирования:* `{results['timestamp']}`"

            keyboard = [[InlineKeyboardButton("🔄 Новый запрос", callback_data="phone_scan")]]
            reply_markup = InlineKeyboardMarkup(keyboard)

            await self.edit_message(update, text, original_message_id, reply_markup)

        except Exception as e:
            logger.error(f"Error sending phone results: {e}")
            await self.edit_message(update, "❌ Ошибка при форматировании результатов", original_message_id)

    async def send_message(self, update: Update, text: str):
        """Универсальный метод отправки сообщений"""
        if hasattr(update, 'message'):
            return await update.message.reply_text(text, parse_mode='Markdown')
        else:
            return await update.callback_query.message.reply_text(text, parse_mode='Markdown')

    async def edit_message(self, update: Update, text: str, message_id: int, reply_markup=None):
        """Редактирование существующего сообщения"""
        try:
            await self.application.bot.edit_message_text(
                chat_id=update.effective_chat.id,
                message_id=message_id,
                text=text,
                parse_mode='Markdown',
                reply_markup=reply_markup
            )
        except TelegramError as e:
            logger.error(f"Error editing message: {e}")

    def run(self):
        """Запуск бота"""
        logger.info("Бот запущен")
        self.application.run_polling()

# Создание и запуск бота
if __name__ == "__main__":
    bot = TelegramBot()
    bot.run()
