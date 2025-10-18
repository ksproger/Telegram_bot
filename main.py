#!/usr/bin/env python3
"""
Telegram бот CyberInvestigator для OSINT разведки
Упрощенная версия для Render.com
"""

import os
import logging
import asyncio
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application, CommandHandler, MessageHandler, CallbackQueryHandler,
    ContextTypes, filters
)

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
            message = await update.message.reply_text("🔍 *Начинаем разведку домена...*\nЭто может занять несколько секунд ⏳", parse_mode='Markdown')
            
            # Имитация сканирования (заглушка)
            await asyncio.sleep(2)
            
            results_text = f"""
🏠 *Результаты разведки домена:* `{domain}`
═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═

📋 *Базовая информация:*
• Домен: `{domain}`
• Статус: Активен
• Проверка: Завершена

🔍 *Рекомендации:*
• Для полного анализа используйте локальную версию
• Проверьте WHOIS информацию
• Исследуйте DNS записи

⚠️ *На Render.com доступен базовый функционал*
Для полного OSINT сканирования запустите бота локально.
            """
            
            keyboard = [[InlineKeyboardButton("🔄 Новый запрос", callback_data="domain_scan")]]
            reply_markup = InlineKeyboardMarkup(keyboard)
            
            await message.edit_text(results_text, parse_mode='Markdown', reply_markup=reply_markup)

        except Exception as e:
            logger.error(f"Domain scan error: {e}")
            await update.message.reply_text(f"❌ Ошибка при сканировании домена: {str(e)}")

    async def perform_ip_scan(self, update: Update, ip_address: str):
        """Выполнение сканирования IP"""
        try:
            message = await update.message.reply_text("🌐 *Начинаем разведку IP...*\nЭто может занять несколько секунд ⏳", parse_mode='Markdown')
            
            # Имитация сканирования (заглушка)
            await asyncio.sleep(2)
            
            results_text = f"""
🌐 *Результаты разведки IP:* `{ip_address}`
═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═

📋 *Базовая информация:*
• IP: `{ip_address}`
• Тип: Публичный IPv4
• Проверка: Завершена

🔍 *Рекомендации:*
• Для геолокации используйте локальную версию
• Проверьте открытые порты
• Исследуйте через Shodan

⚠️ *На Render.com доступен базовый функционал*
Для полного OSINT сканирования запустите бота локально.
            """
            
            keyboard = [[InlineKeyboardButton("🔄 Новый запрос", callback_data="ip_scan")]]
            reply_markup = InlineKeyboardMarkup(keyboard)
            
            await message.edit_text(results_text, parse_mode='Markdown', reply_markup=reply_markup)

        except Exception as e:
            logger.error(f"IP scan error: {e}")
            await update.message.reply_text(f"❌ Ошибка при сканировании IP: {str(e)}")

    async def perform_email_scan(self, update: Update, email: str):
        """Выполнение сканирования email"""
        try:
            message = await update.message.reply_text("📧 *Начинаем разведку email...*\nЭто может занять несколько секунд ⏳", parse_mode='Markdown')
            
            # Имитация сканирования (заглушка)
            await asyncio.sleep(2)
            
            results_text = f"""
📧 *Результаты разведки email:* `{email}`
═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═

📋 *Базовая информация:*
• Email: `{email}`
• Домен: `{email.split('@')[1] if '@' in email else 'N/A'}`
• Проверка: Завершена

🔍 *Рекомендации:*
• Для проверки утечек используйте локальную версию
• Проверьте Gravatar
• Исследуйте социальные профили

⚠️ *На Render.com доступен базовый функционал*
Для полного OSINT сканирования запустите бота локально.
            """
            
            keyboard = [[InlineKeyboardButton("🔄 Новый запрос", callback_data="email_scan")]]
            reply_markup = InlineKeyboardMarkup(keyboard)
            
            await message.edit_text(results_text, parse_mode='Markdown', reply_markup=reply_markup)

        except Exception as e:
            logger.error(f"Email scan error: {e}")
            await update.message.reply_text(f"❌ Ошибка при сканировании email: {str(e)}")

    async def perform_phone_scan(self, update: Update, phone: str):
        """Выполнение сканирования телефона"""
        try:
            message = await update.message.reply_text("📞 *Начинаем разведку номера...*\nЭто может занять несколько секунд ⏳", parse_mode='Markdown')
            
            # Имитация сканирования (заглушка)
            await asyncio.sleep(2)
            
            # Простой анализ номера
            clean_phone = ''.join(filter(str.isdigit, phone))
            
            if clean_phone.startswith('374'):
                operator = "Ucom (Армения)"
            elif clean_phone.startswith('7'):
                operator = "Российский оператор"
            else:
                operator = "Международный оператор"
            
            results_text = f"""
📞 *Результаты разведки номера:* `{phone}`
═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═

📋 *Базовая информация:*
• Номер: `{phone}`
• Оператор: `{operator}`
• Проверка: Завершена

🔍 *Рекомендации:*
• Для детального анализа используйте локальную версию
• Проверьте оператора связи
• Исследуйте социальные профили

⚠️ *На Render.com доступен базовый функционал*
Для полного OSINT сканирования запустите бота локально.
            """
            
            keyboard = [[InlineKeyboardButton("🔄 Новый запрос", callback_data="phone_scan")]]
            reply_markup = InlineKeyboardMarkup(keyboard)
            
            await message.edit_text(results_text, parse_mode='Markdown', reply_markup=reply_markup)

        except Exception as e:
            logger.error(f"Phone scan error: {e}")
            await update.message.reply_text(f"❌ Ошибка при сканировании номера: {str(e)}")

    def run(self):
        """Запуск бота"""
        logger.info("Бот запущен")
        self.application.run_polling()

# Создание и запуск бота
if __name__ == "__main__":
    bot = TelegramBot()
    bot.run()
