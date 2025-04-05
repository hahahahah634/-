import telebot
import base64
import requests
import threading
import io
import time

from urllib.parse import urlparse
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
from PIL import Image

API_KEY = '63bde2892bef6c2f6e7bfd5cdbe17c62104f433b320670c374854b1a88255c6f'
BOT_TOKEN = '8152524170:AAGnd3ZifJmhwIBImJG0_WaRBNuk7LK7NXQ'

bot = telebot.TeleBot(BOT_TOKEN)

user_read_message = {}
last_check_time = {}

def normalize_url(url):
    return urlparse(url, scheme="https").geturl()

def check_url(url, chat_id):
    bot.send_message(chat_id, "🔄 Обрабатываю запрос, пожалуйста, подождите...")

    url = normalize_url(url)
    headers = { 'x-apikey': API_KEY }
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    r = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers)

    if r.status_code == 200:
        data = r.json()['data']['attributes']['last_analysis_stats']
        total = sum(data.values())

        result = f"""✅ Безопасных: {data['harmless']}
❌ Опасных: {data['malicious']}
⚠️ Подозрительных: {data['suspicious']}
🔶 Неизвестных: {data['undetected']}

🔍 Полная статистика:
Проверено антивирусами: {total}
Подтверждено безопасных: {data['harmless']}
Подтверждено опасных: {data['malicious']}
Подтверждено подозрительных: {data['suspicious']}
Подтверждено не обнаруженных: {data['undetected']}
"""
    else:
        result = "⚠️ Ссылка не найдена в базе VirusTotal."

    bot.send_message(chat_id, "✅ Запрос обработан, отправляю результаты...")
    bot.send_message(chat_id, "📸 Отправляю скриншот сайта...")
    bot.send_message(chat_id, result)
    bot.send_photo(chat_id, capture_screenshot(url))

def capture_screenshot(url):
    options = Options()
    options.add_argument("--headless")
    options.add_argument("--disable-gpu")
    options.add_argument("--no-sandbox")

    driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)
    driver.get(url)

    screenshot = driver.get_screenshot_as_png()
    driver.quit()

    return io.BytesIO(screenshot)

@bot.message_handler(commands=['start'])
def start(message):
    user_read_message[message.chat.id] = False

    markup = telebot.types.InlineKeyboardMarkup()
    btn_check = telebot.types.InlineKeyboardButton("Проверить ссылку", callback_data="check")
    btn_help = telebot.types.InlineKeyboardButton("Помощь", callback_data="help")
    btn_read = telebot.types.InlineKeyboardButton("Я прочитал", callback_data="read")

    markup.add(btn_check)
    markup.add(btn_help)
    markup.add(btn_read)

    bot.send_message(
        message.chat.id,
        "Привет, я бот, который проверяет подозрительные ссылки через VirusTotal.",
        reply_markup=markup
    )

@bot.callback_query_handler(func=lambda call: True)
def handle_callback(call):
    chat_id = call.message.chat.id

    if call.data == "read":
        user_read_message[chat_id] = True
        bot.edit_message_reply_markup(chat_id, call.message.message_id, reply_markup=None)
        bot.send_message(chat_id, "Теперь ты можешь использовать бота!")

        # Сразу после нажатия кнопки "Я прочитал", показываем основные кнопки
        markup = telebot.types.InlineKeyboardMarkup()
        btn_check = telebot.types.InlineKeyboardButton("Проверить ссылку", callback_data="check")
        btn_help = telebot.types.InlineKeyboardButton("Помощь", callback_data="help")
        markup.add(btn_check, btn_help)
        bot.send_message(chat_id, "Теперь ты можешь использовать следующие команды:", reply_markup=markup)

    elif call.data == "help":
        if not user_read_message.get(chat_id, False):
            bot.send_message(chat_id, "⚠️ Пожалуйста, нажми 'Я прочитал' перед использованием.")
            return

        help_text = """
📌 Доступные команды:

/start - Перезапуск меню
/help - Помощь по командам
/check <ссылка> - Проверка URL
        """
        bot.send_message(chat_id, help_text)
    elif call.data == "check":
        if not user_read_message.get(chat_id, False):
            bot.send_message(chat_id, "⚠️ Пожалуйста, нажми 'Я прочитал' перед использованием.")
            return

        markup = telebot.types.ForceReply(selective=True)
        bot.send_message(chat_id, "⚠️ Введите ссылку для проверки:", reply_markup=markup)

@bot.message_handler(commands=['check'])
def check_command(message):
    if not user_read_message.get(message.chat.id, False):
        bot.send_message(message.chat.id, "⚠️ Пожалуйста, нажми 'Я прочитал' перед использованием.")
        return

    current_time = time.time()
    last_time = last_check_time.get(message.chat.id, 0)

    if current_time - last_time < 60:
        bot.send_message(message.chat.id, "⚠️ Не спамь! Используй /check не чаще раза в минуту.")
        return

    last_check_time[message.chat.id] = current_time

    markup = telebot.types.ForceReply(selective=True)
    bot.send_message(message.chat.id, "⚠️ Введите ссылку для проверки:", reply_markup=markup)

@bot.message_handler(commands=['help'])
def help_command(message):
    if not user_read_message.get(message.chat.id, False):
        bot.send_message(message.chat.id, "⚠️ Пожалуйста, нажми 'Я прочитал' перед использованием.")
        return

    help_text = """
📌 Доступные команды:

/start - Перезапуск меню
/help - Помощь по командам
/check <ссылка> - Проверка URL
    """
    bot.send_message(message.chat.id, help_text)

@bot.message_handler(func=lambda message: message.text.startswith("http"))
def handle_url(message):
    if not user_read_message.get(message.chat.id, False):
        bot.send_message(message.chat.id, "⚠️ Пожалуйста, нажми 'Я прочитал' перед использованием.")
        return

    threading.Thread(target=check_url, args=(message.text, message.chat.id)).start()

@bot.message_handler(func=lambda message: True)
def handle_unknown(message):
    if not user_read_message.get(message.chat.id, False):
        bot.send_message(message.chat.id, "⚠️ Пожалуйста, нажми 'Я прочитал' перед использованием.")
        return

    bot.send_message(message.chat.id, "Я не понял твою команду. Введи /help чтобы увидеть список.")

bot.polling(none_stop=True)