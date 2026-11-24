import os, asyncio
from dotenv import load_dotenv
from aiogram import Bot, Dispatcher
from aiogram.filters import CommandStart
from aiogram.types import Message, InlineKeyboardMarkup, InlineKeyboardButton, WebAppInfo

load_dotenv()
TOKEN = os.getenv("BOT_TOKEN")
WEBAPP_URL = os.getenv("WEBAPP_URL")
dp = Dispatcher()

@dp.message(CommandStart())
async def start(message: Message):
    if not WEBAPP_URL or not WEBAPP_URL.startswith("https://"):
        await message.answer("SHADOW OSINT: сначала укажите WEBAPP_URL с HTTPS в файле .env.")
        return
    keyboard = InlineKeyboardMarkup(inline_keyboard=[[
        InlineKeyboardButton(text="ОТКРЫТЬ SHADOW OSINT", web_app=WebAppInfo(url=WEBAPP_URL))
    ]])
    await message.answer(
        "🕶 SHADOW OSINT\\n\\nЧёрно-белая OSINT-панель. Используйте только открытые источники и данные, на проверку которых у вас есть право.",
        reply_markup=keyboard
    )

async def main():
    if not TOKEN:
        raise RuntimeError("Добавьте BOT_TOKEN в .env")
    bot = Bot(TOKEN)
    await dp.start_polling(bot)

if __name__ == "__main__":
    asyncio.run(main())
