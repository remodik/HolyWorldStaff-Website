import asyncio
import discord
from discord.ext import commands
from config import Config
import aiohttp
import os
import logging
import json

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('staff_bot.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

BOT_API_SECRET = os.getenv("BOT_API_SECRET")
API_URL = "http://127.0.0.1:5000"
intents = discord.Intents.all()
bot = commands.Bot(command_prefix='!', intents=intents)

bot_jwt = None


async def get_bot_token():
    global bot_jwt
    try:
        logger.info("Попытка получения JWT токена для бота")

        async with aiohttp.ClientSession() as session:
            url = f"{API_URL}/api/auth/bot"
            async with session.post(url, json={"secret": BOT_API_SECRET}) as resp:

                if resp.status == 200:
                    data = await resp.json()
                    if data.get("success"):
                        bot_jwt = data["token"]
                        logger.info("JWT токен бота успешно получен")
                    else:
                        logger.error("API вернуло ошибку: %s", data)
                        return False
                else:
                    logger.error("HTTP ошибка: %s %s", resp.status, await resp.text())
                    return False

        return True

    except aiohttp.ClientError as e:
        logger.error("Ошибка сети при получении токена: %s", e, exc_info=True)
        return False
    except json.JSONDecodeError as e:
        logger.error("Ошибка парсинга JSON ответа: %s", e, exc_info=True)
        return False
    except Exception as e:
        logger.error("Неожиданная ошибка при получении токена: %s", e, exc_info=True)
        return False


async def periodic_sync():
    while True:
        await asyncio.sleep(3600)

        try:
            guild = bot.get_guild(Config.DISCORD_GUILD_ID)
            if guild:
                for member in guild.members:
                    await update_user_access_level(member.id)
                    await asyncio.sleep(0.1)

        except Exception:
            logger.exception(f"Ошибка при периодической синхронизации")


async def token_refresh_task():
    while True:
        await asyncio.sleep(3600)
        await get_bot_token()


async def update_user_access_level(user_id):
    try:
        access_level = get_user_access_level(user_id)

        async with aiohttp.ClientSession() as session:
            url = f"{API_URL}/api/update-access-level"
            headers = {
                'Authorization': f'Bearer {bot_jwt}',
                'Content-Type': 'application/json'
            }
            data = {
                'user_id': user_id,
                'access_level': access_level
            }

            async with session.post(url, headers=headers, json=data) as response:
                if response.status == 200:
                    data = await response.json()
                    if data.get('success'):
                        logger.info(f"Уровень доступа пользователя {user_id} обновлен: {access_level}")
                    else:
                        logger.error(f"Ошибка обновления уровня доступа: {data.get('error')}")
                else:
                    logger.error(f"Ошибка HTTP при обновлении уровня доступа: {response.status}")

    except Exception:
        logger.exception("Ошибка при обновлении уровня доступа")


@bot.event
async def on_ready():
    await get_bot_token()
    logger.info(f'Бот {bot.user} запущен!')

    bot.loop.create_task(token_refresh_task())
    bot.loop.create_task(periodic_sync())


@bot.event
async def on_member_update(before, after):
    if before.roles != after.roles:
        await update_user_access_level(after.id)


@bot.event
async def on_member_join(member):
    await update_user_access_level(member.id)

@bot.event
async def on_member_remove(member):
    await update_user_access_level(member.id)


@bot.event
async def on_command_error(ctx, error):
    if isinstance(error, commands.CommandNotFound):
        return


async def ensure_valid_token():
    global bot_jwt
    if not bot_jwt:
        await get_bot_token()


@bot.command(name="info")
async def staff_info(ctx, member: discord.User = None):
    await ensure_valid_token()

    if member is None:
        member = ctx.author

    headers = {
        'Authorization': f'Bearer {bot_jwt}',
        'User-Agent': 'HolyWorld-Discord-Bot',
        'Content-Type': 'application/json'
    }

    try:
        async with aiohttp.ClientSession() as session:
            url = f"{API_URL}/api/staff/{member.id}"

            async with session.get(url, headers=headers) as response:
                if response.status == 401:
                    logger.warning("JWT Токен истек, пытаемся обновить...")
                    await get_bot_token()
                    headers['Authorization'] = f'Bearer {bot_jwt}'

                    async with session.get(url, headers=headers) as retry_response:
                        await process_response(ctx, member, retry_response)
                else:
                    await process_response(ctx, member, response)

    except aiohttp.ClientError:
        await ctx.reply(
            embed=discord.Embed(
                description="⌛ Ошибка соединения с сервером API",
                color=discord.Color.orange()
            )
        )
    except Exception:
        logger.exception(f"Ошибка в команде info")
        await ctx.reply(
            embed=discord.Embed(
                description="❌ Произошла внутренняя ошибка",
                color=discord.Color.red()
            )
        )


async def process_response(ctx, member, response):
    try:
        if response.status == 200:
            if response.content_type == 'application/json':
                data = await response.json()

                if data.get('success'):
                    staff_data = data['member']
                    await send_staff_embed(ctx, member, staff_data)
                else:
                    await ctx.reply(
                        embed=discord.Embed(
                            description=f"❌ {member.display_name} не найден в базе персонала.",
                            color=discord.Color.red()
                        )
                    )
            else:
                await ctx.reply(
                    embed=discord.Embed(
                        description="⚠️ Неверный формат ответа от API",
                        color=discord.Color.orange()
                    )
                )
        elif response.status == 404:
            await ctx.reply(
                embed=discord.Embed(
                    description=f"❌ {member.display_name} не найден в базе персонала.",
                    color=discord.Color.red()
                )
            )
        elif response.status == 401:
            await ctx.reply(
                embed=discord.Embed(
                    description="🔐 Ошибка авторизации. Попробуйте позже.",
                    color=discord.Color.red()
                )
            )
        else:
            logger.error(f"API вернуло статус: {response.status}")
            await ctx.reply(
                embed=discord.Embed(
                    description="⚠️ Ошибка сервера API",
                    color=discord.Color.red()
                )
            )

    except Exception:
        logger.exception(f"Ошибка при обработке ответа")
        await ctx.reply(
            embed=discord.Embed(
                description="❌ Ошибка обработки данных",
                color=discord.Color.red()
            )
        )


async def send_staff_embed(ctx, member, staff_data):
    role_colors = {
        9: 0x4cadd0, 8: 0x9e6bff, 7: 0x965f7f, 6: 0x00ff22, 5: 0xff0000,
        4: discord.Color.orange(), 3: 0x40e0d0, 2: 0x54b3ca, 1: discord.Color.orange(),
    }

    embed_color = role_colors.get(staff_data['access_level'], 0x000000)
    data_name = staff_data.get('nickname') if staff_data.get('nickname') else member.name

    embed = discord.Embed(
        title=f"Информация о {data_name}",
        color=embed_color
    )

    basic_info = f"**Дискорд:** `{member.name}`"
    if staff_data.get('vk_link'):
        basic_info += f"\n**ВК:** `{staff_data['vk_link']}`"
    if staff_data.get('salary'):
        basic_info += f"\n**Зарплата:** `{staff_data['salary']}`"

    async with aiohttp.ClientSession() as session:
        tasks_url = f"http://127.0.0.1:5000/api/staff/{member.id}/tasks"
        async with session.get(tasks_url, headers={
            'Authorization': f'Bearer {bot_jwt}',
            'User-Agent': 'HolyWorld-Discord-Bot',
            'Content-Type': 'application/json'
        }) as response:
            if response.status == 200:
                tasks_data = await response.json()
                if tasks_data.get('success'):
                    tasks_info = f"**Выполнено заданий:** `{tasks_data['tasks_completed']}`"
                    basic_info += f"\n{tasks_info}"

    embed.add_field(
        name="**Основная информация**",
        value=basic_info,
        inline=False
    )

    position_info = f"**Должность:** `{get_role_name(staff_data['access_level'])}`"
    if staff_data.get('join_date'):
        position_info += f"\n**На должности:** `{staff_data['join_date']}`"

    vacation_status = "Не в отпуске"
    if staff_data.get('vacation_date'):
        vacation_status = f"До {staff_data['vacation_date']}"
    position_info += f"\n**Отпуск:** `{vacation_status}`"

    if staff_data.get('warnings'):
        warns = staff_data['warnings'].split('/')
        position_info += f"\n**Выговоры:** `{warns[0]}/2` `{warns[1]}/3`"

    embed.add_field(
        name="**Должностная информация**",
        value=position_info,
        inline=False
    )

    avatar_url = staff_data.get('avatar') or getattr(member.avatar, 'url', None)
    if avatar_url:
        embed.set_thumbnail(url=avatar_url)

    embed.set_footer(text=f"ID: {member.id}")

    await ctx.send(embed=embed)


def get_role_name(access_level):
    roles = {
        9: "Администратор",
        8: "Куратор дискорда",
        7: "Зам.Куратора дискорда",
        6: "Гл.Модератор дискорда",
        5: "Ст.Модератор дискорда",
        4: "Следящий за хелперами",
        3: "Модератор дискорда",
        2: "Мл.Модератор дискорда",
        1: "Хелпер дискорда"
    }
    return roles.get(access_level, "Неизвестная роль")


def get_user_access_level(user_id: int) -> int:
    try:
        guild = bot.get_guild(Config.DISCORD_GUILD_ID)
        if not guild:
            return 0

        member = guild.get_member(user_id)
        if not member:
            return 0

        if any(role.id == Config.DISCORD_ADMIN_ROLE_ID for role in member.roles):
            return 9
        elif any(role.id == Config.DISCORD_CUR_ROLE_ID for role in member.roles):
            return 8
        elif any(role.id == Config.DISCORD_ZAMCUR_ROLE_ID for role in member.roles):
            return 7
        elif any(role.id == Config.DISCORD_GLMOD_ROLE_ID for role in member.roles):
            return 6
        elif any(role.id == Config.DISCORD_STMOD_ROLE_ID for role in member.roles):
            return 5
        elif any(role.id == Config.DISCORD_CHECKHELPERS_ROLE_ID for role in member.roles):
            return 4
        elif any(role.id == Config.DISCORD_MOD_ROLE_ID for role in member.roles):
            return 3
        elif any(role.id == Config.DISCORD_MLMOD_ROLE_ID for role in member.roles):
            return 2
        elif any(role.id == Config.DISCORD_HELPER_ROLE_ID for role in member.roles):
            return 1
        return 0

    except Exception:
        logger.exception(f"Ошибка при получении уровня доступа")
        return 0


async def add_staff_roles(user_id):
    try:
        guild = bot.get_guild(1315002924048318506)
        member = guild.get_member(int(user_id))

        if member:
            staff_roles = [1398628811586801754, 1315002924048318511]

            for role_id in staff_roles:
                role = guild.get_role(role_id)
                if role and role not in member.roles:
                    await member.add_roles(role)
                    logger.info(f"Выдана роль {role.name} пользователю {member.name}")

            return True
        return False
    except Exception:
        logger.exception("Ошибка при выдаче ролей")
        return False


def run_bot():
    bot.run(Config.DISCORD_BOT_TOKEN)