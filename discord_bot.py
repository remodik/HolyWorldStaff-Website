import discord
from discord.ext import commands
from config import Config
import aiohttp
import os

BOT_API_SECRET = os.getenv("BOT_API_SECRET")
API_URL = "http://127.0.0.1:5000"
intents = discord.Intents.all()
bot = commands.Bot(command_prefix='!', intents=intents)


bot_jwt = None

async def get_bot_token():
    global bot_jwt
    async with aiohttp.ClientSession() as session:
        url = f"{API_URL}/api/auth/bot"
        async with session.post(url, json={"secret": BOT_API_SECRET}) as resp:
            data = await resp.json()
            if data.get("success"):
                bot_jwt = data["token"]
            else:
                print("Не удалось получить токен для бота:", data)


@bot.event
async def on_ready():
    await get_bot_token()
    print(f'Бот {bot.user} запущен!')
    print(f'JWT: {bot_jwt}')


@bot.command(name="info")
async def staff_info(ctx, member: discord.User = None):
    if member is None:
        member = ctx.author

    try:
        async with aiohttp.ClientSession() as session:
            url = f"{API_URL}/api/staff/{member.id}"
            async with session.get(url, headers={
                'Authorization': f'Bearer {bot_jwt}',
                'User-Agent': 'HolyWorld-Discord-Bot',
                'Content-Type': 'application/json'
            }) as response:
                if response.content_type == 'application/json':
                    data = await response.json()

                    if data.get('success'):
                        staff_data = data['member']
                        print(staff_data)
                        await send_staff_embed(ctx, member, staff_data)
                    else:
                        await ctx.send(f"❌ {member.display_name} не найден в базе стаффа")
                else:
                    await ctx.send(
                        embed=discord.Embed(
                            title="",
                            description="⚠️ Ошибка доступа к API.",
                            color=discord.Color.red()
                        )
                    )
                    print(f"Получен редирект на: {response.url}")

    except aiohttp.ClientError:
        await ctx.send("⌛ Ошибка соединения с сервером API")
    except Exception as e:
        await ctx.send(f"🔴 Произошла ошибка: {str(e)}")


async def send_staff_embed(ctx, member, staff_data):
    role_colors = {
        9: 0x4cadd0,
        8: 0x9e6bff, 7: 0x965f7f, 6: 0x00ff22, 5: 0xff0000,
        4: discord.Color.orange(), 3: 0x40e0d0, 2: 0x54b3ca, 1: discord.Color.orange(),
    }

    embed_color = role_colors.get(staff_data['access_level'], 0x000000)

    embed = discord.Embed(
        title=f"Информация о {staff_data.get('nickname', member.display_name)}",
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
        vacation_status = f"До `{staff_data['vacation_date']}`"
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
                    print(f"Выдана роль {role.name} пользователю {member.name}")

            return True
        return False
    except Exception:
        print("Ошибка при выдаче ролей")
        return False


def run_bot():
    bot.run(Config.DISCORD_BOT_TOKEN)