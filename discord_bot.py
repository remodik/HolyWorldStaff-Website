import discord
from discord.ext import commands
from config import Config
import aiohttp

intents = discord.Intents.all()
bot = commands.Bot(command_prefix='!', intents=intents)

@bot.event
async def on_ready():
    print(f'Бот {bot.user} запущен!')


@bot.command(name="info")
async def staff_info(ctx, member: discord.User = None):
    if member is None:
        member = ctx.author

    try:
        async with aiohttp.ClientSession() as session:

            url = f"http://127.0.0.1:5000/api/staff/{member.id}"
            async with session.get(url, headers={
                'X-API-KEY': '123',
                'User-Agent': 'HolyWorld-Discord-Bot'
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
                    await ctx.send("⚠️ Ошибка доступа к API. Нужно обновить настройки сервера.")
                    print(f"Получен редирект на: {response.url}")

    except aiohttp.ClientError:
        await ctx.send("⌛ Ошибка соединения с сервером API")
    except Exception as e:
        await ctx.send(f"🔴 Произошла ошибка: {str(e)}")


async def send_staff_embed(ctx, member, staff_data):
    role_colors = {
        6: 0x9e6bff, 5: 0x965f7f, 4: 0x00ff22,
        3: 0xff0000, 2: 0x78f4db, 1: 0x40e0d0
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
        6: "Куратор дискорда",
        5: "Зам.Куратора дискорда",
        4: "Гл.Модератор дискорда",
        3: "Ст.Модератор дискорда",
        2: "Модератор дискорда",
        1: "Мл.Модератор дискорда"
    }
    return roles.get(access_level, "Неизвестная роль")


def get_user_access_level(user_id: int) -> int:
    guild = bot.get_guild(Config.DISCORD_GUILD_ID)
    if not guild:
        return 0

    member = guild.get_member(user_id)
    if not member:
        return 0

    if any(role.id == Config.DISCORD_CUR_ROLE_ID for role in member.roles):
        return 6
    elif any(role.id == Config.DISCORD_ZAMCUR_ROLE_ID for role in member.roles):
        return 5
    elif any(role.id == Config.DISCORD_GLMOD_ROLE_ID for role in member.roles):
        return 4
    elif any(role.id == Config.DISCORD_STMOD_ROLE_ID for role in member.roles):
        return 3
    elif any(role.id == Config.DISCORD_MOD_ROLE_ID for role in member.roles):
        return 2
    elif any(role.id == Config.DISCORD_MLMOD_ROLE_ID for role in member.roles):
        return 1
    return 0


def run_bot():
    bot.run(Config.DISCORD_BOT_TOKEN)