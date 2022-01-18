#!/usr/bin/python3

from dotenv import load_dotenv
from discord.ext import commands
import os, time, asyncio, discord, random

load_dotenv()
TOKEN = os.getenv("DISCORD_TOKEN")

bot = commands.Bot(command_prefix="$")

FLAG = os.getenv("FLAG")
rounds = 50
timeout = 3


async def send_embed(context, title, description, color=0x00FF00):
    embed = discord.Embed(title=title, description=description, color=color)
    await context.send(embed=embed)


@bot.event
async def on_ready():
    print(f"{bot.user.name} has connected to Discord !")


@bot.event
async def on_command_completion(ctx):
    fullCommandName = ctx.command.qualified_name
    split = fullCommandName.split(" ")
    executedCommand = str(split[0])
    guild_name = "Private DM "
    if ctx.guild:
        guild_name = ctx.guild.name
    print(
        f"Executed {executedCommand} command in {guild_name} by {ctx.message.author} (ID: {ctx.message.author.id})"
    )


# The code in this event is executed every time a valid commands catches an error
@bot.event
async def on_command_error(context, error):
    if isinstance(error, commands.errors.PrivateMessageOnly):
        await send_embed(
            context,
            "DMs only",
            "This service is only available in direct messages",
            discord.Colour.gold(),
        )


def generateEquation():
    a = random.randint(1, 2 ** 64)
    b = random.randint(1, 2 ** 64)
    return f"{a} * {b}", a * b


@bot.command(name="start", help="start maths")
async def start(ctx):
    await ctx.trigger_typing()
    await ctx.send("Introducing MathBot! Relive the classic netcat speed challenges but with a Discord bot this time!\nCan you solve all math questions in the required time?")
    time.sleep(2)
    await ctx.trigger_typing()
    for i in range(rounds):
        equation, solution = generateEquation()
        await ctx.send(equation)
        try:
            answer = await bot.wait_for(
                "message",
                timeout=timeout,
                check=lambda message: message.content.isnumeric(),
            )
            if int(answer.content) != solution:
                await send_embed(ctx, "Error", "You better revise your math courses")
                return
        except asyncio.TimeoutError:
            await send_embed(ctx, "Cancelled", ":octagonal_sign: Command cancelled")
            await ctx.send("you took too long to answer.")
            return

    await send_embed(ctx, "Congratulations !!", f"Here's your flag : {FLAG}")


bot.run(TOKEN)
