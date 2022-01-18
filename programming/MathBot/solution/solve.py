#!/usr/bin/python3
from discord.ext import commands
from dotenv import load_dotenv
import os


# you have to run the solve.py and send as a user $start in the channel


load_dotenv()
TOKEN = os.getenv('DISCORD_TOKEN')

rounds = 50
challengeBotID = 884230099426246707

bot = commands.Bot(command_prefix='!')

def solveEquation(eq):
    return eval(eq)


@bot.event
async def on_ready():
    print(f'{bot.user.name} has connected to Discord !')
    channel = bot.get_channel(806282165406138382)
    msg = await bot.wait_for('message', timeout=10, check=lambda message: message.author.id == challengeBotID)

    for i in range(rounds):
        equation = await bot.wait_for('message', timeout=3, check=lambda message: message.author.id == challengeBotID) 
        solution = solveEquation(equation.content)
        await channel.send(solution)

    flag = await bot.wait_for('message', timeout=3, check=lambda message: message.author.id == challengeBotID )
    print(flag.content)






bot.run(TOKEN)