import discord
import asyncio

intents = discord.Intents.default()
intents.message_content = True

client = discord.Client(intents=intents)
# TODO: THis secret should be safe? somehow?
token = "MTEyNzE1MzgwNjcxOTg0NDM3Mw.GB2uCV.lX9WTJ5ZneGFl1PUlKYDqCxl_TaWF3FeQ8bls8"


@client.event
async def on_ready():
    print(f"We have logged in as {client.user}")


@client.event
async def on_message(message):
    import ipdb

    ipdb.set_trace()
    print("{}: {}".format(message.author.name, message.content))


async def heartbeat():
    await client.wait_until_ready()
    channel = client.get_channel(id=1127155731146223659)
    while not client.is_closed():
        await channel.send("Hello from bot!")
        await asyncio.sleep(10)


client.loop.create_task(heartbeat())
client.run(token)
