#!/usr/bin/env python
import getpass
import sys
import secrets
import logging
import discord
import threading
import time
import argparse

from colorlog import ColoredFormatter
from dsfileshare.upnp import UPNPForward
from discord.ext import tasks

PASSLEN = 10
PORT = 2200
DISCORD_STATUS_PING_SEC = 10
DISCORD_TOKEN = 'MTEyNzE1MzgwNjcxOTg0NDM3Mw.GB2uCV.lX9WTJ5ZneGFl1PUlKYDqCxl_TaWF3FeQ8bls8'
CHANNEL_NAME = 'general'


logger = logging.getLogger(__name__)

class DiscordClient(discord.Client):
    def __init__(self, config_msg, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.config_msg = config_msg
        self.channel_id = None

    async def setup_hook(self) -> None:
        self.status_ping.start()

    async def on_ready(self):
        logger.info(f'successfully logged into discord as {self.user}')

    @tasks.loop(seconds=DISCORD_STATUS_PING_SEC)
    async def status_ping(self):
        await self.wait_until_ready()
        logger.info("sending discord config message")
        if not self.channel_id:
            for server in self.guilds:
                for channel in server.channels:
                    if str(channel.type) == 'text' and str(channel.name) == CHANNEL_NAME:
                        self.channel_id = channel.id

        channel = self.get_channel(self.channel_id)
        if not self.config_msg:
            raise ValueError("Empty config. cannot publish to discord")
        await channel.send(self.config_msg)



def setup_logging(loglevel=logging.INFO):
    formatter = ColoredFormatter(" %(log_color)s%(asctime)s | %(log_color)s%(name)s |  %(log_color)s%(levelname)-8s%(reset)s | %(log_color)s%(message)s%(reset)s")
    stream = logging.StreamHandler()
    stream.setLevel(logging.DEBUG)
    stream.setFormatter(formatter)
    logging.root.setLevel(loglevel)
    logging.root.addHandler(stream)


def get_creds():
    username = getpass.getuser()
    passwd = secrets.token_urlsafe(PASSLEN)
    return (username, passwd)


def main():
    running_config = {}

    setup_logging()

    username, passwd = get_creds()
    logger.info('generated creds : {}/{} '.format(username, passwd))

    with UPNPForward(tcpport=PORT) as u:
        logger.info("public ipaddress is : {}".format(u.public_ipaddr))
        running_config = {'username': username, 'password': passwd, 'ip': u.public_ipaddr, 'port': PORT}

        client = DiscordClient(intents=discord.Intents.default(), config_msg=running_config)
        discord_thread = threading.Thread(target=client.run, args=(DISCORD_TOKEN,), daemon=True)
        discord_thread.start()


        # Advertise the details on discord.
        while True:
            print("Hello from main loop!")
            time.sleep(10)

        # TODO: Start SSHD server.
        


if __name__ == "__main__":
    sys.exit(main())
