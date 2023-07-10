#!/usr/bin/env python
import os
import sys
import secrets
import logging
import discord
import signal
import threading
import time
import argparse

from colorlog import ColoredFormatter
from dsfileshare.upnp import UPNPForward
from logging.handlers import RotatingFileHandler
from discord.ext import tasks
from pathlib import Path
from dsfileshare import sshserver
from multiprocessing import Process

PASSLEN = 10
USERNAME = "dsfileshare"
DISCORD_STATUS_PING_SEC = 30

logger = logging.getLogger(__name__)


class DiscordClient(discord.Client):
    def __init__(self, config_msg, channel_name, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.config_msg = config_msg
        self.channel_name = channel_name
        self.channel = None

    async def on_ready(self):
        logger.info(f"successfully logged into discord as {self.user}")
        if not self.channel:
            for server in self.guilds:
                for channel in server.channels:
                    if str(channel.type) == "text" and str(channel.name) == self.channel_name:
                        self.channel = channel
        if not self.channel:
            logger.error(
                "Could not identify discord channel to publish updates to. Will not publish updates on discord"
            )
            return
        self.status_ping.start()

    @tasks.loop(seconds=DISCORD_STATUS_PING_SEC)
    async def status_ping(self):
        await self.channel.send(self.config_msg)


def setup_logging(logfile=None, loglevel=logging.INFO):
    formatter = ColoredFormatter(
        "%(log_color)s%(asctime)s | %(log_color)s%(name)s |  %(log_color)s%(levelname)-8s%(reset)s | %(log_color)s%(message)s%(reset)s"
    )
    logging.root.setLevel(loglevel)
    if logfile:
        handler = RotatingFileHandler(logfile, maxBytes=20000)
        handler.setFormatter(formatter)
        logging.root.addHandler(handler)
    else:
        stream = logging.StreamHandler()
        stream.setLevel(logging.DEBUG)
        stream.setFormatter(formatter)
        logging.root.addHandler(stream)


def read_discord_token(tokenfile):
    try:
        with open(tokenfile, "r") as tokenfd:
            token = tokenfd.read()
        return token
    except FileNotFoundError as e:
        logger.error("Discord token file not found. Quitting!!")
        raise


def get_creds():
    username = USERNAME
    passwd = secrets.token_urlsafe(PASSLEN)
    return (username, passwd)


def main():
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    tokenfile = os.path.join(Path.home(), ".dsfilesharetoken")
    parser.add_argument(
        "--channel",
        "-c",
        help="the discord `text` channel to listen/publish peer discovery messages on",
        dest="dschannel",
        default="general",
    )
    parser.add_argument(
        "--tokenfile", "-t", help="file to read discord auth token from", default=tokenfile, dest="tokenfile"
    )
    parser.add_argument(
        "--logfile",
        "-l",
        help="file to write application logs into (otherwise logs are displayed on stdout)",
        dest="logfile",
    )
    parser.add_argument("--port", "-p", help="the tcp port to start built-in sshd on", default=2200, type=int)
    parser.add_argument("--debug", "-d", help="log debug messages", dest="debuglogs", action="store_true")
    args = parser.parse_args()

    discord_token = read_discord_token(args.tokenfile).strip()

    running_config = {}

    if args.debuglogs:
        setup_logging(args.logfile, logging.DEBUG)
    else:
        setup_logging(args.logfile, logging.INFO)

    username, passwd = get_creds()
    logger.info("generated creds : {}/{} ".format(username, passwd))

    with UPNPForward(tcpport=args.port) as u:
        logger.info("public ipaddress is : {}".format(u.public_ipaddr))
        running_config = {"username": username, "password": passwd, "ip": u.public_ipaddr, "port": args.port}

        client = DiscordClient(
            intents=discord.Intents.default(), config_msg=running_config, channel_name=args.dschannel
        )
        discord_thread = threading.Thread(
            target=client.run,
            args=(discord_token,),
            kwargs={
                "log_handler": None,
            },
            daemon=True,
        )
        discord_thread.start()

        ssh_server_thread = threading.Thread(
            target=sshserver.start_ssh_server, args=(username, passwd, args.port), daemon=True
        )
        ssh_server_thread.start()

        def signal_handler(signum, frame):
            logger.info("Received sigint/sigterm. Stopping..")
            logger.info("Waiting 5 seconds for discord thread to terminate")
            discord_thread.join(5)
            logger.info("Waiting 5 seconds for sftpserver thread to terminate")
            ssh_server_thread.join(5)
            sys.exit(0)

        signal.signal(signal.SIGINT, signal_handler)

        while True:
            logger.info("Hello from main loop!")
            time.sleep(10)


if __name__ == "__main__":
    sys.exit(main())
