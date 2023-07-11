#!/usr/bin/env python
import os
import sys
import getpass
import re
import secrets
import logging
import discord
import signal
import threading
import time
import json
import argparse
from tabulate import tabulate

from datetime import datetime, timedelta
from colorlog import ColoredFormatter
from dataclasses import dataclass
from dsfileshare.upnp import UPNPForward
from logging.handlers import RotatingFileHandler
from discord.ext import tasks
from pathlib import Path
from dsfileshare import sshserver

from prompt_toolkit import prompt
from prompt_toolkit.completion import WordCompleter


PASSLEN = 10
USERNAME = "dsfileshare"
DISCORD_STATUS_PING_SEC = 30
SERVER_MSG_PREFIX = "dsfileshare-hello"

logger = logging.getLogger(__name__)


@dataclass
class RemoteServer:
    instance: str
    username: str
    password: str
    port: int
    ip: str

    def __hash__(self):
        return hash(self.instance)


class DiscordClient(discord.Client):
    def __init__(self, config_msg, channel_name, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.config_msg = config_msg
        self.channel_name = channel_name
        self.channel = None
        self.live_servers = {}

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
        self.get_live_servers.start()

    @tasks.loop(seconds=DISCORD_STATUS_PING_SEC)
    async def status_ping(self):
        await self.channel.send(self.config_msg)

    @tasks.loop(seconds=10)
    async def get_live_servers(self):
        live_server_map = {}
        broadcast_messages = []
        messages_after = datetime.now() - timedelta(seconds=180)
        async for message in self.channel.history(after=messages_after):
            r = re.match(rf"{SERVER_MSG_PREFIX}\s(.*)", message.content)
            if r:
                config = r.groups()[0]
                conf = json.loads(config)
                conf["timestamp"] = message.created_at
                broadcast_messages.append(conf)

        for msg in broadcast_messages:
            if msg["instance"] not in live_server_map:
                live_server_map[msg["instance"]] = []
            live_server_map[msg["instance"]].append(msg)

        latest_servers = {}
        for server, msgs in live_server_map.items():
            latest = sorted(msgs, key=lambda x: x["timestamp"], reverse=True)[0]
            latest_servers[server] = latest

        self.live_servers = latest_servers


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
        stream.setFormatter(formatter)
        logging.root.addHandler(stream)


def read_discord_token(tokenfile):
    try:
        with open(tokenfile, "r") as tokenfd:
            token = tokenfd.read()
        return token
    except FileNotFoundError:
        logger.exception("Discord token file not found. Quitting!!")
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
    parser.add_argument(
        "--clientonly",
        help="only run the client, do not run the internal sftpserver or publish messages on discord",
        dest="clientonly",
        action="store_true",
    )
    args = parser.parse_args()

    running_config = {}
    discord_token = read_discord_token(args.tokenfile).strip()
    if args.debuglogs:
        setup_logging(args.logfile, logging.DEBUG)
    else:
        setup_logging(args.logfile, logging.INFO)
    args = parser.parse_args()

    username, passwd = get_creds()
    logger.info("generated creds : {}/{} ".format(username, passwd))

    if not args.clientonly:
        with UPNPForward(tcpport=args.port) as u:
            logger.info("public ipaddress is : {}".format(u.public_ipaddr))
            running_config = {
                "username": username,
                "password": passwd,
                "ip": u.public_ipaddr,
                "port": args.port,
                "instance": getpass.getuser(),
            }
            status_msg = f"{SERVER_MSG_PREFIX} {json.dumps(running_config)}"

            intents = discord.Intents.default()
            intents.message_content = True
            client = DiscordClient(intents=intents, config_msg=status_msg, channel_name=args.dschannel)
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
                if discord_thread.is_alive():
                    logger.info("Waiting 2 seconds for discord thread to terminate")
                    discord_thread.join(0.1)
                if ssh_server_thread.is_alive():
                    logger.info("Waiting 2 seconds for sftpserver thread to terminate")
                    ssh_server_thread.join(0.1)
                sys.exit(0)

            signal.signal(signal.SIGINT, signal_handler)

            # Start the interactive shell
            logger.info("Starting interactive shell now !")

            while True:
                print("Hello from main thread!!")
                time.sleep(10)


if __name__ == "__main__":
    sys.exit(main())
