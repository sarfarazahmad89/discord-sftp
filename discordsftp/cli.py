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
import cmd
import paramiko
from tabulate import tabulate

from datetime import datetime, timedelta
from colorlog import ColoredFormatter
from dataclasses import dataclass
from discordsftp.upnp import UPNPForward
from logging.handlers import RotatingFileHandler
from discord.ext import tasks
from pathlib import Path
from discordsftp import sshserver
from multiprocessing import Process

from paramiko.client import SSHClient, AutoAddPolicy


PASSLEN = 10
USERNAME = "discordsftp"
DISCORD_STATUS_PING_SEC = 30
SERVER_MSG_PREFIX = "discordsftp-hello"

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
            r = re.match(f"{SERVER_MSG_PREFIX}\s(.*)", message.content)
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
    except FileNotFoundError as e:
        logger.error("Discord token file not found. Quitting!!")
        raise


def _strip_quotes(string):
    if string.startswith('"'):
        return string.lstrip('"').rstrip('"')
    elif string.startswith("'"):
        return string.lstrip("'").rstrip("'")
    else:
        return string


def get_creds():
    username = USERNAME
    passwd = secrets.token_urlsafe(PASSLEN)
    return (username, passwd)


def main():
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    tokenfile = os.path.join(Path.home(), ".discordsftptoken")
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

            class TopLevelCmd(cmd.Cmd):
                intro = "Welcome to discord-sftp client! You can list other active peers here and transfer files over the internet using sftp"
                prompt = ">> "

                def __init__(self, *args, **kwargs):
                    super().__init__(*args, **kwargs)
                    self.remote_server = None
                    self.remote_server_config = {}
                    self.sftp_conn = None
                    self.ssh_c = paramiko.SSHClient()
                    self.ssh_c.set_missing_host_key_policy(AutoAddPolicy)

                def do_list_peers(self, args):
                    """list active discord-sftp peers"""
                    output = [["server", "lastseen", "config"]]
                    for server, msg in client.live_servers.items():
                        output.append([server, str(msg["timestamp"]), str(msg)])
                    print(tabulate(output, headers="firstrow"))

                def do_connect(self, peer):
                    """connect to one of the active peer (from list_peers)"""
                    print(f"Attemping to connect with '{peer}'")
                    self.remote_server = peer
                    if peer not in client.live_servers:
                        return
                    self.remote_server_config = client.live_servers[peer]
                    print(
                        f"Opening SFTP connection to {self.remote_server_config['ip']}:{self.remote_server_config['port']}"
                    )
                    try:
                        self.ssh_c.connect(
                            self.remote_server_config["ip"],
                            self.remote_server_config["port"],
                            username=self.remote_server_config["username"],
                            password=self.remote_server_config["password"],
                            timeout=15,
                        )
                        self.sftp_conn = self.ssh_c.open_sftp()
                    except Exception as e:
                        logger.exception("SFTP connect failed")
                        print("SFTP Connection failed")
                        return

                    sftp_cmd = SFTPClientCmd(self.remote_server, self.ssh_c, self.sftp_conn)
                    sftp_cmd.cmdloop()

                def complete_connect(self, text, line, start_index, end_index):
                    if text:
                        return [server for server in client.live_servers.keys() if server.startswith(text)]
                    else:
                        return list(client.live_servers.keys())

                def do_exit(self, peer):
                    """exit the program"""
                    sys.exit(0)
                    return

                def emptyline(self):
                    return

            class SFTPClientCmd(cmd.Cmd):
                @property
                def prompt(self):
                    return f"(connected - {self.server}) >> "

                def __init__(self, server, ssh_c, sftp_conn, *args, **kwargs):
                    super().__init__(*args, **kwargs)
                    self.ssh_c = ssh_c
                    self.server = server
                    self.sftp_conn = sftp_conn

                def do_ls(self, args):
                    try:
                        listing = self.sftp_conn.listdir(".")
                        print("\n".join(listing))
                    except Exception:
                        print("Error listing files")

                def do_disconnect(self, args):
                    self.sftp_conn.close()
                    self.ssh_c.close()
                    return True

                def do_get(self, remote_file):
                    remote_file = _strip_quotes(remote_file)
                    print(remote_file)
                    try:
                        self.sftp_conn.get(remote_file, remote_file)
                        print(f"{remote_file} downloaded successfully!")
                    except Exception:
                        print(f"Err - {remote_file} : incorrect filename or file no longer exists")

                def do_pwd(self, *args):
                    cwd = self.sftp_conn.getcwd()
                    if not cwd:
                        print("/")
                    print(cwd)

                def do_cd(self, remote_dir):
                    remote_dir = _strip_quotes(remote_dir)
                    cwd = self.sftp_conn.getcwd()
                    if not cwd:
                        dir_to_cd = os.path.join("/", remote_dir)
                    else:
                        dir_to_cd = os.path.join(cwd, remote_dir)

                    try:
                        self.sftp_conn.chdir(dir_to_cd)
                    except Exception:
                        print(f"Directory does not exist {dir_to_cd}")

                def complete_get(self, text, line, start_index, end_index):
                    files = self.sftp_conn.listdir(".")
                    if text:
                        return [file for file in files if file.startswith(text)]
                    else:
                        return list(files)

            TopLevelCmd().cmdloop()


if __name__ == "__main__":
    sys.exit(main())
