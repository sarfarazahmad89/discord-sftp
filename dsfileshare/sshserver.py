import paramiko
import base64
import os
import sys
import socket
import traceback
import threading
import logging

from base64 import decodebytes
from binascii import hexlify
from paramiko.util import b, u

logger = logging.getLogger(__name__)

host_key = paramiko.RSAKey.generate(2048)
logger.info("HostKeyFprint: {}".format(u(hexlify(host_key.get_fingerprint()))))


class Server(paramiko.ServerInterface):
    def __init__(self, username, password):
        self.event = threading.Event()
        self.username = username
        self.password = password

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        if (username == self.username) and (password == self.password):
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def enable_auth_gssapi(self):
        return False

    def get_allowed_auths(self, username):
        return "password,publickey"

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True


def start_ssh_server(username, password, port=2200):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("", port))
    except Exception as e:
        logger.error(f"failed to bind on port {port}")
        traceback.print_exc()
        return

    try:
        sock.listen(100)
        logger.info("listening for connection ...")
        while True:
            conn, addr = sock.accept()
            logger.info("Received connection from {}".format(addr))
            t = threading.Thread(target=process_connection, args=(conn, addr, username, password), daemon=True)
            t.start()
    except Exception as e:
        logger.error("*** listen/accept failed: " + str(e))
        traceback.print_exc()


def process_connection(conn, addr, username, password):
    try:
        t = paramiko.Transport(conn, gss_kex=False)
        t.set_gss_host(socket.getfqdn(""))
        try:
            t.load_server_moduli()
        except:
            logger.warning("(Failed to load moduli -- gex will be unsupported.)")
            raise

        t.add_server_key(host_key)
        server = Server(username=username, password=password)

        try:
            t.start_server(server=server)
        except paramiko.SSHException:
            logger.error("*** SSH negotiation failed.")

        # wait for auth
        chan = t.accept(20)
        if chan is None:
            logger.warning("*** No channel was requested by the client.")
            return
        logger.info("client authenticated successfully !")

        server.event.wait(10)
        if not server.event.is_set():
            logger.error("*** Client never asked for a shell.")
            return
        chan.send("\r\n\r\nWelcome to my dsfileshare service !!\r\n\r\n")

    except Exception as e:
        logger.error("*** Caught exception: " + str(e.__class__))
        traceback.print_exc()

    finally:
        logger.info("Closing channel and transport for {}".format(addr))
        try:
            chan.close()
            t.close()
        except:
            pass


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s", handlers=[logging.StreamHandler()])
    start_ssh_server("dummy", "dummy", 2200)


if __name__ == "__main__":
    main()
