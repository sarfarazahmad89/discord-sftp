import logging
import requests
import subprocess
import re
import ipaddress

logger = logging.getLogger(__name__)


class UPNPForward:
    def __init__(self, tcpport):
        self.tcpport = tcpport
        self.public_ipaddr = None

    def _get_pub_addr_ipinfo(self):
        r = requests.get("https://ipinfo.io")
        if r.ok:
            return r.json()["ip"]

    def __enter__(self):
        cmd = "upnpc -i -r {} tcp".format(self.tcpport)
        logger.info("executing command {}".format(cmd.split()))
        cmd_result = subprocess.run(cmd.split(), capture_output=True)
        logger.debug("OUTPUT: {}".format(cmd_result.stdout.decode("ascii")))
        cmd_result.check_returncode()
        for line in cmd_result.stdout.decode("ascii").split("\n"):
            r = re.match(r"ExternalIPAddress = (.*)", line)
            if r:
                self.public_ipaddr = r.groups()[0]
        assert ipaddress.IPv4Address(self.public_ipaddr)
        assert self.public_ipaddr, "could not determine public ip address"
        if self.public_ipaddr != self._get_pub_addr_ipinfo():
            logger.warning("Public IPAddr does not match with ipinfo")
        logger.info("`add` request completed successfully")
        return self

    def __exit__(self, type, value, traceback):
        cmd = "upnpc -i -d {} tcp".format(self.tcpport)
        logger.info("executing command {}".format(cmd.split()))
        cmd_result = subprocess.run(cmd.split(), capture_output=True)
        logger.debug("OUTPUT: {}".format(cmd_result.stdout.decode("ascii")))
        cmd_result.check_returncode()
        logger.info("`delete` request completed successfully")
