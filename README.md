** SERVER STARTUP **

1. sshd on 2222
2. upnpc program
3. authentication.


BOT.

1. Will create a random password and use the launching user.
  * ahmad / randompass

2. It will start `sshd` with the username and pass from (1).
   and port 2200.

3. Run `upnpc` command to forward the port to internet. 

4. Get the public ip from output of `upnpc` command in (3).

5. What details do we have now?
  * Username.
  * Password.
  * Public IP.
  * Port.
  * Time.

6. Discord bot publishes details from (5) on discord channel.

# TODO : add a switch for debug logs
# TODO : Use a dataclass for running config

