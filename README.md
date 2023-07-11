# discord-sftp
discord-sftp enables members of a discord channel to exchange file among themselves over SFTP protocol. The idea is to have UPnP forward the built-in SFTP server onto the internet, a built-in discord bot publishes the details required to connect to the previously forwarded service on a specific discord channel. The discord bot and the sftp service are run as background threads while an sftp client is spun in the foreground to connect to other instances of this discord-sftp that might be running on other computers across the internet (say your friends) and publishing to the same discord channel. Client and server(s) are baked into one executable for the moment.

## highlights/breakdown.
- UPnP to forward built-in SFTP server onto the internet.
- Discord (bot): discord is used a broadcast/service discovery mechanism on the internet.
- Built-in SFTP server: built-in sftp server using paramiko. only shares the directory where the cli is invoked from.
- Built-in SFTP client: Client that discovers other copies of this software run by the members of the channel.

### requirements
- See [setup.py](/setup.py) for dependencies.
- You need to configure a discord bot that can read and publish messages on a specific text channel.
- Hopefully UPnP forwarding is enabled in your router and goes all the way through to the internet.

### limitations
It is pretty much a hack/a proof of concept and solves my purposes. It is not very robust at the moment.
 
### installing
1. Clone the git repo.
2. Run pip install
```
git clone https://github.com/sarfarazahmad89/discord-sftp
pip install discord-sftp
```

## usage
- The client offers following interactive commands,
```
Use the available commands to interact with the application:
   - `list_peers`: List active Discord-SFTP peers.
   - `connect [peer]`: Connect to a specific peer for file transfer.
   - `ls`: List files in the connected peer's directory.
   - `cd [directory]`: Change the current directory on the connected peer.
   - `get [file]`: Download a file from the connected peer.
   - `pwd`: Print the current directory on the connected peer.
   - `disconnect`: Disconnect from the connected peer.
   - `exit`: Exit the application.```

