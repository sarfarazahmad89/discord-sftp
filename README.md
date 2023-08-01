# discord-sftp
discord-sftp enables members of a discord channel to exchange file among themselves over SFTP protocol. The idea is to have UPnP forward the built-in SFTP server onto the internet, a built-in discord bot publishes the details required to connect to the previously forwarded service on a specific discord channel. The discord bot and the sftp service are run as background threads while an sftp client is spun in the foreground to connect to other instances of this software (discord-sftp) that would be running on other computers across the internet (say your friends/members of that specific discord text channel). Discord is used a medium to advertise our presence among peers and correspondingly to detect other active peers. Client and server(s) are all baked in one executable for convenience. Again, discord is basically used to advertise connection details of other copies of this daemon (say running on your buddy's computer).

## Highlight.
- UPnP to forward built-in SFTP server onto the internet.
- Discord (bot): discord is used a broadcast/service discovery mechanism on the internet.
- Built-in SFTP server: built-in sftp server using paramiko. only shares the directory where the cli is invoked from.
- Built-in SFTP client: Client that discovers other copies of this software run by the members of the channel.
- New hostkey and passwords are generated at every new run. These details are advertised and consumed from discord messages.

### Requirements
- See [setup.py](/setup.py) for dependencies.
- You need to configure a discord bot that can read and publish messages on a specific text channel.
- Hopefully UPnP forwarding is enabled in your router and this way SFTP server that is potentially running in a private networ, can be forwarded all the way to the internet.

### Limitations
It is pretty much a hack/a proof of concept and serves my purposes. It is not very robust at the moment.
 
### Installing
1. Clone the git repo.
2. Run pip install
```
git clone https://github.com/sarfarazahmad89/discord-sftp
pip install discord-sftp
```

## Usage
- Run the client/server with a single `discordsftp` command. It will spawn the background `discord` and `sftpserver` threads, and take you an interactive shell.
- The interactive client offers following interactive commands,
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
```

## Sample Images
1. listing peers and connecting to one
 ![startup_n_listing_peers](/images/1_startup_listing_peers.png?raw=true)

2. running commands after connection. 
 ![running_commands](/images/2_running_commands.png?raw=true)
