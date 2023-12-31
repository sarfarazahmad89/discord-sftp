from setuptools import setup
setup(name='discord.sftp',
      version='0.1',
      description=("Interactive file transfers using sftp, upnpc and discord for discovery"),
      author='Sarfaraz Ahmad',
      author_email='sarfaraz.ahmad@live.in',
      license='MIT',
      packages=['discordsftp'],
      install_requires=['discord.py', 'paramiko', 'colorlog', 'tabulate', 'requests'],
      zip_safe=False,
      entry_points='''
        [console_scripts]
        discordsftp=discordsftp.cli:main
      ''',
     )
