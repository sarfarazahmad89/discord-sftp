from setuptools import setup
setup(name='dsfileshare',
      version='0.1',
      description=("Interactive file transfers using sftp, upnpc and discord for discovery"),
      author='Sarfaraz Ahmad',
      author_email='sarfaraz.ahmad@live.in',
      license='MIT',
      packages=['dsfileshare'],
      install_requires=['discord.py', 'paramiko', 'colorlog', 'tabulate'],
      zip_safe=False,
      entry_points='''
        [console_scripts]
        dsfileshare=dsfileshare.cli:main
      ''',
     )
