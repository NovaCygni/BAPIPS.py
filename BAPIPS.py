#!/usr/bin/python3
import os
import time


euid = os.geteuid()
if euid == 0:
    print("You Cannot perform any upgrades or repairs while logged in with root permissions, Try again without Root/Sudo..")
    print("In future you probably dont want to try running anything as Root unless you have a specific reason for it......")
    time.sleep(6)
    os.kill(os.getpid(), 9)

print("Blackarch Post Installation Python Stuff script, this script should check for and install \n"
      "all the python2 and python3 modules that Blackarch uses.")
print("Author: AmonChaKi")
print("Early Prototype version: Release build 0.01")
print("This will NOT be quick.... go watch a film, go to work or sleep or something... ")
time.sleep(5)


py2stuff = ['abcd', 'ajpy', 'alabaster', 'alembic', 'alexa-top-sites', 'amqp', 'ana', 'androguard',
            'angr', 'angrop', 'anyjson', 'apache-log-parser', 'apkid', 'appdirs', 'apsw', 'arandr', 'archinfo',
            'argcomplete', 'armscgen', 'ascii-graph', 'asncrypto', 'async', 'attrs', 'autobahn', 'automat', 'awake',
            'babel', 'backports-abc', 'backportsfunctools-lru-cache', 'backportsshutil-get-terminal-size', 'bacpypes',
            'balbuzard', 'barf', 'bbqsql', 'bcrypt', 'beaker', 'beautifulsoup', 'beautifulsoup', 'beeswarm', 'billiard',
            'binaryornot', 'bintrees', 'bitarray', 'bitstring', 'blessings', 'blindelephant', 'blinker', 'bluto',
            'bmap-tools', 'boto', 'boto', 'botocore', 'bottle', 'bowcaster', 'bs', 'bson', 'btproxy', 'cachetools',
            'canari', 'capstone', 'case', 'celery', 'cement', 'ceph-detect-init', 'ceph-disk', 'ceph-volume', 'cephfs',
            'cerberus', 'certifi', 'cffi', 'cfscrape', 'chapcrack', 'chardet', 'cheroot', 'cherrypy', 'chipsecrc',
            'clamd', 'claripy', 'cle', 'clearbit', 'click-plugins', 'click', 'cliff', 'clint', 'cluster', 'cmd',
            'cmdline-search', 'cmdline-shellsploit', 'coding', 'colorama', 'colored', 'coloredlogs', 'colorizer',
            'colorlog', 'commonmark', 'config', 'configobj', 'configparser', 'conpot', 'constantly', 'construct',
            'contextlib', 'cookiecutter', 'cookiejar', 'cooldict', 'couchdb', 'couchdbkit', 'coverage',
            'crackmapexecdev', 'crc', 'crcmod', 'crochet', 'cryptography', 'cssselect', 'cx-oracle', 'cybox', 'cycler',
            'cython', 'dartsutillru', 'dataset', 'decorator', 'defusedxml', 'demjson', 'dicttoxml', 'dis', 'distorm',
            'django', 'dnet', 'dnsdumpster', 'dnsknife', 'dnslib', 'dnspython', 'docopt', 'docutils', 'docxtxt', 'dpkt',
            'droopescan', 'dropbox', 'eapeak', 'easyprocess', 'ecdsa', 'editorconfig', 'elasticsearch', 'elfesteem',
            'elixir', 'emailprotectionslib', 'enum', 'esmre', 'eventlet', 'exabgp', 'exifread', 'exrex',
            'exscript', 'extracthosts', 'facepy', 'fado', 'fake-useragent', 'fakemail-python', 'fakenet-ng',
            'featherduster', 'feedparser', 'file-magic', 'filebytes', 'flake', 'flask-babel', 'flask-cors',
            'flask-login', 'flask-mail', 'flask-openid', 'flask-pymongo', 'flask-restlessb', 'flask-sqlalchemydev',
            'flask-whooshalchemy-redux', 'flask-wtfdev', 'flask', 'flickrapi', 'flipflop', 'frida', 'fs',
            'fullcontactpy', 'funcsigs', 'functoolspost', 'fuse-python', 'fusil', 'future', 'futures', 'fuzzywuzzy',
            'gdata', 'gdshortener', 'geoip', 'geoip', 'gevent-websocket', 'gevent', 'ghostpydev', 'gitdb', 'gitpython',
            'gmpy', 'gmpy', 'gnuplot-py', 'google-api-python-client', 'google', 'gps', 'gramfuzz', 'greenlet',
            'grequests', 'guess-language', 'h', 'hachoir-core', 'hachoir-parser', 'hackersh', 'halberd', 'hashes',
            'haystack', 'hgapi', 'hpack', 'hpfeeds', 'htmltext', 'htmllib', 'httmock', 'http-parser', 'httpforge',
            'httplib', 'httpreplay', 'httpretty', 'humanfriendly', 'hyperframe', 'hyperlink', 'iampoliciesgonewild',
            'idalink', 'idna', 'imagesize', 'impacket', 'incremental', 'indxparse', 'iniparse', 'inquisitor',
            'intervaltree', 'ipaddr', 'ipaddress', 'ipcalc', 'iptools', 'ipwhois', 'ipy', 'ipython-genutils', 'ipython',
            'isc-dhcp-leases', 'ishell', 'isodate', 'itsdangerous', 'ivre', 'jclipost', 'jaracoclasses',
            'jaracocollections', 'jaracofunctools', 'jaracoitertools', 'jaracologging', 'jaracostream', 'jaracotext',
            'jinja', 'jmespath', 'jspy', 'jsbeautifier', 'jsonhtml', 'jsonrpclib-pelix', 'keystone', 'killerbee',
            'kittyfuzzer', 'knockpy', 'kombu', 'libarchive', 'libnum', 'libtaxii', 'lightblue', 'lightbulb-framework',
            'linecache', 'linereader', 'lockfile', 'logbook', 'logging', 'logutils', 'lxml', 'mcrypto', 'macholib',
            'mako', 'markdown', 'markupsafe', 'mat', 'mate-menu', 'matplotlib', 'maxminddb', 'mccabe', 'mechanize',
            'mimerender', 'mixbox', 'mobiusft', 'mock', 'mockito', 'modbus-tk', 'mongoaudit', 'morbid',
            'more-itertools', 'mpmath', 'mrtparse', 'msgpack', 'mulpyplexer', 'multipartposthandler', 'multiscanner',
            'mutagen', 'mysql-python', 'nassl', 'ndg-httpsclient', 'netaddr', 'netfilterqueue', 'netifaces', 'netscan',
            'netsnmp-pythona', 'networkx', 'nfcpy', 'nfspy', 'nltk', 'normality', 'nose', 'ntdsxtract', 'ntlm-auth',
            'ntplib', 'numpy', 'oauthpost', 'oauthclient', 'oauthlib', 'obfsproxy', 'olefile', 'oletools', 'omnihash',
            'onionshare', 'opensvp', 'opinel', 'orbited', 'ordereddict', 'osrframework', 'otxv', 'packaging',
            'pacumengit', 'pager', 'pandas', 'pappyproxy', 'paramiko', 'parsley', 'passlib', 'paste', 'pathlib',
            'pbkdf-ctypes', 'pbkdf', 'pbr', 'pcapy', 'pdb', 'pdfkit', 'pdfminer', 'pdfrw', 'pecan', 'pefile', 'peframe',
            'pexpect', 'phplydev', 'pickleshare', 'pillow', 'pip', 'pluggy', 'pluginbase', 'plumbum', 'ply', 'pmw',
            'pocsuite', 'portend', 'poster', 'praw', 'prawcore', 'pretend', 'prettytable', 'progressbar',
            'prompt-toolkit', 'protobuf', 'psutil', 'psycopg', 'ptp', 'ptyprocess', 'publicsuffix', 'pushbulletpy',
            'py-bcrypt', 'py-radix', 'py-zabbix', 'pyneob', 'py', 'py', 'pyasn-modules', 'pyasn', 'pyblake', 'pybloom',
            'pybloomfiltermmap', 'pybluez', 'pybozocrack', 'pycairo', 'pyclamd', 'pycodestyle', 'pycparser', 'pycrypto',
            'pycups', 'pycurl', 'pydeep', 'pydes', 'pydispatcher', 'pydivert', 'pydns', 'pydot', 'pydotplus',
            'pyelftools', 'pyersinia', 'pyexfilb', 'pyexiftool', 'pyfiglet', 'pyflakes', 'pyftpdlib', 'pygeoip',
            'pyghmi', 'pygithub', 'pygments', 'pygobject', 'pygoogle-simple', 'pygraphviz', 'pygtail', 'pyinotify',
            'pyjfuzz', 'pyjwt', 'pylibemu', 'pyliblzma', 'pylibpcap', 'pylnk', 'pylzma', 'pyminifier', 'pymisp',
            'pymongo', 'pymssql', 'pymysql', 'pynacl', 'pynids', 'pyopenssl', 'pyparsing', 'pypcaprc', 'pypcapfile',
            'pypdf', 'pypdns', 'pypea', 'pyperclip', 'pyprind', 'pypssl', 'pyptlib', 'pypubsubrc', 'pyrasite', 'pyric',
            'pyrit', 'pyroute', 'pyrtlsdr', 'pysendfile', 'pyserial', 'pysha', 'pyshark', 'pyside', 'pysmb', 'pysmbc',
            'pysnmp', 'pysocks', 'pysqlite', 'pystache', 'pyswf', 'pytest-cov', 'pytest-mock', 'pytest-twisted',
            'pytest', 'pythem', 'python-cjson', 'python-daemon', 'python-dateutil', 'python-distutils-extra',
            'python-docx', 'python-editor', 'python-emailahoy', 'python-evt', 'python-geoip-geolite', 'python-geoip',
            'python-ldap', 'python-levenshtein', 'python-libnmap', 'python-libtorrent', 'python-mimeparse',
            'python-nmap', 'python-ntlm', 'python-ntlm', 'python-openid', 'python-osmgpsmap', 'python-owasp-zap-v',
            'python-poppler-qt', 'python-ptrace', 'python-pytun', 'python-utils', 'python-wappalyzer', 'python-whois',
            'python-xlib', 'pythonect', 'pythonwhois', 'pyttsx', 'pytz', 'pyusb', 'pyvex', 'pyvirtualdisplay',
            'pywebview', 'pywerview', 'pywhois', 'pyx', 'pyxdg', 'pyxml', 'pyyaml', 'pyzmq', 'qrcode', 'rados', 'rbd',
            'rdflib', 'rdpy', 're', 'recommonmark', 'redis', 'regex', 'reportlab', 'requesocks', 'requests-cache',
            'requests-file', 'requests-ntlm', 'requests-oauthlib', 'requests-toolbelt', 'requests', 'restkit', 'rex',
            'rfcat', 'rfidiot', 'rgw', 'ropgadget', 'ropper', 'rpigpio', 'rpyc', 'rsa', 'scandir', 'scanless',
            'scapyunknownversion', 'schema', 'scipy', 'scp', 'scrypt', 'selenium', 'service-identity', 'setproctitle',
            'setuptools-scm', 'setuptools', 'sfalearn', 'sha', 'shodan', 'simplegeneric', 'simplejson', 'simplekml',
            'simuvex', 'singledispatch', 'singlefilea', 'six', 'skpy', 'skypepy', 'slowaesa', 'smalisca',
            'smartencoding', 'smmap', 'smspdu', 'snapception', 'snowballstemmer', 'socketpool', 'sortedcontainers',
            'speaklater', 'speechrecognition', 'sphinx-rtd-theme', 'sphinx', 'sphinxcontrib-websupportdev', 'splinter',
            'sploitego', 'sqlalchemy-migrate', 'sqlalchemy-utils', 'sqlalchemy', 'ssdeep', 'sshtunnel', 'sslcaudit',
            'sslstrip', 'sslyze', 'steganography', 'stemdev', u'stepicbzr', 'stevedore', 'stix', 'stomper', 'stopit',
            'subprocess', 'suricatasc', 'symath', 'symautomata', 'sympy', 'tabi', 'tabulate', 'tblib', 'tckfc',
            'tcpextract', 'tcpwatch', 'team', 'telepot', 'telnetsrv', 'tempitadev', 'tempora', 'termcolor',
            'terminaltables', 'texttable', 'threadpool', 'threatcrowd', 'tinydb', 'tld', 'tldextract', 'tls-parser',
            'tlsenum', 'tlslite-ng', 'torctl', 'tornado', 'tox', 'tqdm', 'traceback', 'tracer', 'traitlets', 'triton',
            'trollius', 'tweepy', 'twisted', 'twodict', 'txaio', 'txsocksx', 'typing', 'ua-parser', 'uefi-firmware',
            'ufw', 'ujson', 'unicodecsv', 'unicorn', 'unidecode', 'unirest', 'unittest', 'unqlite', 'update-checker',
            'uritemplate', 'urllib', 'urwid', 'user-agents', 'utidylib', 'validate-email', 'validators', 'validictory',
            'verboselogs', 'vine', 'vinettoa', 'virtualenv', 'virustotal-api', 'volatility', 'vulndb', 'wafwf',
            'wakeonlan', 'wcwidth', 'webencodings', 'webob', 'websocket-client', 'websockify', 'werkzeug', 'wget',
            'whatportis', 'wheel', 'whichcraft', 'whoosh', 'wifiphisher', 'win-inet-pton', 'wpa-halfhandshake-crack',
            'wpsik', 'wtforms', 'wxpython-common', 'wxpython', 'xdot', 'xgoogle', 'xhtmlpdfb', 'xlrd', 'xlsxcsv',
            'xlsxwriter', 'xmltodict', 'xmpppyrc', 'xortool', 'xsser', 'xtermcolor', 'yapsy', 'yara-python',
            'yaraprocessor', 'youtube-dlg', 'zenmap', 'zlib-wrapper', 'zopeinterface']

py3stuff = ['aio-ping', 'aioftp', 'aiohttp', 'aiostream', 'amqp', 'aniso8601',
            'arybo', 'asn1crypto', 'async-timeout', 'asyncio', 'attrs',
            'automat', 'awscli', 'bcrypt', 'beautifulsoup4', 'blessings',
            'botocore', 'bottle', 'bottleneck', 'brotlipy', 'bs4',
            'capstone', 'certifi', 'cffi', 'chardet', 'cheroot',
            'cherrypy', 'click', 'colorama', 'coloredlogs', 'colorlog',
            'constantly', 'construct', 'cryptography', 'cssselect', 'cymruwhois',
            'cython', 'datetime', 'decorator', 'deen', 'detectem', 'django',
            'dnsdiag', 'dnspython', 'docker-pycreds', 'docker', 'docutils',
            'editorconfig', 'elasticsearch-async', 'elasticsearch', 'filebytes',
            'flask-socketio', 'frida', 'future', 'gdbgui', 'gi', 'gitdb2',
            'gitem', 'gitpython', 'gmpy2', 'greenlet', 'gufw', 'h11',
            'habu', 'html2text', 'html5lib', 'httplib2', 'humanfriendly',
            'hyperlink', 'idna-ssl', 'idna', 'imagemounter', 'incremental',
            'inquirer', 'ipwhois', 'ipython-genutils', 'ipython', 'isc',
            'jaraco.classes', 'jaraco.collections', 'jaraco.functools', 'jaraco.itertools',
            'jaraco.logging', 'jaraco.stream', 'jaraco.text', 'jedi', 'jinja2',
            'jmespath', 'jsbeautifier', 'json2html', 'jsonpickle', 'kaitaistruct',
            'keystone-engine', 'kombu', 'ldap3', 'libtorrent-test', 'logbook',
            'lxc', 'lxml', 'mako', 'markupsafe', 'meson', 'mido',
            'mitmproxy', 'more-itertools', 'msgpack-python', 'msgpack=', 'multidict',
            'networkx', 'nump', 'olefile', 'openpyxl', 'paramiko', 'parsel',
            'parso', 'paste', 'pefile', 'pexpect', 'pickleshare', 'pika',
            'pillow', 'pip', 'plasma', 'plecost', 'pluggy', 'ply',
            'poormanslogging', 'portend', 'prompt-toolkit', 'psutil', 'psycopg2',
            'ptyprocess', 'py', 'pyalpm', 'pyasn1-modules', 'pyasn1',
            'pycairo', 'pycparser', 'pyelftools', 'pygdbmi', 'pygments',
            'pygobject', 'pynacl', 'pyopenssl', 'pyperclip', 'pyserial',
            'pysocks', 'pytest', 'python-dateutil', 'python-engineio',
            'python-libtorrent', 'python-openflow', 'python-socketio', 'pytz',
            'pyusb', 'pyyaml', 'pyzmq', 'qbittorrent', 'readchar', 'requests',
            'requestsexceptions', 'retdec-python', 'ropgadget', 'ropper', 'rsa',
            'ruamel.yaml', 's3transfer', 'scapy-python3', 'scrapy', 'selenium',
            'setuptools-scm', 'setuptools', 'simplegeneric', 'simplejson', 'six',
            'slip.dbus', 'slip', 'smmap2', 'socksipy-branch', 'sortedcontainers',
            'stopit', 'storjtorrent', 'style', 'tabulate', 'team', 'tempora',
            'termcolor', 'tld', 'tornado', 'torrentstream', 'tqdm',
            'traitlets', 'trufflehog', 'twisted', 'tzlocal', 'unicorn',
            'update', 'urh', 'url', 'urllib3', 'urwid', 'vine',
            'virtualenv', 'voltron', 'w3lib', 'wapiti', 'wcwidth'
            'webencodings', 'websocket-client', 'werkzeug', 'wsproto',
            'xlsxwriter', 'yara-python', 'yarl', 'yaswfp', 'youtube-dl',
            'yts', 'zope.interface']

try:
    import subprocess
    import asyncio
    from concurrent.futures import ThreadPoolExecutor
    e = ThreadPoolExecutor()
except ImportError or ImportWarning:
    subprocess.call("pip3 install asyncio --upgrade ", shell=True)
    subprocess._cleanup()
    import asyncio

def killpid():
    os.kill(os.getpid(), 9)

a1a = len(py2stuff)
a2a = len(py3stuff)


#todo add Exception Os.Error handling if detects corrupted permissions or ownership of detected files.
@asyncio.coroutine
def dostuffpy2():
    for i in range(a1a):
        for hodor in py2stuff:
            try:
                subprocess.call(["pip2 install --upgrade --no-deps --force-reinstall " + hodor], shell=True, timeout=61)
                subprocess._cleanup()
            except Exception as durin:
                print("skipping the module" + hodor + "because of" + "\n" + str(durin))
                subprocess._cleanup()


@asyncio.coroutine
def dostuffpy3():
    for i in range(a2a):
        for holdthedoor in py3stuff:
            try:
                subprocess.call(["pip3 install --upgrade --no-deps --force-reinstall " + holdthedoor], shell=True, timeout=61)
                subprocess._cleanup()
            except Exception as durins:
                print("skipping the module" + holdthedoor + "because of" + "\n" + str(durins))
                subprocess._cleanup()


@asyncio.coroutine
def finishingup1():
    subprocess.call(["pip2 freeze --local | grep -v '^\-e' | cut -d = -f 1  | xargs -n1 pip2 install -U"], shell=True)
    subprocess._cleanup()
@asyncio.coroutine
def finishingup2():
    subprocess.call(["pip3 freeze --local | grep -v '^\-e' | cut -d = -f 1  | xargs -n1 pip3 install -U"], shell=True)
    subprocess._cleanup()


Future = asyncio.futures.Future
class Task(Future):

    def __init__(self, gen, *,loop):
        super().__init__(loop=loop)
        self._gen = gen
        self._loop.call_soon(self._step)

    def _step(self, val=None, exc=None):
        try:
            if exc:
                f = self._gen.throw(exc)
            else:
                f = self._gen.send(val)
        except StopIteration as e:
            self.set_result(e.value)
        except Exception as e:
            self.set_exception(e)
        else:
            f.add_done_callback(
                 self._wakeup)

    def _wakeup(self, fut):
        try:
            res = fut.result()
        except Exception as e:
            self._step(None, e)
        else:
            self._step(res, None)


print("Beginning The Py2 and Py3 Asyncio Loops for python Modules installtion.")
loop = asyncio.get_event_loop()
tasks = [Task(dostuffpy2(), loop=loop),
         loop.create_task(dostuffpy3())]
loop.run_until_complete(asyncio.wait(tasks))
loop.close()
print("Finished the Py2 and Py3 Modules installation loops, Starting finalizing and make sure everything is as it should be!.")
loop2 = asyncio.get_event_loop()
tasks2 = [Task(finishingup1(), loop=loop2),
          loop2.create_task(finishingup2())]
loop2.run_until_complete(asyncio.wait(tasks2))
loop2.close()
print("Finished Everything... Gratz!")
time.sleep(5)
killpid()
