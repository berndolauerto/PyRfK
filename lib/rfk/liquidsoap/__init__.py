# -*- coding: utf-8 -*-

import os
import telnetlib
from string import Template

import rfk
from rfk.database.streaming import Relay, Stream
from rfk.helper import get_path


class LiquidInterface(object):
    timeout = 5000

    def __init__(self, host='127.0.0.1', port=1234):
        self.host = host
        self.port = port
        self._version = None

    def connect(self):
        self.conn = telnetlib.Telnet(self.host, self.port)

    def close(self):
        self.conn.close()

    def get_version(self):
        if not self._version:
            for line in self._execute_command('version').splitlines():
                if len(line) > 0:
                    self._version = line
                    return self._version
        return self._version
    version = property(get_version)

    def get_uptime(self):
        for line in self._execute_command('uptime').splitlines():
            if len(line) > 0:
                return line
    uptime = property(get_uptime)

    def get_sinks(self):
        sinks = []
        for item in self._list(filter='output'):
            sinks.append(LiquidSink(self, item[0], item[1]))
        return sinks
    sinks = property(get_sinks)

    def get_sources(self):
        sources = []
        for item in self._list(filter='input'):
            sources.append(LiquidSource(self, item[0], item[1]))
        return sources
    sources = property(get_sources)

    def get_status(self, sink_or_source):
        assert isinstance(sink_or_source, (LiquidSink, LiquidSource))
        return self.endpoint_action(sink_or_source.handler, 'status')

    def endpoint_action(self, handler, action):
        for line in self._execute_command("%s.%s" % (handler, action)).splitlines():
            if len(line) > 0:
                return line

    def kick_harbor(self):
        kicked = False
        for source in self.sources:
            if source.type == 'input.harbor' and source.status != 'no source client connected':
                source.kick()
                kicked = True
        return kicked

    def _list(self, filter=None):
        list = self._execute_command('list')
        for line in list.splitlines():
            spl = map(str.strip, line.split(':'))
            if len(spl) == 2 and (filter is None or spl[1].startswith('%s.' % (filter,))):
                yield spl

    def _execute_command(self, command):
        self.conn.write("%s\n" % command)
        ret = self.conn.read_until('END', self.timeout)
        return ret


class LiquidSink(object):
    def __init__(self, interface, handler, type):
        self.interface = interface
        self.handler = handler
        self.type = type

    @property
    def status(self):
        return self.interface.get_status(self)

    def __repr__(self):
        return "<rfk.liquidsoap.LiquidSink %s at %s>" % (self.type, self.handler)


class LiquidSource(object):
    def __init__(self, interface, handler, type):
        self.interface = interface
        self.handler = handler
        self.type = type

    @property
    def status(self):
        return self.interface.get_status(self)

    def kick(self):
        self.interface._execute_command("%s.kick" % (self.handler))

    def __repr__(self):
        return "<rfk.liquidsoap.LiquidSource %s at %s>" % (self.type, self.handler)


def _get_template_path(template):
    return os.path.join(get_path(os.path.join('rfk', 'templates', 'liquidsoap', template), internal=True))


def gen_script():
    """Generates liquidsoap script from templates

    """

    interface = os.path.join(get_path('bin'), 'rfk-liquidsoaphandler')
    logfile = os.path.join(get_path(rfk.CONFIG.get('liquidsoap', 'logpath')))
    loglevel = rfk.CONFIG.get('liquidsoap', 'loglevel')
    address = rfk.CONFIG.get('liquidsoap', 'address')
    port = rfk.CONFIG.get('liquidsoap', 'port')

    backendurl = rfk.CONFIG.get('liquidsoap', 'backendurl')
    backendpassword = rfk.CONFIG.get('liquidsoap', 'backendpassword')

    lastfm = make_lastfm()
    emergency = make_emergency()

    template_string = open(_get_template_path('main.liq'), 'r').read()

    template = Template(template_string)
    config = template.substitute(address=address,
                                 port=port,
                                 logfile=logfile,
                                 loglevel=loglevel,
                                 backendurl=backendurl,
                                 backendpassword=backendpassword,
                                 emergency=emergency,
                                 lastFM=lastfm,
                                 script=interface)
    if isinstance(config, str):
        config = config.decode('utf-8')
    if not isinstance(config, unicode):
        config = unicode(config)
    config += make_output(dir)
    return config


def make_lastfm():
    script = ''

    enabled = rfk.CONFIG.getboolean('liquidsoap', 'lastfm')
    username = rfk.CONFIG.get('liquidsoap', 'lastfmuser')
    password = rfk.CONFIG.get('liquidsoap', 'lastfmpassword')

    if enabled and username and password:
        template_string = open(_get_template_path('lastfm.liq'), 'r').read()
        template = Template(template_string)
        script += template.substitute(username=username,
                                      password=password)

    return script


def make_emergency():
    if rfk.CONFIG.has_option('liquidsoap', 'fallback'):
        fallback_filename = rfk.CONFIG.get('liquidsoap', 'fallback')
        fallback = os.path.join(get_path(rfk.CONFIG.get('liquidsoap', 'looppath')), fallback_filename)
        if os.path.isfile(fallback):
            return 'emergency = single("{}")'.format(fallback)
    return 'emergency = blank()'


def make_output(dir):
    script = u''
    streams = Stream.query.all()
    for stream in streams:
        if stream.type == Stream.TYPES.OGG:
            file = 'output_vorbis.liq'
        elif stream.type == Stream.TYPES.AACP:
            file = 'output_aacp.liq'
        elif stream.type == Stream.TYPES.MP3:
            file = 'output_mp3.liq'
        elif stream.type == Stream.TYPES.OPUS:
            file = 'output_opus.liq'
        else:
            continue
        template_string = open(_get_template_path(file), 'r').read()
        template = Template(template_string)
        master = Relay.get_master()
        script += template.substitute(name=stream.code,
                                      description=stream.name,
                                      quality=stream.quality,
                                      host=master.address,
                                      port=master.port,
                                      username=master.auth_username,
                                      password=master.auth_password,
                                      mount=stream.mount,
                                      url=rfk.CONFIG.get('site', 'url'))
    if isinstance(streams, str):
        streams = streams.decode('utf-8')
    if not isinstance(streams, unicode):
        streams = unicode(streams)
    return script
