import time
import threading
import socket
import subprocess
import select
import pickle
import traceback
import sys
import logging

import os
import re

import rfk.liquidsoap
import rfk.database
from rfk.helper import get_path
from rfk.types import RingBuffer


COMMAND_LOG = 1
COMMAND_SHUTDOWN = 2

buffer_size = 1024


def write(_socket, data):
    f = _socket.makefile('wb', buffer_size)
    pickle.dump(data, f, pickle.HIGHEST_PROTOCOL)
    f.close()


def read(_socket):
    f = _socket.makefile('rb', buffer_size)
    data = pickle.load(f)
    f.close()
    return data


class SocketExists(BaseException):
    pass


class LiquidsoapDaemon(logging.Handler):
    telnet_ignore_pattern = re.compile('(New client: localhost)|(Client localhost)')

    def __init__(self, socket='/tmp/liquiddaemon.sock'):
        logging.Handler.__init__(self)
        self.logger = logging.getLogger('LiquidsoapDaemon')
        self.logger.setLevel(logging.INFO)
        self.logger.addHandler(self)
        self.liquidsoap_logger = logging.getLogger('Liquidsoap')
        self.liquidsoap_logger.setLevel(logging.INFO)
        self.liquidsoap_logger.addHandler(self)
        self.process = None
        self.socket_handler = SocketHandler(get_path(socket), self)
        self.log = RingBuffer(100)
        self.quit = False
        self.run_liquid = True
        self.skip_telnet = True

    def shutdown(self):
        self.logger.info('Shutting down...')
        self.run_liquid = False
        self.quit = True
        c = 0
        while self.process.returncode is None:
            c += 1
            self.logger.info("Asking liquidsoap nicely to terminate... (Try #%d)", c)
            self.process.terminate()
            self.process.poll()
            time.sleep(2)
            if c > 5:
                break
        if self.process.returncode is None:
            self.logger.warn('Killing liquidsoap...')
            self.process.kill()
            self.logger.error('NACH FRANKREICH NUR AUF KETTEN')

    def get_log(self, offset=None):
        lo = 0
        if offset is not None:
            lo = offset - self.log.offset
        if lo < 0:
            lo = 0
        return self.log.offset + (len(self.log)), self.log.get()[lo:]

    def emit(self, record):
        self.log.append([time.time(), record.name, record.levelno, record.getMessage()])

    def run(self):
        self.socket_handler.start()
        try:
            while True:
                try:
                    self.run_liquidsoap()
                    if self.process.returncode == 0:
                        self.logger.info("liquidsoap quit with: %d ", self.process.returncode)
                    else:
                        self.logger.error("liquidsoap quit with: %d!", self.process.returncode)
                except Exception as err:
                    exc_type, exc_value, exc_tb = sys.exc_info()
                    for tb in traceback.format_exception(exc_type, exc_value, exc_tb):
                        self.logger.error(tb)
                if self.run_liquid and not self.quit:  # we want to autorestart liquidsoap and dont want to quit the daemon
                    self.logger.info('Trying to restart liquidsoap in 10 seconds')
                    btime = time.time()
                    while (time.time() - btime < 10) and not self.quit: # impatience is a gift
                        time.sleep(.5)
                else:
                    break

                if not self.run_liquid or self.quit:  # not autorestart or we want to exit the daemon
                    break
            time.sleep(1)
            while not self.quit:
                time.sleep(1)
        except KeyboardInterrupt:
            self.logger.info('SIGINT: shutting down...')
            self.shutdown()
        finally:
            self.socket_handler.shutdown()

    def run_liquidsoap(self):
        self.process = subprocess.Popen(['liquidsoap', '-'], bufsize=-1,
                                        stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE)

        self.process.stdin.write(rfk.liquidsoap.gen_script().encode('utf-8'))

        # leave the database in a rather clean state
        rfk.database.session.rollback()
        rfk.database.session.remove()

        self.process.stdin.close()
        while self.process.returncode is None:
            try:
                line = re.sub(r'^\d{4}/d{2}/d{2} d{2}:d{2}:d{2} ', '', self.process.stdout.readline())
                if not (self.skip_telnet and self.telnet_ignore_pattern.search(line) is not None):
                    self.liquidsoap_logger.info(line.rstrip("\n \t\r"))
            finally:
                self.process.poll()

    def set_debug(self, debug):
        if debug:
            self.logger.setLevel(logging.DEBUG)
        else:
            self.logger.setLevel(logging.INFO)

    def enable_stdout(self):
        formatter = logging.Formatter('%(asctime)s:%(levelname)s:%(name)s - %(message)s')
        ch = logging.StreamHandler()
        ch.setLevel(self.logger.level)
        ch.setFormatter(formatter)
        self.logger.addHandler(ch)
        self.liquidsoap_logger.addHandler(ch)


class SocketHandler(threading.Thread):
    def __init__(self, path, liquiddaemon):
        threading.Thread.__init__(self)
        if os.path.exists(path):
            raise SocketExists()
        self.path = path
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server.bind(self.path)
        self.setDaemon(True)
        self.liquiddaemon = liquiddaemon
        self.server.listen(5)
        self.open_sockets = []

    def run(self):
        try:
            while True:
                self.open_sockets.append(SocketConnectionHandler(self, self.server.accept()))
        finally:
            self.shutdown()

    def shutdown(self):
        for connection in self.open_sockets:
            connection.close()
        os.unlink(self.path)

    def remove_socket(self, socket):
        self.open_sockets.remove(socket)


class SocketConnectionHandler(threading.Thread):
    def __init__(self, sockethandler, connection):
        threading.Thread.__init__(self)
        self.sock = connection[0]
        self.sock.setblocking(0)
        self.client = connection[1]
        self.sockethandler = sockethandler
        self.start()

    def run(self):
        while True:
            try:
                ready_to_read, ready_to_write, in_err = \
                    select.select([self.sock], [], [], 1)
                if self.sock in ready_to_read:
                    command = read(self.sock)
                    if command[0] == COMMAND_LOG:
                        write(self.sock, self.sockethandler.liquiddaemon.get_log(command[1]))
                    elif command[0] == COMMAND_SHUTDOWN:
                        self.sockethandler.liquiddaemon.shutdown()
            except:
                break

        self.close()

    def close(self):
        self.sockethandler.remove_socket(self)
        self.sock.close()


class LiquidDaemonClient(object):
    def __init__(self, path='/tmp/liquiddaemon.sock'):
        self.path = path
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

    def connect(self):
        self.sock.connect(self.path)

    def close(self):
        if self.sock:
            self.sock.close()

    def get_log(self, offset=None):
        command = (COMMAND_LOG, offset)
        write(self.sock, command)
        offset, lines = read(self.sock)
        return offset, lines

    def shutdown_daemon(self):
        command = (COMMAND_SHUTDOWN, )
        write(self.sock, command)
