#!/usr/bin/env python

"""

    rfk.liquidsoaphandler
    ~~~~~~~~~~~~~~~~~~~~~

    ALL YOUR LIQUID SOAP ARE BELONG TO US

    Flow is like this:
        Auth: streaming client tries to authenticate
        Connect: streaming of data starts
        Meta: Metadata (ATTENTION: not all clients send metadata!)
        Disconnect: streaming client disconnects

"""

import argparse
import json
import sys
import base64

import redis
import redis.exceptions

import shelve

import os
basedir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.join(basedir, 'lib'))

import rfk
import rfk.database
from rfk.database.base import User, Loop
from rfk.database.show import Show, Tag, UserShow
from rfk.database.track import Track
from rfk.database.streaming import Listener
from rfk.liquidsoap import LiquidInterface
from rfk import exc as rexc
from rfk.helper import get_path
from rfk.log import init_db_logging


class RfKRedisPub(object):
    """Publish changes of tracks or shows via redis"""

    def __init__(self, channel='rfk-event'):
        self.redis = redis.StrictRedis(host='127.0.0.1', port=6379)
        self.channel = channel

    def _publish(self, channel, message):
        try:
            return self.redis.publish(channel, message)
        except redis.exceptions.ConnectionError:
            return False

    def track_change(self, track_id=None):
        if track_id is not False:
            self._publish(self.channel, {'event': 'track_change', 'track_id': track_id})

    def show_change(self, show_id=None):
        if show_id is not False:
            self._publish(self.channel, {'event': 'show_change', 'show_id': show_id})


username_delimiter = '|'
publish = None
logger = None


def kick():
    """Shorthand method for kicking the currently connected user
    
    returns True if someone was kicked
    returns False if harbor was empty or kick failed
    """

    logger.info('kick: trying to kick source')
    liquidsoap = LiquidInterface()
    liquidsoap.connect()
    kicked = liquidsoap.kick_harbor()
    liquidsoap.close()
    logger.info('kick: result is %s' % kicked)
    return kicked


def init_show(user):
    """Initializes a show

        it either takes a planned show or an unplanned show if it's still running
        if non of them is found a new unplanned show is added and initialized
        if a new show was initialized the old one will be ended and the streamer status will be resetted
    """

    show = Show.get_current_show(user)
    if show is None:
        show = Show()
        if user.get_setting(code='use_icy'):
            show.add_tags(Tag.parse_tags(user.get_setting(code='icy_show_genre') or ''))
            show.description = user.get_setting(code='icy_show_description') or ''
            show.name = user.get_setting(code='icy_show_name') or ''
        else:
            show.add_tags(Tag.parse_tags(user.get_setting(code='show_def_tags') or ''))
            show.description = user.get_setting(code='show_def_desc') or ''
            show.name = user.get_setting(code='show_def_name') or ''
        show.logo = user.get_setting(code='show_def_logo') or None
        show.flags = Show.FLAGS.UNPLANNED
        show.add_user(user)
    elif show.flags == Show.FLAGS.UNPLANNED:
        # just check if there is a planned show to transition to
        s = Show.get_current_show(user, only_planned=True)
        if s is not None:
            show = s
    us = show.get_usershow(user)
    us.status = UserShow.STATUS.STREAMING
    rfk.database.session.commit()
    unfinished_shows = UserShow.query.filter(UserShow.status == UserShow.STATUS.STREAMING,
                                             UserShow.show != show).all()
    for us in unfinished_shows:
        if us.show.flags & Show.FLAGS.UNPLANNED:
            us.show.end_show()
        if us.status == UserShow.STATUS.STREAMING:
            us.status = UserShow.STATUS.STREAMED
        rfk.database.session.commit()
    return show


def doAuth(username, password):
    """Authenticates a user

    This function will also disconnect the current user
    if the user to be authenticated has a show registered.
    If that happens this function will print false to the
    user since we need a grace period to actually disconnect
    the other user. (Which means that the user has to reconnect.)
    
    Keyword arguments:
        - username
        - password
    """

    if username == 'source':
        try:
            username, password = password.split(username_delimiter)
        except ValueError:
            pass
    try:
        user = User.authenticate(username, password)
        show = Show.get_current_show(user)
        if show is not None and show.flags & Show.FLAGS.PLANNED:
            logger.info('doAuth: cleaning harbor because of planned show')
            if kick():
                sys.stdout.write('false')
                logger.info('doAuth: harbor is now clean, reconnect pl0x')
                rfk.database.session.commit()
                return
            else:
                logger.info('doAuth: harbor was empty, go ahead')
        logger.info('doAuth: accepted auth for %s' % username)
        sys.stdout.write('true')
    except rexc.base.InvalidPasswordException:
        logger.info('doAuth: rejected auth for %s (invalid password)' % username)
        sys.stdout.write('false')
    except rexc.base.UserNotFoundException:
        logger.info('doAuth: rejected auth for %s (invalid user)' % username)
        sys.stdout.write('false')

    rfk.database.session.commit()


def doMetaData(data):
    publish_track = False
    logger.debug('doMetaData: %s' % (json.dumps(data),))
    #if 'userid' not in data or data['userid'] == 'none':
    #    print 'no userid'
    #    rfk.database.session.commit()
    #    return
    #user = User.get_user(id=data['userid'])
    persist = shelve.open('/tmp/icesource.shelve')
    user = User.get_user(username=persist['sourceuser'])
    persist.close()
    
    if user == None:
        print 'user not found'
        rfk.database.session.commit()
        return

    if 'artist' in data:
        artist = data['artist'].strip()
    else:
        artist = None

    if 'title' in data:
        title = data['title'].strip()
    else:
        title = None

    if 'song' in data:
        song = data['song'].split(' - ', 1)
        if (artist is None) or (len(artist) == 0):
            artist = song[0]
        if (title is None) or (len(title) == 0):
            title = song[1]

    show = init_show(user)
    if artist is None and title is None:
        track = Track.current_track()
        if track:
            track.end_track()
            publish_track = None
    else:
        track = Track.new_track(show, artist, title)
        publish_track = track.track

    rfk.database.session.commit()
    publish.track_change(publish_track)


def doConnect(data):
    """Handles a connect from liquidsoap
    
    Keyword arguments:
        data -- list of headers
    """
    publish_show = False

    # better to not store any passwords in our logs
    safe_dump = data.copy()
    safe_dump.pop('Authorization', None)
    logger.info('doConnect: connect request %s' % (json.dumps(safe_dump),))

    rfk.database.session.commit()
    try:
        auth = data['Authorization'].strip().split(' ')
        if auth[0].lower() == 'basic':
            try:
                username, password = base64.b64decode(auth[1]).decode('utf-8').split(':', 1)
            except UnicodeDecodeError:
                username, password = base64.b64decode(auth[1]).decode('latin-1').split(':', 1)
            if username == 'source':
                username, password = password.split(username_delimiter, 1)
        else:
            raise ValueError
        user = User.authenticate(username, password)
        if user.get_setting(code='use_icy'):
            if 'ice-genre' in data:
                user.set_setting(data['ice-genre'], code='icy_show_genre')
            if 'ice-name' in data:
                user.set_setting(data['ice-name'], code='icy_show_name')
            if 'ice-description' in data:
                user.set_setting(data['ice-description'], code='icy_show_description')
        show = init_show(user)
        publish_show = show.show
        logger.info('doConnect: accepted connect for %s' % (user.username,))
        print user.user
    except (rexc.base.UserNotFoundException, rexc.base.InvalidPasswordException, KeyError):
        logger.info('doConnect: rejected connect, initiate kick...')
        kick()

    rfk.database.session.commit()
    publish.show_change(publish_show)



def doDisconnect(userid):
    logger.info('doDisconnect: diconnect for userid %s' % (userid,))
    if userid == "none" or userid == '':
        print "Whooops no userid?"
        logger.warn('doDisconnect: no userid supplied!')
        rfk.database.session.commit()
        return
    user = User.get_user(id=int(userid))
    if user:
        usershows = UserShow.query.filter(UserShow.user == user,
                                          UserShow.status == UserShow.STATUS.STREAMING).all()
        for usershow in usershows:
            usershow.status = UserShow.STATUS.STREAMED
            if usershow.show.flags & Show.FLAGS.UNPLANNED:
                usershow.show.end_show()
        rfk.database.session.commit()
        track = Track.current_track()
        if track:
            track.end_track()
            publish.track_change()
        publish.show_change()
        rfk.database.session.commit()
    else:
        print "no user found"


def doPlaylist():
    loop = Loop.get_current_loop()
    print os.path.join(get_path(rfk.CONFIG.get('liquidsoap', 'looppath')), loop.filename)


def doListenerCount():
    lc = Listener.get_total_listener()
    sys.stdout.write("<icestats><source mount=\"/live.ogg\"><listeners>%d</listeners><Listeners>%d</Listeners></source></icestats>" % (lc, lc,))


def decode_json(jsonstr):
    try:
        jsonstr = jsonstr.decode('utf-8')
    except UnicodeDecodeError:
        logger.warn('decode_json: not an utf-8 string: {}'.format(repr(jsonstr)))
        jsonstr = jsonstr.decode('latin-1')
    try:
        return json.loads(jsonstr)
    except ValueError:
        logger.warn('decode_json: failed to decode json {}'.format(repr(jsonstr)))
        raise


def main():
    parser = argparse.ArgumentParser(description='PyRfK Interface for liquidsoap',
                                     epilog='Anyways, this should normally not be called manually')
    parser.add_argument('--debug', action='store_true')
    subparsers = parser.add_subparsers(dest='command', help='sub-command help')

    authparser = subparsers.add_parser('auth', help='a help')
    authparser.add_argument('username')
    authparser.add_argument('password')

    metadataparser = subparsers.add_parser('meta', help='a help')
    metadataparser.add_argument('data', metavar='data', help='mostly some json encoded string from liquidsoap')
    connectparser = subparsers.add_parser('connect', help='a help')
    connectparser.add_argument('data', metavar='data', help='mostly some json encoded string from liquidsoap')
    disconnectparser = subparsers.add_parser('disconnect', help='a help')
    disconnectparser.add_argument('data', metavar='data', help='mostly some json encoded string from liquidsoap')
    playlistparser = subparsers.add_parser('playlist', help='a help')
    listenerparser = subparsers.add_parser('listenercount', help='prints total listenercount')

    args = parser.parse_args()

    rfk.init()
    rfk.database.init_db("%s://%s:%s@%s/%s" % (rfk.CONFIG.get('database', 'engine'),
                                               rfk.CONFIG.get('database', 'username'),
                                               rfk.CONFIG.get('database', 'password'),
                                               rfk.CONFIG.get('database', 'host'),
                                               rfk.CONFIG.get('database', 'database')))
    try:
        global publish
        publish = RfKRedisPub()

        global logger
        logger = init_db_logging('liquidsoaphandler')

        logger.info(args.command)
        rfk.database.session.commit()
        if args.command == 'auth':
            doAuth(args.username, args.password)
        elif args.command == 'meta':
            data = decode_json(args.data)
            doMetaData(data)
        elif args.command == 'connect':
            data = decode_json(args.data)
            doConnect(data)
        elif args.command == 'disconnect':
            data = decode_json(args.data)
            doDisconnect(data)
        elif args.command == 'playlist':
            doPlaylist()
        elif args.command == 'listenercount':
            doListenerCount()

    except Exception as e:
        rfk.database.session.rollback()
        exc_type, exc_value, exc_tb = sys.exc_info()
        import traceback

        logger.error(''.join(traceback.format_exception(exc_type, exc_value, exc_tb)))
        rfk.database.session.commit()

    finally:
        rfk.database.session.rollback()
        rfk.database.session.remove()


if __name__ == '__main__':
    sys.exit(main())
