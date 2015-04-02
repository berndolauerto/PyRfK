import os
import sys
import json
import base64

import sqlalchemy.orm.exc
from flask import Blueprint, request, make_response
from functools import wraps, partial

import rfk
import rfk.database
from rfk.database import session
from rfk.database.base import User, Loop
from rfk.database.show import Show, Tag, UserShow
from rfk.database.track import Track
from rfk.database.streaming import Relay, Stream, StreamRelay, Listener

from rfk.liquidsoap import LiquidInterface

from rfk import exc as rexc
from rfk.helper import get_path, now
from rfk.log import init_db_logging


backend = Blueprint('backend', __name__)
logger = init_db_logging('backend')

# Maybe make this an configurable option?
# TODO: Make this an configurable option!
username_delimiter = '|'


def update_global_statistics():
    try:
        stat = rfk.database.stats.Statistic.query.filter(rfk.database.stats.Statistic.identifier == 'lst-total').one()
    except sqlalchemy.orm.exc.NoResultFound:
        stat = rfk.database.stats.Statistic(name='Overall Listener', identifier='lst-total')
        rfk.database.session.add(stat)
        rfk.database.session.flush()
    stat.set(now(), rfk.database.streaming.Listener.get_total_listener())


"""

    rfk.backend for Icecast2
    ~~~~~~~~~~~~~~~~~~~~~~~~

    ICE ICE BABY! YEAAAAH!

"""


@backend.route('/icecast/auth', methods=['POST'])
def icecast_auth():
    logger.info('icecast_auth: {}'.format(request.form))
    session.commit()
    if request.form['action'] != 'stream_auth':
        return make_response('you just went full retard', 405)
    relay = Relay.get_relay(address=request.form['server'],
                            port=request.form['port'])
    if relay.auth_password == request.form['pass'] and \
                    relay.auth_username == request.form['user']:
        return make_response('ok', 200, {'icecast-auth-user': '1'})
    else:
        return make_response('authentication failed', 401)


@backend.route('/icecast/add', methods=['POST'])
def icecast_add_mount():
    logger.info('icecast_add_mount: {}'.format(request.form))
    session.commit()
    if request.form['action'] != 'mount_add':
        return make_response('you just went full retard', 405)
    relay = Relay.get_relay(address=request.form['server'],
                            port=request.form['port'])
    stream = Stream.get_stream(mount=request.form['mount'])
    if relay and stream:
        stream.add_relay(relay)
        session.flush()

        #Cycle every listener
        relay.get_stream_relay(stream).set_offline()
        session.flush()

        relay.get_stream_relay(stream).status = StreamRelay.STATUS.ONLINE
        relay.status = Relay.STATUS.ONLINE
        session.commit()
        return make_response('ok', 200, {'icecast-auth-user': '1'})
    else:
        return make_response('something strange happened', 500)


@backend.route('/icecast/remove', methods=['POST'])
def icecast_remove_mount():
    logger.info('icecast_remove_mount: {}'.format(request.form))
    session.commit()
    if request.form['action'] != 'mount_remove':
        return make_response('you just went full retard', 405)
    relay = Relay.get_relay(address=request.form['server'],
                            port=request.form['port'])
    stream = Stream.get_stream(mount=request.form['mount'])
    if relay and stream:
        stream.add_relay(relay)
        stream_relay = relay.get_stream_relay(stream)
        stream_relay.set_offline()
        session.flush()
        relay.update_statistic()
        stream.update_statistic()
        relay.get_stream_relay(stream).update_statistic()
        update_global_statistics()
        session.commit()
        return make_response('ok', 200, {'icecast-auth-user': '1'})
    else:
        return make_response('something strange happened', 500)


@backend.route('/icecast/listenerremove', methods=['POST'])
def icecast_remove_listener():
    #logger.info('icecast_remove_listener: {}'.format(request.form))
    #session.commit()
    if request.form['action'] != 'listener_remove':
        return make_response('you just went full retard', 405)
    relay = Relay.get_relay(address=request.form['server'],
                            port=request.form['port'])
    stream = Stream.get_stream(mount=request.form['mount'])
    listener = Listener.get_listener(relay.get_stream_relay(stream), int(request.form['client']))
    listener.set_disconnected()
    session.flush()
    relay.update_statistic()
    stream.update_statistic()
    relay.get_stream_relay(stream).update_statistic()
    update_global_statistics()
    session.commit()
    return make_response('ok', 200, {'icecast-auth-user': '1'})


@backend.route('/icecast/listeneradd', methods=['POST'])
def icecast_add_listener():
    #logger.info('icecast_add_listener: {}'.format(request.form))
    #session.commit()
    if request.form['action'] != 'listener_add':
        return make_response('you just went full retard', 405)
    relay = Relay.get_relay(address=request.form['server'],
                            port=request.form['port'])
    stream = Stream.get_stream(mount=request.form['mount'])
    listener = Listener.create(request.form['ip'], request.form['client'], request.form['agent'],
                               relay.get_stream_relay(stream))
    session.add(listener)
    session.flush()
    relay.update_statistic()
    stream.update_statistic()
    relay.get_stream_relay(stream).update_statistic()
    update_global_statistics()
    session.commit()
    return make_response('ok', 200, {'icecast-auth-user': '1'})


"""

    rfk.backend for liquidsoap
    ~~~~~~~~~~~~~~~~~~~~~~~~~~

    ALL YOUR LIQUID SOAP ARE BELONG TO US

    Flow is like this:
        Auth: a new client tries to authenticate
        Connect: transmission of streaming data begins
        Meta: track changes (ATTENTION: not all clients send metadata!)
        Disconnect: the connected client disconnects

"""


def liquidsoap_decorator(f=None):
    """Decorator for auth and error handling

    This decorator will check the header of incoming requests for the
    backend password in the 'key' field, which is specified in the config file.
    It will also wrap every request in a try/except block to perform a rollback
    in case there was an error with the request to keep the database safe.
    """

    if f is None:
        return partial(liquidsoap_decorator)

    @wraps(f)
    def decorated_function(*args, **kwargs):

        if 'key' not in request.headers:
            return 'false'

        key = request.headers.get('key')
        if key != rfk.CONFIG.get('liquidsoap', 'backendpassword'):
            # TODO: return appropriate status code
            return "false"

        try:
            return f(*args, **kwargs)
        except Exception as e:
            session.rollback()
            exc_type, exc_value, exc_tb = sys.exc_info()
            import traceback

            logger.error(''.join(traceback.format_exception(exc_type, exc_value, exc_tb)))
            session.commit()
        finally:
            session.rollback()

    return decorated_function


def kick():
    """Shorthand method for kicking the currently connected user

    Returns True if someone was kicked successfully
    Returns False if harbor was empty or the kick failed
    """

    # TODO: kick() should also create a time ban, otherwise the kicked client can reconnect immediately.
    # NOTE: Maybe we can create a global helper for this, as this may be helpful elsewhere.

    logger.info('kick: trying to kick source')
    liquidsoap = LiquidInterface()
    liquidsoap.connect()
    kicked = liquidsoap.kick_harbor()
    liquidsoap.close()
    logger.info('kick: result is %s' % kicked)
    return kicked


def init_show(user):
    """Initializes a show

    It either takes a planned show or an unplanned show if it's still running
    If non of them is found a new unplanned show is added and initialized
    If a new show was initialized the old one will be ended and the streamer status will be reset
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
    session.commit()
    unfinished_shows = UserShow.query.filter(UserShow.status == UserShow.STATUS.STREAMING,
                                             UserShow.show != show).all()
    for us in unfinished_shows:
        if us.show.flags & Show.FLAGS.UNPLANNED:
            us.show.end_show()
        if us.status == UserShow.STATUS.STREAMING:
            us.status = UserShow.STATUS.STREAMED
        session.commit()
    return show


@backend.route('/liquidsoap/metadata', methods=['POST'])
@liquidsoap_decorator()
def liquidsoap_meta_data():
    """Handles track changes

    Returns error message if something suspicious happens
    Returns 'true' when everything worked like expected
    """

    data = request.get_json()
    logger.debug('liquidsoap_meta_data: %s' % (json.dumps(data),))
    if 'userid' not in data or data['userid'] == 'none':
        session.commit()
        return 'no userid'
    user = User.get_user(id=data['userid'])
    if user is None:
        session.commit()
        return 'user not found'

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
    else:
        track = Track.new_track(show, artist, title)

    session.commit()
    return 'true'


@backend.route('/liquidsoap/playlist')
@liquidsoap_decorator()
def liquidsoap_playlist():
    """Returns the path to the current loop file that should be played

    """

    loop = Loop.get_current_loop()
    return os.path.join(get_path(rfk.CONFIG.get('liquidsoap', 'looppath')), loop.filename)


@backend.route('/liquidsoap/listenercount')
@liquidsoap_decorator()
def liquidsoap_listener_count():
    """This mimics an icecast2 statistic output so clients will display the total listener count

    """

    lc = Listener.get_total_listener()
    return '<icestats><source mount=\"/live.ogg\"><listeners>%d</listeners><Listeners>%d</Listeners></source></icestats>' % (lc, lc,)


@backend.route('/liquidsoap/auth', methods=['POST'])
@liquidsoap_decorator()
def liquidsoap_auth():
    """Authenticates a user

    This function will also disconnect the current user
    if the user to be authenticated has a show registered.
    If that happens this function will print false to the
    user since we need a grace period to actually disconnect
    the other user. Which means that the user has to reconnect!

    Keyword arguments:
        - username
        - password
    """

    data = request.get_json()
    username, password = data['username'], data['password']

    if username == 'source':
        try:
            username, password = password.split(username_delimiter)
        except ValueError:
            pass
    try:
        user = User.authenticate(username, password)
        show = Show.get_current_show(user)
        if show is not None and show.flags & Show.FLAGS.PLANNED:
            logger.info('liquidsoap_auth: cleaning harbor because of planned show')
            if kick():
                logger.info('liquidsoap_auth: harbor is now clean, reconnect pl0x')
                session.commit()
                return 'false'
            else:
                logger.info('liquidsoap_auth: harbor was empty, go ahead')
        logger.info('liquidsoap_auth: accepted auth for %s' % username)
        session.commit()
        return 'true'
    except rexc.base.InvalidPasswordException:
        logger.info('liquidsoap_auth: rejected auth for %s (invalid password)' % username)
        session.commit()
        return 'false'
    except rexc.base.UserNotFoundException:
        logger.info('liquidsoap_auth: rejected auth for %s (invalid user)' % username)
        session.commit()
        return 'false'


@backend.route('/liquidsoap/connect', methods=['POST'])
@liquidsoap_decorator()
def liquidsoap_connect():
    """Handles a client connect from liquidsoap

    Keyword arguments:
        data -- list of headers
    """

    data = request.get_json()

    # better to not store any passwords in our logs
    safe_dump = data.copy()
    safe_dump.pop('Authorization', None)
    logger.info('liquidsoap_connect: connect request %s' % (json.dumps(safe_dump),))

    session.commit()
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
        logger.info('liquidsoap_connect: accepted connect for %s' % (user.username,))
        session.commit()
        return str(user.user)
    except (rexc.base.UserNotFoundException, rexc.base.InvalidPasswordException, KeyError):
        logger.info('liquidsoap_connect: rejected connect, initiate kick...')
        kick()
        session.commit()
        return 'none'


@backend.route('/liquidsoap/disconnect', methods=['POST'])
@liquidsoap_decorator()
def liquidsoap_disconnect():
    """Handles a client disconnect from liquidsoap

    """

    userid = request.get_json()

    logger.info('liquidsoap_disconnect: diconnect for userid %s' % (userid,))
    if userid == 'none' or userid == '':
        logger.warn('liquidsoap_disconnect: no userid supplied!')
        session.commit()
        return 'Whooops no userid?'
    user = User.get_user(id=int(userid))
    if user:
        usershows = UserShow.query.filter(UserShow.user == user,
                                          UserShow.status == UserShow.STATUS.STREAMING).all()
        for usershow in usershows:
            usershow.status = UserShow.STATUS.STREAMED
            if usershow.show.flags & Show.FLAGS.UNPLANNED:
                usershow.show.end_show()
        session.commit()
        track = Track.current_track()
        if track:
            track.end_track()
        session.commit()
        return 'true'
    else:
        return 'no user found'
