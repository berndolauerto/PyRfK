import os
import sys
import json
import base64
from time import sleep

import sqlalchemy.orm.exc
from flask import Blueprint, request, make_response, abort
from functools import wraps, partial

import requests as http
import xpath
from xml.dom.minidom import parseString

import shelve

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

icesource = Blueprint('icesource', __name__)
logger = init_db_logging('icesource')

# Maybe make this an configurable option?
# TODO: Make this an configurable option!
username_delimiter = '|'

icecast_url = 'http://radio.krautchan.net:8000'
icecast_admin_pw = 'XXXXXXXX'
input_mount = '/live.ogg'


def kick():
    # Check if a source is present. If so, kick the source and 
    # return True. Otherwise return False

    r = http.get('%s/admin/stats' % icecast_url,
        auth = ('admin', icecast_admin_pw))

    if r.status_code == 200:
        doc = parseString(r.text)
        if len(xpath.find('//source[@mount="%s"]' % input_mount, doc)) > 0:
            logger.info('icesource.kick(): Kicking old source')
            session.commit()

            http.get(
                '%s/admin/killsource?mount=%s' % (icecast_url, input_mount),
                auth = ('admin', icecast_admin_pw))

            return True

    return False



def get_source_name_and_description():
    # Get the name and description of the current
    # source stream

    stream_name = ''
    stream_description = ''

    r = http.get('%s/admin/stats' % icecast_url,
        auth = ('admin', icecast_admin_pw))

    if r.status_code == 200:
        doc = parseString(r.text)
        base_xpath = '//source[@mount="%s"]' % input_mount

        try:
            stream_name = xpath.find(
                '%s/server_name/text()' % base_xpath,
                doc
            )[0].nodeValue

        except IndexError:
            pass


        try:
            stream_description = xpath.find(
                '%s/server_description/text()' % base_xpath,
                doc
            )[0].nodeValue

        except IndexError:
            pass

    return (stream_name, stream_description)


def get_track_artist_and_title():
    # Get the name and description of the current
    # source track

    track_artist = ''
    track_title = ''
        
    r = http.get('%s/admin/stats' % icecast_url,
        auth = ('admin', icecast_admin_pw))

    if r.status_code == 200:
        doc = parseString(r.text)
        base_xpath = '//source[@mount="%s"]' % input_mount

        try:
            track_artist = xpath.find(
                '%s/artist/text()' % base_xpath,
                doc
            )[0].nodeValue

        except IndexError:
            pass


        try:
            track_title = xpath.find(
                '%s/title/text()' % base_xpath,
                doc
            )[0].nodeValue

        except IndexError:
            pass

    return (track_artist, track_title)



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



@icesource.route('/auth', methods=['POST'])
def auth():

    if request.form['action'] != 'stream_auth':
        abort(400)

    username = request.form['user']
    password = request.form['pass']

    if username == 'source':
        try:
            username, password = password.split(username_delimiter)
        except ValueError:
            abort(400)

    try:
        user = User.authenticate(username, password)
        show = Show.get_current_show(user)
        if show is not None and show.flags & Show.FLAGS.PLANNED:
            if kick():
                sleep(1)

        persist = shelve.open('/tmp/icesource.shelve')
        persist['authuser'] = username;
        persist.close()

        logger.info('icesource_auth: accepted auth for %s' % username)
        session.commit()
        return make_response('ok', 200, {'icecast-auth-user': '1'})

    except rexc.base.InvalidPasswordException:
        logger.info('icesource_auth: rejected auth for %s (invalid password)' % username)
        session.commit()
        abort(401)

    except rexc.base.UserNotFoundException:
        logger.info('icesource_auth: rejected auth for %s (invalid user)' % username)
        session.commit()
        abort(401)


@icesource.route('/add', methods=['POST'])
def add():
    persist = shelve.open('/tmp/icesource.shelve')
    user = User.get_user(username=persist['authuser'])
    if user.get_setting(code='use_icy'):
        (showname, showdesc) = get_source_name_and_description()
        # FIXME
        #if 'ice-genre' in data:
        #   user.set_setting(data['ice-genre'], code='icy_show_genre')
        if showname != '':
            user.set_setting(showname, code='icy_show_name')
        if showdesc != '':
            user.set_setting(showdesc, code='icy_show_description')

    show = init_show(user)
    persist['sourceuser'] = persist['authuser']
    persist.close()
    logger.info('icesource_connect: accepted connect for %s' % (user.username,))
    session.commit()
    return make_response('ok', 200, {'icecast-auth-user': '1'})


@icesource.route('/remove', methods=['POST'])
def remove():
    persist = shelve.open('/tmp/icesource.shelve')
    user = User.get_user(username=persist['sourceuser'])
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
        persist['sourceuser'] = ''
        session.commit()
    persist.close()

    return make_response('ok', 200, {'icecast-auth-user': '1'})


@icesource.route('/updatemeta')
def updatemeta():
    # This is (for now) actually called by liquidsoap
    # as we don't yet have the metadata hook in icecast
    # Therefore we get the data through another call to
    # the icecast admin interface for now

    (artist, title) = get_track_artist_and_title()

    logger.debug('icesource_updatemeta: %s - %s' % (artist, title))

    persist = shelve.open('/tmp/icesource.shelve')
    user = User.get_user(username=persist['sourceuser'])
    if user is None:
        session.commit()
        return 'user not found'

    show = init_show(user)
    if artist=='' and title=='':
        track = Track.current_track()
        if track:
            track.end_track()
    else:
        track = Track.new_track(show, artist, title)

    session.commit()
    return 'true'
