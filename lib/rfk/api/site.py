import pytz
from time import mktime
from datetime import datetime, timedelta

from sqlalchemy.sql.expression import between
from sqlalchemy import or_

import dateutil.parser
import parsedatetime as pdt

from flask import jsonify, request
from flask.ext.babel import to_user_timezone, to_utc, format_datetime, get_timezone
from flask_login import current_user

import rfk.database
from rfk.database.streaming import Stream
from rfk.database.show import Show, Series, Tag
from rfk.database.track import Track
from rfk.database.streaming import Listener
from rfk.helper import now, to_timestamp, natural_join, make_user_link, iso_country_to_countryball
from rfk.site.helper import permission_required, emit_error
from rfk.api import api


def parse_datetimestring(datestring):
    try:
        return dateutil.parser.parse(datestring).astimezone(pytz.utc)
    except (TypeError, ValueError):
        cal = pdt.Calendar()
        return datetime.fromtimestamp(mktime(cal.parse(datestring)[0]), tz=pytz.utc)


@api.route("/site/listenergraphdata/<string:start>", methods=['GET'], defaults={'stop': 'now'})
@api.route("/site/listenergraphdata/<string:start>/<string:stop>", methods=['GET'])
def listenerdata(start, stop):
    from rfk.site import app

    #app.logger.warn(start)
    #app.logger.warn(stop)
    stop = parse_datetimestring(stop)
    start = parse_datetimestring(start)
    #app.logger.warn(start)
    #app.logger.warn(stop)
    ret = {'data': {}, 'shows': []}

    streams = Stream.query.all()
    for stream in streams:
        ret['data'][str(stream.mount)] = []
        #just set an initial stating point from before the starting point
        stats = stream.statistic.get(stop=start, num=1, reverse=True)
        c = 0
        for stat in stats:
            c = stat.value
        ret['data'][str(stream.mount)].append((to_timestamp(to_user_timezone(start)), int(c)))

    #fill in the actual datapoints
    streams = Stream.query.all()
    for stream in streams:
        stats = stream.statistic.get(start=start, stop=stop)
        for stat in stats:
            ret['data'][str(stream.mount)].append(
                (to_timestamp(to_user_timezone(stat.timestamp)), int(stat.value)))

    streams = Stream.query.all()
    for stream in streams:
        stats = stream.statistic.get(stop=stop, num=1, reverse=True)
        for stat in stats:
            c = stat.value
        if not stats:
            c = 0
        ret['data'][str(stream.mount)].append((to_timestamp(to_user_timezone(stop)), int(c)))

    #get the shows for the graph
    shows = Show.query.filter(between(Show.begin, start, stop) \
                              | between(Show.end, start, stop)).order_by(Show.begin.asc()).all()
    for show in shows:
        sstart = to_timestamp(to_user_timezone(show.begin))
        if show.end:
            send = to_timestamp(to_user_timezone(show.end))
        else:
            send = to_timestamp(to_user_timezone(now()))
        ret['shows'].append({'name': show.name,
                             'b': sstart,
                             'e': send})
    return jsonify(ret)


@api.route('/site/series/query')
@permission_required(ajax=True)
def series_query():
    series = Series.query.filter(Series.name.ilike('%%%s%%' % request.args.get('query')),
                                 or_(Series.public == True, Series.user == current_user)).order_by(
        Series.name.asc()).limit(10)
    ret = []
    for s in series:
        ret.append({'id': s.series, 'name': s.name})

    return jsonify({'success': True, 'data': ret})


@api.route('/site/show/info')
def show_info():
    show = request.args.get('show')
    if show is None:
        return jsonify({'success': False, 'error': 'no show set!'})

    show = Show.query.get(int(show))
    if show is None:
        return jsonify({'success': False, 'error': 'no show found!'})
    ret = {'name': show.name, 'description': show.description,
           'begin': format_datetime(show.begin),
           #'duration': format_timedelta(show.end - show.begin,granularity='minute'),
           'users': []}
    for ushow in show.users:
        ret['users'].append({'username': ushow.user.username,
                             'status': ushow.status})
    return jsonify({'success': True, 'data': ret})


@api.route('/site/show/add', methods=['POST'])
@permission_required(ajax=True)
def show_add():
    try:
        if 'begin' in request.form and \
                        'description' in request.form and \
                        'duration' in request.form and \
                        'title' in request.form:
            if int(request.form['duration']) < 30:
                return emit_error(6, 'Duration too short')
            if int(request.form['duration']) > 1440:
                return emit_error(5, 'Duration too long')
            if len(request.form['title']) < 3:
                return emit_error(4, 'Title too short')
            if len(request.form['description']) == 0:
                return emit_error(3, 'Description is empty')

            begin = to_utc(get_timezone().localize(datetime.utcfromtimestamp(int(request.form['begin']))))
            begin = begin.replace(second=0)
            end = begin + timedelta(minutes=int(request.form['duration']))
            if begin < now():
                return emit_error(2, 'You cannot enter a past date!')
            if Show.query.filter(Show.end > begin, Show.begin < end).count() > 0:
                return emit_error(1, 'Your show collides with other shows')
            show = Show(begin=begin,
                        end=end,
                        name=request.form['title'],
                        description=request.form['description'],
                        flags=Show.FLAGS.PLANNED)
            rfk.database.session.add(show)
            show.add_user(current_user)
            _set_show_info(show, request.form)
            rfk.database.session.commit()
            return jsonify({'success': True, 'data': None})
        else:
            return emit_error(0, 'Wait a second, are you trying to trick me again?!')
    except Exception as e:
        from rfk.site import app

        app.logger.error(e)
        return emit_error(0, 'something went horribly wrong')


@api.route('/site/show/<int:show>/edit', methods=['POST'])
@permission_required(ajax=True)
def show_edit(show):
    if 'begin' in request.form and \
                    'description' in request.form and \
                    'duration' in request.form and \
                    'title' in request.form:
        if int(request.form['duration']) < 30:
            return emit_error(6, 'Duration too short')
        if int(request.form['duration']) > 1440:
            return emit_error(5, 'Duration too long')
        if len(request.form['title']) < 3:
            return emit_error(4, 'Title too short')
        if len(request.form['description']) == 0:
            return emit_error(3, 'Description is empty')
        show = Show.query.get(show)
        if show is None:
            return emit_error(7, 'Whoop, invalid show!')
        if show.get_usershow(current_user) is None:
            return emit_error(8, 'Trying to edit another user\'s show, eh?!')
        begin = to_utc(get_timezone().localize(datetime.utcfromtimestamp(int(request.form['begin']))))
        begin = begin.replace(second=0)
        if begin < now():
            return jsonify({'success': False, 'error': 'You cannot enter a past date!'})
        end = begin + timedelta(minutes=int(request.form['duration']))
        if Show.query.filter(Show.end > begin, Show.begin < end, Show.show != show.show).count() > 0:
            return emit_error(1, 'Your show collides with other shows')
        show.begin = begin
        show.end = end
        _set_show_info(show, request.form)
        rfk.database.session.commit()
    else:
        return emit_error(0, 'Wait a second, are you trying to trick me again?!')
    return jsonify({'success': True, 'data': None})


@api.route('/site/show/<int:show>/delete', methods=['POST'])
@permission_required(ajax=True)
def show_delete(show):
    from rfk.site import app

    app.logger.warn('hnnngggg');
    show = Show.query.get(show)
    if show is None:
        return emit_error(7, 'Whoop, invalid show!')
    if show.get_usershow(current_user) is None:
        return emit_error(8, 'Trying to delete another user\'s show, eh?!')

    app.logger.warn(rfk.database.session.delete(show))

    rfk.database.session.commit()
    return jsonify({'success': True, 'data': None})


def _check_shows(begin, end):
    return Show.query.filter(Show.begin < end, Show.end > begin).all()


def _set_show_info(show, form):
    show.name = form.get('title')
    show.description = form.get('description')
    #series
    if 'series' in form and \
            len(form['series']) and \
                    int(form['series']) > 0:
        series = Series.query.get(int(form['series']))
        if series and (series.public == True or series.user == current_user):
            show.series = series
    else:
        show.series = None
    #tags
    if 'tags[]' in form:
        tags_str = ' '.join(form.getlist('tags[]'))
    else:
        tags_str = ''
    tags = Tag.parse_tags(tags_str)
    show.sync_tags(tags)
    #logo
    if 'logo' in form and \
                    len(form['logo']) > 0:
        show.logo = form['logo']


@api.route('/site/nowplaying')
def now_playing():
    try:
        ret = {}
        #gather showinfos
        show = Show.get_active_show()
        if show:
            user = show.get_active_user()
            if show.end:
                end = to_timestamp(to_user_timezone(show.end))
            else:
                end = None

            ret['show'] = {'id': show.show,
                           'name': show.name,
                           'begin': to_timestamp(to_user_timezone(show.begin)),
                           'now': to_timestamp(to_user_timezone(now())),
                           'end': end,
                           'logo': show.get_logo(),
                           'type': Show.FLAGS.name(show.flags),
                           'user': {'countryball': iso_country_to_countryball(user.country)}
                           }
            if show.series:
                ret['show']['series'] = {'name': show.series.name,
                                          'series': show.series.series}
            link_users = []
            name_users = []
            for ushow in show.users:
                link_users.append(make_user_link(ushow.user))
                name_users.append(ushow.user.username)

            ret['show']['user']['links'] = natural_join(link_users)
            ret['show']['user']['names'] = natural_join(name_users)

        #gather trackinfos
        track = Track.current_track()
        if track:
            ret['track'] = {'title': track.title.name,
                            'artist': track.title.artist.name,
            }

        #gather nextshow infos
        if show and show.end:
            filter_begin = show.end
        else:
            filter_begin = now()
        if request.args.get('full') == 'true':
            nextshow = Show.query.filter(Show.begin >= filter_begin).order_by(Show.begin.asc()).first()
            if nextshow:
                ret['nextshow'] = {'name': nextshow.name,
                                   'begin': to_timestamp(to_user_timezone(nextshow.begin)),
                                   'logo': nextshow.get_logo()}
                if nextshow.series:
                    ret['nextshow']['series'] = {'name': nextshow.series.name,
                                                 'series': nextshow.series.series}

        #get listenerinfo for disco
        listeners = Listener.get_current_listeners()
        ret['listener'] = {}
        for listener in listeners:
            ret['listener'][listener.listener] = {'listener': listener.listener,
                                                  'county': listener.country,
                                                  'countryball': iso_country_to_countryball(listener.country)}
        return jsonify({'success': True, 'data': ret})
    except Exception as e:
        return jsonify({'success': False, 'error': unicode(e)})


try:
    from rfk.armor import get_serviceproxy
    @api.route('/site/donation/getaddress')
    def get_new_address():
        sp = get_serviceproxy()
        return jsonify({'success': True, 'address': sp.getnewaddress()})
except ImportError:
    @api.route('/site/donation/getaddress')
    def get_new_address():
        emit_error(1, 'Bitcoin is not available')
