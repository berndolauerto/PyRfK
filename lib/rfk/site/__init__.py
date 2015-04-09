import datetime
import json

from flask import Flask, g, render_template, flash, redirect, url_for, request, jsonify, abort, send_from_directory, session
from flask.ext.login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask.ext.babel import Babel, get_locale, get_timezone, refresh, lazy_gettext, gettext
from flask_babel import to_user_timezone

from sqlalchemy import func
from sqlalchemy.orm import exc

from . import helper

import pytz
import os

import rfk.helper
from rfk.helper import now, get_secret_key
from rfk.site.helper import paginate_query, Pagination, permission_required
import rfk.database
from rfk.database.base import User, Anonymous, News
from rfk.database.donations import Donation
from rfk.database.streaming import Stream, Listener, Relay
from rfk.site.forms.login import login_form, register_form
from rfk.site.forms.settings import SettingsForm
from rfk.exc.base import UserNameTakenException, UserNotFoundException, InvalidUsernameException
from rfk.database.track import Track
from rfk.database.show import Show, UserShow
from rfk.database.stats import Statistic
from collections import OrderedDict


app = Flask(__name__, instance_relative_config=True)
app.config['DEBUG'] = True
app.config['BABEL_DEFAULT_TIMEZONE'] = 'Europe/Berlin'
app.config['BABEL_DEFAULT_LOCALE'] = 'de'
app.config['BABEL_LOCALE_PATH'] = 'de'
app.secret_key = get_secret_key()

locales = {'de': {'name': 'Bernd',
                  'img': '/static/img/cb/de.png',
                  'datetime_format': 'DD.MM.YYYY HH:mm'},
           'en': {'name': 'English',
                  'img': '/static/img/cb/gb.png',
                  'datetime_format': 'MM/DD/YYYY HH:mm'}}


def get_datetime_format():
    try:
        return locales[str(get_locale())]['datetime_format']
    except KeyError:
        return locales['de']['datetime_format']


# Register Jinja2 filters
app.jinja_env.filters['bbcode'] = helper.bbcode
app.jinja_env.filters['timedelta'] = helper.timedelta
app.jinja_env.filters['naturaltime'] = helper.naturaltime
app.jinja_env.filters['naturaldelta'] = helper.naturaldelta
app.jinja_env.filters['countryball'] = rfk.helper.iso_country_to_countryball
app.jinja_env.filters['countryname'] = rfk.helper.iso_country_to_countryname


# Register Jinja2 globals
app.jinja_env.globals['piwik_url'] = helper.piwik_url()
app.jinja_env.globals['now_playing'] = helper.now_playing
app.jinja_env.globals['get_disco'] = helper.disco
app.jinja_env.globals['url_for_other_page'] = helper.url_for_other_page


babel = Babel(app)


@app.teardown_request
def shutdown_session(exception=None):
    rfk.database.session.rollback()
    rfk.database.session.remove()


@babel.localeselector
def babel_localeselector():
    if hasattr(g, 'current_locale'):
        return g.current_locale
    elif request.cookies.get('locale') is not None:
        return request.cookies.get('locale')
    elif current_user is not None:
        return current_user.get_locale()
    return request.accept_languages.best_match(locales.keys())


@babel.timezoneselector
def babel_timezoneselector():
    if hasattr(g, 'current_timezone'):
        return g.current_timezone
    elif request.cookies.get('timezone') is not None:
        return request.cookies.get('timezone')
    elif current_user is not None:
        return current_user.get_timezone()
    return 'Europe/Berlin'


login_manager = LoginManager()
login_manager.setup_app(app)

login_manager.anonymous_user = Anonymous
login_manager.login_view = "login"
login_manager.login_message = gettext("Please log in to access this page.")
#login_manager.refresh_view = "reauth"

@login_manager.user_loader
def load_user(userid):
    return User.get_user(id=int(userid))


from . import user
app.register_blueprint(user.user, url_prefix='/user')

from . import show
app.register_blueprint(show.show)

from . import admin
app.register_blueprint(admin.admin, url_prefix='/admin')

from . import listen
app.register_blueprint(listen.listen, url_prefix='/listen')

from rfk.api import api
app.register_blueprint(api, url_prefix='/api')

from rfk.feeds import feeds
app.register_blueprint(feeds, url_prefix='/feeds')

from . import streaming
app.register_blueprint(streaming.streaming, url_prefix='/')

from . import backend
app.register_blueprint(backend.backend, url_prefix='/backend')

from . import donation
app.register_blueprint(donation.donation, url_prefix='/donations')

from . import icesource
app.register_blueprint(icesource.icesource, url_prefix='/icesource')


def after_this_request(f):
    if not hasattr(g, 'after_request_callbacks'):
        g.after_request_callbacks = []
    g.after_request_callbacks.append(f)
    return f


@app.after_request
def call_after_request_callbacks(response):
    for callback in getattr(g, 'after_request_callbacks', ()):
        response = callback(response)
    return response


@app.before_request
def before_request():
    if request.method == 'GET':
        if request.args.get('lang') is not None and request.args.get('lang') != '':
            current_user.locale = request.args.get('lang')
            g.current_locale = request.args.get('lang')

            @after_this_request
            def remember_locale(response):
                response.set_cookie('locale', current_user.locale,
                                    expires=datetime.datetime.utcnow() + datetime.timedelta(days=365))
                return response
        if request.args.get('tz') is not None and \
                        request.args.get('tz') in pytz.common_timezones:
            current_user.timezone = request.args.get('tz')
            g.current_timezone = request.args.get('tz')

            @after_this_request
            def remember_timezone(response):
                response.set_cookie('timezone', current_user.timezone)
                return response
    refresh()
    request.current_locale = get_locale()
    request.current_timezone = str(get_timezone())


@app.before_request
def make_menu():
    request.menu = OrderedDict()
    entries = [['index', gettext('Home')], ['listeners', gettext('Listeners')]]

    if current_user.is_authenticated():
        entries.append(['history', gettext('History')])

    for entry in entries:
        request.menu['app.' + entry[0]] = {'name': entry[1],
                                           'url': url_for(entry[0]), 'active': (entry[0] == request.endpoint)}

    for bpname in app.blueprints.keys():
        try:
            menu = app.blueprints[bpname].create_menu(request.endpoint)
            if menu:
                request.menu[bpname] = menu
        except AttributeError:
            pass


@app.errorhandler(404)
def page_not_found(e):
    return render_template('error/404.html', TITLE='404'), 404


@app.route('/')
def index():
    news = News.query.order_by(News.time.desc()).all()
    streams = Stream.query.all()
    return render_template('index.html', TITLE=gettext('Index'), news=news, streams=streams)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = login_form(request.form)
    if request.method == 'POST' and form.validate():
        username = form.username.data
        try:
            user = User.get_user(username=username)
            if user and user.check_password(password=form.password.data):
                user.authenticated = True
                remember = form.remember.data
                if login_user(user, remember=remember):
                    if not user.last_login:
                        flash(gettext('<strong>Tip:</strong> It appears that this is your first login, if you need any help please visit our help section by clicking <a href="/help">here</a>.'), 'info')
                    user.last_login = now()
                    loc = rfk.helper.get_location(request.remote_addr)
                    if 'country_code' in loc and loc['country_code'] is not None:
                        user.country = loc['country_code']
                    rfk.database.session.commit()
                    flash(gettext('Login successful. Welcome %s!' % user.username), 'success')
                    return redirect(request.args.get('next') or url_for('index'))
                else:
                    form.username.errors.append(gettext('There was an error while logging you in.'))
                    #flash('There was an error while logging you in.', 'error')
            else:
                form.username.errors.append(gettext('Invalid User or Password.'))
                #flash('Invalid username or password.')
        except UserNotFoundException:
            form.username.errors.append(gettext('Invalid User or Password.'))
            #flash('Invalid username or password.')
    return render_template('login.html', form=form, TITLE=gettext('Login'))


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash(gettext('Logout successful. See you soon!'), 'success')
    return redirect(url_for('index'))


@app.route("/register", methods=["GET", "POST"])
def register():
    form = register_form(request.form)
    if request.method == "POST" and form.validate():
        try:
            user = User.add_user(form.username.data, form.password.data)
            if form.email.data:
                user.mail = form.email.data
            rfk.database.session.commit()
            flash(gettext('Registration successful. You can now login!'), 'success')
            return redirect(url_for("login"))
        except UserNameTakenException:
            form.username.errors.append(gettext('Username already taken!'))
        except InvalidUsernameException:
            form.username.errors.append(gettext('Username invalid!'))

    return render_template("register.html", form=form, TITLE=gettext('Register'))


@app.route('/settings', methods=['get', 'post'])
@login_required
def settings():
    form = SettingsForm(request.form,
                        username=current_user.username,
                        email=current_user.mail,
                        show_def_name=current_user.get_setting(code='show_def_name'),
                        show_def_desc=current_user.get_setting(code='show_def_desc'),
                        show_def_tags=current_user.get_setting(code='show_def_tags'),
                        show_def_logo=current_user.get_setting(code='show_def_logo'),
                        use_icy=current_user.get_setting(code='use_icy'))

    if request.method == "POST" and form.validate():
        if current_user.check_password(password=form.old_password.data):
            if form.new_password.data:
                current_user.password = User.make_password(form.new_password.data)
            current_user.mail = form.email.data
            current_user.set_setting(code='show_def_name', value=form.show_def_name.data)
            current_user.set_setting(code='show_def_desc', value=form.show_def_desc.data)
            current_user.set_setting(code='show_def_tags', value=form.show_def_tags.data)
            current_user.set_setting(code='show_def_logo', value=form.show_def_logo.data)
            current_user.set_setting(code='use_icy', value=form.use_icy.data)
            rfk.database.session.commit()
            flash(gettext('Settings successfully updated.'), 'success')
            return redirect(url_for('settings'))
        else:
            form.old_password.errors.append(gettext('Wrong password.'))

    return render_template('settings.html', form=form, TITLE=gettext('Settings'),
                           imgur={'client': rfk.CONFIG.get('site', 'imgur-client')})


@app.route('/irc')
def irc():
    return render_template('irc.html', TITLE='IRC')


@app.route('/help')
def help():
    return render_template('help.html', TITLE='Help')


@app.route('/history/', defaults={'page': 1})
@app.route('/history/page/<int:page>')
@login_required
def history(page):
    per_page = 25
    (tracks, total_count) = paginate_query(Track.query.join(Show).join(UserShow).order_by(Track.end.desc()), page=page, per_page=per_page)
    pagination = Pagination(page, per_page, total_count)
    return render_template('history.html', tracks=tracks, pagination=pagination, TITLE=gettext('History'))


@app.route('/donations')
def donations():
    return redirect(url_for("donation.list"))


@app.route('/stats')
def stats():
    #>>> session.query(Listener).filter(Listener.useragent.like('%iTunes%')).count()
    countries = rfk.database.session.query(Listener.country, func.count('*')).group_by(Listener.country).filter(Listener.country != None, Listener.country != 'DE').all()
    return render_template('stats.html', countries=json.dumps(countries), TITLE=gettext('Stats'))


@app.route('/listeners')
def listeners():

    # check if current_user is logged in and if user is streaming or if user is admin
    if not current_user.is_anonymous():
        is_streaming = UserShow.query.join(User).filter(UserShow.status == UserShow.STATUS.STREAMING, UserShow.user == current_user).first()
        if is_streaming or current_user.has_permission('admin'):
            show_listener_list = True
        else:
            show_listener_list = False
    else:
        show_listener_list = False

    # get current bandwidth of all active relays
    total_bandwidth = 0
    relays = Relay.query.filter(Relay.status == Relay.STATUS.ONLINE).all()
    active_relays = len(relays)
    for relay in relays:
        total_bandwidth += relay.usage
    total_bandwidth *= 128 # convert kbit to byte

    # get all current listeners
    current_listener = Listener.get_current_listeners()

    # generate per country stats
    per_country = {}
    for listener in current_listener:
        country = listener.country
        try:
            per_country[country]['count'] += 1
        except KeyError:
            per_country[country] = {'count': 1}
            per_country[country]['ball'] = country
    per_country = sorted(per_country.iteritems(), key=lambda (k, v): v['count'], reverse=True)

    # get recent listener count to calculate a trend
    try:
        stats_total = Statistic.query.filter(Statistic.identifier == 'lst-total').one()
        stats = stats_total.get(start=now() - datetime.timedelta(minutes=5), stop=now())
    except exc.NoResultFound:
        stats = None

    if stats and stats.count() > 0:
        listener_sum = 0
        for stat in stats:
            listener_sum += stat.value
        average_listeners = listener_sum / stats.count()
    else:
        average_listeners = len(current_listener)

    return render_template('listenergraph.html', TITLE=gettext('Listeners'), show_listener_list=show_listener_list,
                           listeners=current_listener, per_country=per_country, total_bandwidth=total_bandwidth,
                           active_relays=active_relays, average_listeners=average_listeners)


@app.route('/player5')
@app.route('/player')
def html5player():
    '''legacy url'''
    return redirect(url_for("listen.html5_player"))


@app.route('/api/')
@app.route('/api/index.php')
def api_legacy():
    '''lazy people...'''

    apikey = request.args.get("apikey")
    if apikey != '86c6c5162aa6845906cff55320ea8608991358c3':
        return ''

    #ltid=0&w=track%2Clistener%2Cdj%2Cshow%2Cnextshows,
    ret = {}
    listeners = Listener.query.filter(Listener.disconnect == None).all()
    tmp = {}
    for listener in listeners:
        if listener.stream_relay.stream.code in tmp:
            tmp[listener.stream_relay.stream.code]['c'] += 1
        else:
            tmp[listener.stream_relay.stream.code] = {'c': 1,
                                                      'name': listener.stream_relay.stream.code,
                                                      'description': listener.stream_relay.stream.name}
    ret['listener'] = tmp.values()

    currtrack = Track.current_track()
    ltid = request.args.get("apikey")
    if currtrack and ltid != currtrack.track:
        ret['trackid'] = currtrack.track
        ret['title'] = currtrack.title.name
        ret['artist'] = currtrack.title.artist.name

    show = Show.get_active_show()
    if show:
        user = show.get_active_user()
        ret['dj'] = user.username
        ret['djid'] = user.user
        ret['status'] = 'STREAMING'
        ret['showbegin'] = int(to_user_timezone(show.begin).strftime("%s"))
        if show.end:
            ret['showend'] = int(to_user_timezone(show.end).strftime("%s"))
        else:
            ret['showend'] = None
        ret['showtype'] = 'PLANNED'
        ret['showname'] = show.name
        ret['showdescription'] = show.description
        ret['showid'] = show.show
        ret['showthread'] = None
        ret['showdj'] = user.username
        ret['showdjid'] = user.user

    ret['shows'] = []
    if show and show.end:
        filter_begin = show.end
    else:
        filter_begin = now()
    nextshow = Show.query.filter(Show.begin >= filter_begin).order_by(Show.begin.asc()).first()
    if nextshow:
        arr = {}
        arr['showbegin'] = int(to_user_timezone(nextshow.begin).strftime("%s"))
        if nextshow.end:
            arr['showend'] = int(to_user_timezone(nextshow.end).strftime("%s"))
        else:
            arr['showend'] = None
        arr['showtype'] = 'PLANNED'
        arr['showname'] = nextshow.name
        arr['showdescription'] = nextshow.description
        arr['showid'] = nextshow.show
        arr['showdj'] = nextshow.users[0].user.username
        arr['showdjid'] = nextshow.users[0].user.user
        arr['showthread'] = None
        ret['shows'].append(arr)

    return jsonify(ret)


@app.route('/robots.txt')
@app.route('/favicon.ico')
def static_from_root():
    return send_from_directory(app.static_folder, request.path[1:])
