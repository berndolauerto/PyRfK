import time
import hashlib
from datetime import timedelta

from passlib.hash import bcrypt

from sqlalchemy import *
from sqlalchemy.orm import relationship, backref, exc
from sqlalchemy.dialects.mysql import INTEGER as Integer
from sqlalchemy.ext.hybrid import hybrid_property, hybrid_method
from sqlalchemy.sql.expression import case

import re
import os

from flask.ext.login import AnonymousUserMixin

import rfk.database
from rfk.types import SET, ENUM
from rfk import exc as rexc
from rfk import CONFIG
from rfk.database import Base, UTCDateTime
from rfk.database.show import UserShow, Show
from rfk.helper import now, get_path


class Anonymous(AnonymousUserMixin):
    def __init__(self):
        AnonymousUserMixin.__init__(self)
        self.locale = 'de'
        self.timezone = 'Europe/Berlin'

    def get_locale(self):
        return self.locale

    def get_timezone(self):
        return self.timezone

    def has_permission(self, code=None, permission=None):
        return False


class User(Base):
    __tablename__ = 'users'
    user = Column(Integer(unsigned=True), primary_key=True, autoincrement=True)
    username = Column(String(50), unique=True)
    password = Column(String(64))
    mail = Column(String(255))
    country = Column(String(3))

    register_date = Column(UTCDateTime, default=now)
    last_login = Column(UTCDateTime, default=None)

    def get_id(self):
        return unicode(self.user)

    def is_anonymous(self):
        return False

    def is_active(self):
        return True

    def is_authenticated(self):
        return True

    def get_locale(self):
        return self.get_setting(code='locale')

    def get_timezone(self):
        return self.get_setting(code='timezone')

    @staticmethod
    def authenticate(username, password):
        """shorthand function for authentication a user
        returns the user object
        
        Keyword arguments:
        username -- username
        password -- unencrypted password
        """
        user = User.get_user(username=username)
        if user.check_password(password):
            return user
        else:
            raise rexc.base.InvalidPasswordException()


    @staticmethod
    def get_user(id=None, username=None):
        assert id or username
        try:
            if username is None:
                return User.query.filter(User.user == id).one()
            else:
                return User.query.filter(User.username == username).one()
        except exc.NoResultFound:
            raise rexc.base.UserNotFoundException

    @staticmethod
    def check_username(username):
        if re.match('^[0-9a-zA-Z_-]{3,}$', username) is None:
            return False
        else:
            return True

    @staticmethod
    def make_password(password):
        return bcrypt.encrypt(password)

    @staticmethod
    def add_user(username, password):
        if not User.check_username(username):
            raise rexc.base.InvalidUsernameException
        try:
            User.query.filter(User.username == username).one()
            raise rexc.base.UserNameTakenException()
        except exc.NoResultFound:
            user = User(username=username, password=User.make_password(password))
            rfk.database.session.add(user)
            rfk.database.session.flush()
            return user

    def check_password(self, password):
        try:
            return bcrypt.verify(password, self.password)
        except ValueError:
            if hashlib.sha1(password).hexdigest() == self.password:
                self.password = User.make_password(password)
                return True
            else:
                return False

    def add_permission(self, code=None, permission=None):
        assert code or permission
        if permission is None:
            permission = Permission.get_permission(code)
        try:
            UserPermission.query.filter(UserPermission.user == self,
                                        UserPermission.permission == permission) \
                .one()
            return False
        except exc.NoResultFound:
            self.permissions.append(UserPermission(permission))
            return True

    def has_permission(self, code=None, permission=None):
        assert code or permission
        if permission is None:
            permission = Permission.get_permission(code)
        try:
            UserPermission.query.filter(UserPermission.user == self,
                                        UserPermission.permission == permission) \
                .one()
            return True
        except exc.NoResultFound:
            return False

    def get_setting(self, setting=None, code=None):
        assert setting or code
        if setting is None:
            setting = Setting.get_setting(code)
        try:
            us = UserSetting.query.filter(UserSetting.user == self,
                                          UserSetting.setting == setting).one()
            return us.get_value()
        except exc.NoResultFound:
            return None

    def set_setting(self, value, setting=None, code=None):
        assert setting or code
        if setting is None:
            setting = Setting.get_setting(code)
        UserSetting.set_value(self, setting, value)
        rfk.database.session.flush()

    def get_total_streamtime(self):
        """Returns a timedelta Object with the users total time streamed"""
        try:
            return timedelta(seconds= float(rfk.database.session
                .query( func.sum( func.time_to_sec( func.timediff(Show.end,Show.begin) ) ) ) \
                .join(UserShow).filter(UserShow.status == UserShow.STATUS.STREAMED,
                                       UserShow.user == self).first()[0]))
        except TypeError:
            return timedelta(seconds=0)

    def __repr__(self):
        return "<USER username={0}>".format(self.username)


class Setting(Base):
    __tablename__ = 'settings'
    setting = Column(Integer(unsigned=True), primary_key=True, autoincrement=True)
    code = Column(String(25), unique=True)
    name = Column(String(50))
    val_type = Column(Integer(unsigned=True))
    TYPES = ENUM(['INT', 'STR'])

    @staticmethod
    def get_setting(code):
        return Setting.query.filter(Setting.code == code).one()

    @staticmethod
    def add_setting(code, name, val_type):
        try:
            return Setting.query.filter(Setting.code == code).one()
        except exc.NoResultFound:
            return Setting(code=code, name=name, val_type=val_type)


class UserSetting(Base):
    __tablename__ = 'user_settings'
    userSetting = Column(Integer(unsigned=True), primary_key=True, autoincrement=True)
    user_id = Column("user", Integer(unsigned=True), ForeignKey('users.user',
                                                                onupdate="CASCADE",
                                                                ondelete="RESTRICT"))
    user = relationship("User", backref=backref('settings'))
    setting_id = Column("setting", Integer(unsigned=True),
                        ForeignKey('settings.setting',
                                   onupdate="CASCADE",
                                   ondelete="RESTRICT"))
    setting = relationship("Setting")
    val_int = Column(Integer)
    val_str = Column(String(255))

    def get_value(self):
        if self.setting.val_type == Setting.TYPES.INT:
            return self.val_int
        elif self.setting.val_type == Setting.TYPES.STR:
            return self.val_str

    @staticmethod
    def set_value(user, setting, value):
        if value == True:
            value = 1
        elif value == False:
            value = 0
        try:
            us = UserSetting.query.filter(UserSetting.user == user,
                                          UserSetting.setting == setting).one()
        except exc.NoResultFound:
            us = UserSetting(user=user, setting=setting)
        if us.setting.val_type == Setting.TYPES.INT:
            us.val_int = value
        elif us.setting.val_type == Setting.TYPES.STR:
            us.val_str = value


class Permission(Base):
    __tablename__ = 'permissions'
    permission = Column(Integer(unsigned=True), primary_key=True, autoincrement=True)
    code = Column(String(25), unique=True)
    name = Column(String(50))

    @staticmethod
    def get_permission(code):
        return Permission.query.filter(Permission.code == code).one()

    @staticmethod
    def add_permission(code, name):
        try:
            return Permission.query.filter(Permission.code == code).one()
        except exc.NoResultFound:
            return Permission(code=code, name=name)


class UserPermission(Base):
    __tablename__ = 'user_permissions'
    userPermission = Column(Integer(unsigned=True), primary_key=True, autoincrement=True)
    user_id = Column("user", Integer(unsigned=True), ForeignKey('users.user',
                                                                onupdate="CASCADE",
                                                                ondelete="RESTRICT"))
    user = relationship("User", backref=backref('permissions', cascade="all, delete-orphan"))
    permission_id = Column("permission", Integer(unsigned=True),
                           ForeignKey('permissions.permission',
                                      onupdate="CASCADE",
                                      ondelete="RESTRICT"))
    permission = relationship("Permission", backref=backref('users', cascade="all, delete-orphan"))

    def __init__(self, permission):
        self.permission = permission


class Ban(Base):
    __tablename__ = 'bans'
    ban = Column(Integer(unsigned=True), primary_key=True, autoincrement=True)
    user_id = Column("user", Integer(unsigned=True), ForeignKey('users.user',
                                                                onupdate="CASCADE",
                                                                ondelete="RESTRICT"))
    user = relationship("User", backref=backref('bans'))
    range = Column(String(50))
    expiration = Column(UTCDateTime)


class News(Base):
    __tablename__ = 'news'
    news = Column(Integer(unsigned=True), primary_key=True, autoincrement=True)
    time = Column(UTCDateTime, default=now())
    user_id = Column("user", Integer(unsigned=True), ForeignKey('users.user',
                                                                onupdate="CASCADE",
                                                                ondelete="RESTRICT"))
    user = relationship("User")
    title = Column(String(255))
    content = Column(Text)


class ApiKey(Base):
    __tablename__ = 'apikeys'
    apikey = Column(Integer(unsigned=True), primary_key=True, autoincrement=True)
    user_id = Column("user", Integer(unsigned=True), ForeignKey('users.user',
                                                                onupdate="CASCADE",
                                                                ondelete="RESTRICT"))
    user = relationship("User", backref="apikeys")
    key = Column(String(128))
    counter = Column(Integer(unsigned=True), default=0)
    access = Column(UTCDateTime, default=now())
    application = Column(String(128))
    description = Column(String(255))
    flag = Column(Integer(unsigned=True), default=0)
    FLAGS = SET(['DISABLED', 'FASTQUERY', 'KICK', 'BAN', 'AUTH'])

    def gen_key(self):
        c = 0
        while True:
            key = hashlib.sha1("%s%s%d%d" % (self.application, self.description, time.time(), c)).hexdigest()
            if ApiKey.query.filter(ApiKey.key == key).first() == None:
                break
        self.key = key

    @staticmethod
    def check_key(key):

        try:
            apikey = ApiKey.query.filter(ApiKey.key == key).one()
        except (exc.NoResultFound, exc.MultipleResultsFound):
            raise rexc.api.KeyInvalidException()
        if apikey.flag & ApiKey.FLAGS.DISABLED:
            raise rexc.api.KeyDisabledException()
        elif not apikey.flag & ApiKey.FLAGS.FASTQUERY:
            if now() - apikey.access <= timedelta(seconds=1):
                raise rexc.api.FastQueryException(last_access=apikey.access)

        apikey.counter += 1
        apikey.access = now()
        return apikey


class Log(Base):
    __tablename__ = 'log'
    log = Column(Integer(unsigned=True), primary_key=True, autoincrement=True)
    timestamp = Column(UTCDateTime, default=now)
    severity = Column(Integer(unsigned=True))
    module = Column(String(50))
    message = Column(Text)


class Loop(Base):
    __tablename__ = 'loops'
    loop = Column(Integer(unsigned=True), primary_key=True, autoincrement=True)
    begin = Column(Integer(unsigned=True), default=0)
    end = Column(Integer(unsigned=True), default=1440)
    filename = Column(String(50))

    @hybrid_property
    def length(self):
        if (self.end >= self.begin):
            return abs(self.end - self.begin)
        else:
            return abs((self.end + 2400) - self.begin)

    @length.expression
    def length(cls):
        return func.abs(cast(case([(cls.begin <= cls.end, cls.end),
                                   (cls.begin >= cls.end, cls.end + 2400)]), Integer) - cast(cls.begin, Integer))

    @hybrid_method
    def contains(self, point):
        return case([(self.begin <= self.end, (self.begin <= point) & (self.end >= point)),
                     (self.begin >= self.end, (self.begin <= point) | (self.end >= point))])

    @hybrid_property
    def file_exists(self):
        if self.filename is None:
            return False
        return os.path.exists(os.path.join(get_path(CONFIG.get('liquidsoap', 'looppath')), self.filename))

    @staticmethod
    def get_current_loop():
        """
            returns the current loop to be scheduled
            @todo maybe broken ;_;
        """
        n = now()
        #try to find a loop that should be running
        loops = Loop.query.filter(Loop.contains(int(n.hour * 100 + (n.minute / 60.) * 100))).order_by(
            Loop.length.asc()).all()
        for loop in loops:
            if loop.file_exists:
                return loop;
                # we found no loops
                # just try to find the longest one
        loops = Loop.query.order_by(Loop.length.asc()).all()
        for loop in loops:
            if loop.file_exists:
                return loop;
                #okay, now we have a problem, just retun none
        return None
