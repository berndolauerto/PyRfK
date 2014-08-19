class NoConfigException(Exception):
    pass


class UserNotFoundException(Exception):
    pass


class UserNameTakenException(Exception):
    pass


class InvalidUsernameException(Exception):
    pass


class InvalidPasswordException(Exception):
    pass


class InvalidSettingException(Exception):
    def __init__(self, reason):
        self.reason = reason

    def __repr__(self):
        "<rfk.exc.base.InvalidSettingException %s>" % (self.reason,)