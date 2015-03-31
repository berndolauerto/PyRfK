from wtforms import Form, SubmitField, BooleanField, TextField, SelectField, \
    PasswordField, IntegerField, FieldList, FormField, validators


class LoginForm(Form):
    username = TextField('Username', [validators.Required()])
    password = PasswordField('Password', [validators.Required()])
    remember = BooleanField('Remember me')


def login_form(rform):
    return LoginForm(rform)


class RegisterForm(Form):
    username = TextField('Username', [validators.Required()])
    password = PasswordField('Password', [validators.Required(),
                                          validators.Length(min=5, message='Password too short.'),
                                          validators.EqualTo('password_retype', message='Passwords must match.')])
    password_retype = PasswordField('Password (verification)', [validators.Required()])
    email = TextField('E-Mail (optional)', [validators.Optional(), validators.Email()])


def register_form(rform):
    return RegisterForm(rform)
