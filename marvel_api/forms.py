from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired,Email

class UserLoginForm(FlaskForm):
    #email, password, submit_button    the empty() means that it needs to be instantiated for it to work
    email = StringField('Email', validators = [DataRequired(),Email()])
    password = PasswordField('Password', validators = [DataRequired()])
    submit_button = SubmitField()