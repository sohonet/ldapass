import argparse
import datetime
import os
import sqlite3
import sys
import time
import uuid

from configparser import ConfigParser
from flask import Flask, flash, request, render_template, redirect, url_for
import ldap
from flask_wtf import FlaskForm, RecaptchaField
from flask_mail_sendgrid import MailSendGrid
from flask_mail import Message
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, Length

app = Flask('__name__')
app.config['SECRET_KEY'] = os.environ['LDAPASS_SECRET']
app.config['MAIL_SENDGRID_API_KEY'] = os.environ['LDAPASS_MAILKEY']
conf = ConfigParser(interpolation = None)
conf.read(os.environ['LDAPASS_CONFIG'])

DEBUG = False
MIN_PASSWORD_LENGTH = 15

app.config['RECAPTCHA_PUBLIC_KEY'] = os.environ['RECAPTCHA_PUBLIC_KEY']
app.config['RECAPTCHA_PRIVATE_KEY'] = os.environ['RECAPTCHA_PRIVATE_KEY']

flaskmail = MailSendGrid(app)

class EmailForm(FlaskForm):
    mail = StringField('Email address', validators=[DataRequired(), Email()],
                       render_kw={"placeholder": "Your LDAP user email address"})
    recaptcha = RecaptchaField()
    submit = SubmitField("Submit", render_kw={"class": "btn btn-primary"})


class PasswordForm(FlaskForm):
    passwd = PasswordField('New password',
                           validators=[DataRequired(),
                                       EqualTo('passwd_confirm', message="Password confirmation doesn't match the password"),
                                       Length(min=MIN_PASSWORD_LENGTH, message="Password is too short"),
                                       ],
                           render_kw={"placeholder": "Type in desired password"})
    passwd_confirm = PasswordField('Confirm new password',
                                   render_kw={"placeholder": "Retype desired password"})
    submit = SubmitField("Update Password", render_kw={"class": "btn btn-primary"})


def parse_arguments(description=''):
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument('-b', action="store_true", dest="bootstrap", required=False)
    return parser.parse_args()


def send_mail(mail, reset_url):
    msg = Message('LDAP password reset link',
                  sender='noreply@sohonet.com',
                  recipients=[mail])
    msg.body = '''
        Hi,
        Your LDAP password reset link is:
        {reset_url}
        This url will be valid for next 24 hours. If you have any issues, \
        issues with this process, contact a LDAP administrator.
        '''.format(reset_url=reset_url)
    flaskmail.send(msg)

@app.route('/', methods=['GET', 'POST'])
def index():
    error = None
    form = EmailForm()
    if request.method == 'GET':
        return render_template('index.html', error=error, form=form)
    elif request.method == 'POST':
        if form.validate_on_submit():
            ldap_uri = 'ldap://{addr}:{port}'.format(
                addr=conf.get('ldap', 'addr'), port=conf.getint('ldap', 'port'))
            try:
                ldap.set_option(
                    ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
                l = ldap.initialize(
                    ldap_uri, trace_level=conf.getint('app', 'ldap_debug'))
                l.start_tls_s()
            except ldap.LDAPError as error:
                return render_template('index.html', error=error, form=form), 400
            try:
                search_filter = 'mail={mail}'.format(mail=form.mail.data)
                ldap_result_id = l.search(
                    conf.get('ldap', 'basedn'), ldap.SCOPE_SUBTREE,
                    search_filter, None)
            except ldap.LDAPError as error:
                return render_template('index.html', error=error, form=form), 400
            result_type, result_data = l.result(ldap_result_id, 0)
            if len(result_data) == 1:
                link_id = '{uuid}-{account}'.format(
                    uuid=str(uuid.uuid4()),
                    account=form.mail.data.split('@')[0]
                )

                db_conn = sqlite3.connect(conf.get('app', 'database'))
                db_curs = db_conn.cursor()
                db_curs.execute(
                    "SELECT id FROM mails WHERE mail='{mail}'".format(
                        mail=form.mail.data))
                db_data = db_curs.fetchall()
                if len(db_data) == 0:
                    db_curs.execute(
                        "INSERT INTO mails (mail, link_id, created) VALUES \
                        ('{mail}', '{link_id}', '{created}')".format(
                        mail=form.mail.data,
                        link_id=link_id,
                        created=datetime.datetime.now()
                    ))
                    flash('An email containing a password reset URL has been sent \
                        to {mail}'.format(mail=form.mail.data))
                else:
                    db_curs.execute(
                        "DELETE FROM mails WHERE mail='{mail}'".format(
                            mail=form.mail.data))
                    db_curs.execute(
                        "REPLACE INTO mails (mail, link_id, created) VALUES \
                        ('{mail}', '{link_id}', '{created}')".format(
                        mail=form.mail.data,
                        link_id=link_id,
                        created=datetime.datetime.now()
                    ))
                    flash('An Email containing a password reset URL has been sent \
                        to {mail}. Previous reset URLs have been \
                        invalidated.'.format(mail=form.mail.data))
                db_conn.commit()
                db_conn.close()

                reset_url = 'https://{hostname}/reset/{link_id}'.format(
                    hostname=conf.get('app', 'hostname'),
                    port=conf.getint('app', 'listen_port'),
                    link_id=link_id
                )
                send_mail(form.mail.data, reset_url)
            elif len(result_data) > 1:
                error = 'More than one user found with email address of \
                    {mail}. Please get in touch with an LDAP administrator'.format(mail=form.mail.data)
            else:
                error = 'No user found with email address of {mail}.'.format(mail=form.mail.data)
            return render_template('index.html', error=error, form=form), 404

        else:
            error = 'The mail address you have filled is invalid.'
            return render_template('index.html', error=error, form=form), 400


@app.route('/reset/<link_id>', methods=['GET', 'POST'])
def reset(link_id):
    error = None
    form = PasswordForm()

    db_conn = sqlite3.connect(conf.get('app', 'database'))
    db_curs = db_conn.cursor()
    db_curs.execute("SELECT * FROM mails WHERE link_id='{link_id}'".format(
        link_id=link_id))
    db_data = db_curs.fetchall()

    if len(db_data) == 1:
        if request.method == 'GET':
            flash(
                'You are changing password for the account of {mail}'.format(
                    mail=db_data[0][1]))
            return render_template(
                'reset.html',
                error=error,
                form=form,
                link_id=link_id)

        if request.method == 'POST':
            if form.validate_on_submit():
                ldap_uri = 'ldap://{addr}:{port}'.format(
                    addr=conf.get('ldap', 'addr'),
                    port=conf.getint('ldap', 'port')
                )
                try:
                    ldap.set_option(
                        ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
                    l = ldap.initialize(ldap_uri)
                    l.start_tls_s()
                except ldap.LDAPError as error:
                    return render_template('error.html', error=error), 400
                try:
                    search_filter = 'mail={mail}'.format(mail=db_data[0][1])
                    ldap_result_id = l.search(
                        conf.get('ldap', 'basedn'),
                        ldap.SCOPE_SUBTREE,
                        search_filter,
                        None)
                    result_type, result_data = l.result(ldap_result_id, 0)
                    l.simple_bind_s(
                        conf.get('ldap', 'user'), conf.get('ldap', 'pass'))
                    l.passwd_s(
                        'uid={uid},{basedn}'.format(
                            uid=result_data[0][1]['uid'][0].decode(),
                            basedn=conf.get('ldap', 'basedn')),
                        None,
                        '{passwd}'.format(passwd=form.passwd.data))
                except ldap.CONSTRAINT_VIOLATION:
                    error = 'LDAP error: Password does comply with \
                                     the password policy set on your LDAP server' 
                    return render_template(
                        'reset.html',
                        error=error,
                        form=form,
                        link_id=link_id
                    ), 400
                except ldap.LDAPError as error:
                    error = 'LDAP error: {error}'.format(error=error)
                    return render_template(
                        'reset.html',
                        error=error,
                        form=form,
                        link_id=link_id
                    ), 400
                flash('Password for account {mail} has been changed.'.format(
                    mail=db_data[0][1]))
                db_curs.execute(
                    "DELETE FROM mails WHERE link_id='{link_id}'".format(
                        link_id=link_id))
                db_conn.commit()
                db_conn.close()
                return redirect(url_for('index'))
            else:
                error = 'The form is invalid, please try again.'
                return render_template('reset.html', error=error, form=form,
                                       link_id=link_id), 400
    else:
        db_conn.close()
        error = 'There is no such password reset id {link_id}'.format(
            link_id=link_id)
        return render_template('error.html', error=error), 404


if __name__ == '__main__':
    conf = ConfigParser(interpolation = None)
    conf.read(os.environ['LDAPASS_CONFIG'])

    args = parse_arguments()

    # test if the database exists, and create it if not, with proper warning
    db_conn = sqlite3.connect(conf.get('app', 'database'))
    db_curs = db_conn.cursor()
    db_curs.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='mails'")
    if len(db_curs.fetchall()) == 0:
        print((('WARNING: the SQLite file {database} doesnt exist! Sleeping for \
            10 seconds and creating the database file. KILL ME if this is an \
            error!').format(database=conf.get('app', 'database'))))
        time.sleep(10)
        db_curs.execute(
            '''create table mails (
                id      INTEGER PRIMARY KEY,
                mail    VARCHAR(255) NOT NULL COLLATE NOCASE,
                link_id    VARCHAR(512) NOT NULL COLLATE NOCASE,
                created INTEGER DEFAULT NULL);
            ''')
        db_conn.commit()
        print('Created the sqlite file.')
    else:
        print((('SQLite file {database} found.').format(
            database=conf.get('app', 'database'))))
        if args.bootstrap:
            print('WARNING: bootstrap option ignored as SQLite file exists')
    db_conn.close()

    if args.bootstrap:
        sys.exit(0)

    app.run(host=conf.get('app', 'listen_addr'),
            port=conf.getint('app', 'listen_port'), debug=DEBUG)
