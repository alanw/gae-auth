# -*- coding: utf-8 -*-
# Copyright (c) 2015 Alan Wright. All rights reserved.

from google.appengine.api.mail import EmailMessage


class EmailHelper(object):

    COMPANY = 'Foobar'
    SENDER = 'no-reply@foobar.com'

    @classmethod
    def verify_email(cls, email, name, url):
        sender = '{company} <{sender}>'.format(
            company=cls.COMPANY,
            sender=cls.SENDER)
        to = '{name} <{email}>'.format(
            name=name,
            email=email)
        subject = 'Please verify your email address'
        message = '''
Hello {name},

This email address was used to sign up to {company}. Please verify your email address by clicking the link below.

{url}

Thank you,
The {company} Team
'''
        body = message.format(
            name=name,
            company=cls.COMPANY,
            url=url)

        email_message = EmailMessage(
            sender=sender,
            to=to,
            subject=subject,
            body=body)
        email_message.send()

    @classmethod
    def reset_email(cls, email, name, url):
        sender = '{company} <{sender}>'.format(
            company=cls.COMPANY,
            sender=cls.SENDER)
        to = '{name} <{email}>'.format(
            name=name,
            email=email)
        subject = '{company} password reset request'.format(
            company=cls.COMPANY)
        message = '''
Hello {name},

We received a request to reset your password at {company}. Please click the link below to reset your password.

{url}

Thank you,
The {company} Team
'''
        body = message.format(
            name=name,
            company=cls.COMPANY,
            url=url)

        email_message = EmailMessage(
            sender=sender,
            to=to,
            subject=subject,
            body=body)
        email_message.send()

    @classmethod
    def changed_email(cls, email, name, url):
        sender = '{company} <{sender}>'.format(
            company=cls.COMPANY,
            sender=cls.SENDER)
        to = '{name} <{email}>'.format(
            name=name,
            email=email)
        subject = 'Please verify your email address'
        message = '''
Hello {name},

Your email address was recently changed on {company}. Please verify your email address by clicking the link below.

{url}

Thank you,
The {company} Team
'''
        body = message.format(
            name=name,
            company=cls.COMPANY,
            url=url)

        email_message = EmailMessage(
            sender=sender,
            to=to,
            subject=subject,
            body=body)
        email_message.send()

    @classmethod
    def password_confirm(cls, email, name, url):
        sender = '{company} <{sender}>'.format(
            company=cls.COMPANY,
            sender=cls.SENDER)
        to = '{name} <{email}>'.format(
            name=name,
            email=email)
        subject = '{company} password reset request'.format(
            company=cls.COMPANY)
        message = '''
Hello {name},

This email confirms your recent {company} password change. If your password was changed without your knowledge, then please click the link below to change it again.

{url}

Thank you,
The {company} Team
'''
        body = message.format(
            name=name,
            company=cls.COMPANY,
            url=url)

        email_message = EmailMessage(
            sender=sender,
            to=to,
            subject=subject,
            body=body)
        email_message.send()
