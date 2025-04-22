from django.contrib.sites.shortcuts import get_current_site
from django.contrib.auth.tokens import default_token_generator as token_generator
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from django.template.loader import render_to_string
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import os

SMTP_SERVER="smtp.mail.ru"
SMTP_PORT=587

def send_email_for_verify(request, user):
    email = os.getenv('EMAIL_USER')
    email_pass = os.getenv('EMAIL_PASS')
    current_site = get_current_site(request)
    context = {
        'user': user,
        'domain': current_site.domain,
        'uid': urlsafe_base64_encode(force_bytes(user.pk)),
        'token': token_generator.make_token(user),
    }
    message = render_to_string(
        'registration/verify_email.html',
        context=context,
    )

    mail = MIMEMultipart('alternative')
    mail['Subject'] = "Подтверждение учётной записи Datum"
    mail['From'] = email.strip()
    mail['To'] = ', '.join(str(user.email))
    mail.attach(MIMEText(message, 'html'))

    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.ehlo()
        server.starttls()
        server.login(email, email_pass)
        server.sendmail(email.strip(), str(user.email), message.as_string())

    print(f"Письмо отправлено на: {str(user.email)}")