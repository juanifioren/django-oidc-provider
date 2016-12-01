# -*- coding: utf-8 -*-
from django.dispatch import Signal


user_accept_consent = Signal(providing_args=['user', 'client', 'scope'])
user_decline_consent = Signal(providing_args=['user', 'client', 'scope'])
