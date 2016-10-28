from hashlib import sha224

from django.conf import settings as django_settings
from django.utils.deprecation import MiddlewareMixin


class SessionManagementMiddleware(MiddlewareMixin):
    """
    Maintain a `op_browser_state` cookie along with the `sessionid` cookie that
    represents the End-User's login state at the OP. If the user is not logged
    in then use `SECRET_KEY` value.
    """

    def process_response(self, request, response):
        session_state = sha224(request.session.session_key or django_settings.SECRET_KEY).hexdigest()
        response.set_cookie('op_browser_state', session_state)
        return response
