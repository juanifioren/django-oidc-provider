from django.utils.decorators import method_decorator
from django.views.generic.list import ListView
from openid_provider.lib.utils.decorators import staff_required
from openid_provider.models import Client


class ClientListView(ListView):

    model = Client
    template_name = "openid_provider/clients.html"

    @method_decorator(staff_required)
    def dispatch(self, *args, **kwargs):
        return super(ClientListView, self).dispatch(*args, **kwargs)