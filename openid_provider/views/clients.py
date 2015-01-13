from django.utils.decorators import method_decorator
from django.views.generic.detail import DetailView
from django.views.generic.list import ListView
from openid_provider.lib.utils.decorators import staff_required
from openid_provider.models import Client


class ClientListView(ListView):

    model = Client

    @method_decorator(staff_required)
    def dispatch(self, *args, **kwargs):
        return super(ClientListView, self).dispatch(*args, **kwargs)

class ClientDetailView(DetailView):

    model = Client