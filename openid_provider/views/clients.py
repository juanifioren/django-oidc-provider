from django.shortcuts import redirect
from django.shortcuts import render
from django.utils.decorators import method_decorator
from django.views.generic.detail import DetailView
from django.views.generic.edit import CreateView
from django.views.generic.list import ListView
from openid_provider.lib.utils.decorators import staff_required
from openid_provider.models import Client
from random import random
import uuid


class ClientListView(ListView):

    model = Client

    @method_decorator(staff_required)
    def dispatch(self, *args, **kwargs):
        return super(ClientListView, self).dispatch(*args, **kwargs)

class ClientDetailView(DetailView):

    model = Client

    @method_decorator(staff_required)
    def dispatch(self, *args, **kwargs):
        return super(ClientListView, self).dispatch(*args, **kwargs)

@staff_required
def client_create(request):

    error = False

    if request.method == 'POST':

        try:
            client = Client()

            client.name = request.POST.get('name')
            client.client_type = request.POST.get('client_type')
            client.response_type = request.POST.get('response_type')
            client.redirect_uris = request.POST.get('redirect_uris')

            client.client_id = str(random()).split('.')[1][:8]
            client.client_secret = uuid.uuid4().hex

            client.save()

            return redirect('openid_provider:client_list')

        except Exception as e:
            print e
            error = True

    data = {
        'error': error,
    }

    return render(request, 'openid_provider/client_create.html', data)