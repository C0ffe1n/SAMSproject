from django.conf.urls import url

from . import views

urlpatterns = [
    url(r'^$', views.index, name='webui'),
    url(r'^machines$', views.get_status, name='get_status'),
    url(r'^ajax$', views.xhr_test, name='xhr_test'),
    #url(r'^search$', views.search, name='search'),
    url(r'^global_search$', views.global_search, name='global_search'),
    url(r'^console_search$', views.console_search, name='console_search'),
    url(r'^detail_id/$', views.global_search_id, name='global_search_id'),
    url(r'^analytics/$', views.analytics, name='analytics'),
    url(r'^create_graph/$', views.create_graph, name='create_graph'),
    url(r'^create_chart/$', views.analytics_charts, name='analytics_charts'),
    url(r'^change_verdict/$', views.change_verdict, name='change_verdict'),
    url(r'^search_verdict/(?P<searchVerdict>[a-z]+)$', views.global_search, name='global_search'),
    url(r'^search_verdict/console_search$', views.console_search, name='console_search'),
    url(r'^search_region/console_search$', views.console_search, name='console_search'),
    url(r'^search_region/(?P<regionCode>[A-Z]+)$', views.global_search, name='global_search'),
    url(r'^search_md5/console_search$', views.console_search, name='console_search'),
    url(r'^search_md5/(?P<searchMd5>[A-Za-z0-9_]+)$', views.global_search, name='global_search'),
    url(r'^search_recipient/console_search$', views.console_search, name='console_search'),
    url(r'^search_recipient/(?P<searchRecipient>[A-Za-z0-9_@.-]+)$', views.global_search, name='global_search'),
    url(r'^search_sender/console_search$', views.console_search, name='console_search'),
    url(r'^search_sender/(?P<searchSender>[A-Za-z0-9_@.-]+)$', views.global_search, name='global_search'),
    url(r'^search_exten/console_search$', views.console_search, name='console_search'),
    url(r'^search_exten/(?P<searchExten>[A-Za-z0-9_@.-]+)$', views.global_search, name='global_search'),
    url(r'^search_mta/console_search$', views.console_search, name='console_search'),
    url(r'^search_mta/(?P<searchMta>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$', views.global_search, name='global_search'),
    url(r'^detail_id/$', views.global_search_id, name='global_search_id'),
    url(r'^detail_id/console_search_id$', views.console_search_id, name='console_search_id'),
    url(r'^detail_id/(?P<searchId>[A-Za-z0-9]+)$', views.global_search_id, name='global_search_id'),
]
