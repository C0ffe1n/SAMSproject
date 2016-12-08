from django.conf.urls import url

from . import views

urlpatterns = [
    url(r'^$', views.index, name='index'),
    url(r'^ioc_add/$', views.ioc_add, name='ioc_add'),
    url(r'^ioc_search/$', views.ioc_search, name='ioc_search'),
    url(r'^ioc_db_import/$', views.upload_file_form, name='upload_file_form'),
    url(r'^ioc_db_impt/$', views.upload_file, name='upload_file'),
]
