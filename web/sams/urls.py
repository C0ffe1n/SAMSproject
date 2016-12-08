from django.conf.urls import include, url
from django.contrib import admin

urlpatterns = [
    # Examples:
    # url(r'^$', 'sams.views.home', name='home'),
    # url(r'^blog/', include('blog.urls')),
    url(r'^webui/', include('webui.urls', namespace="webui")),
    url(r'^admin/', include(admin.site.urls)),
    url(r'^ioc_db_static/', include('ioc_db_stat.urls', namespace="ioc_db_stat")),
]
