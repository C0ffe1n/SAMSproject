from django.contrib import admin

# Register your models here.
from .models import status_machine
#from .models import cuckoo


class MachineAdmin(admin.ModelAdmin):
    fields = ['date_update','machine_text']
admin.site.register(status_machine, MachineAdmin)

#class CuckooAdmin(admin.ModelAdmin):
    #fields = ['version']
#admin.site.register(cuckoo, CuckooAdmin)

