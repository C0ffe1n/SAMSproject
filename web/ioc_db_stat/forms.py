from django import forms
import datetime
#from django.db import models
#from .models import ioc_gen


class Formaddioc(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'
    ioc = forms.CharField(label='IOC Name', max_length=100)
    ioc_type = forms.CharField(label='Type', max_length=100)
    ioc_author = forms.CharField(label='Author', max_length=100)
    ioc_dateadd = forms.DateTimeField(label='Date', initial=datetime.datetime.now)
    ioc_source = forms.CharField(label='Source', max_length=1024)
    
class FormSearchIOC(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'
    ioc = forms.CharField(label="IOC Search", max_length=100)
    
class UploadFileForm(forms.Form):
    file_import = forms.FileField()
