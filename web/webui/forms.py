from django import forms
from .choices import CHOICES_type, CHOICES_date, CHOICES_map_range, CHOICES_top_range, CHOICES_verdict


class FormSearchID(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'
    search_content = forms.CharField(label="SAMS ID", max_length=100)
    verdict_status = forms.ChoiceField(choices=CHOICES_verdict, required=False)
    
class FormSearchGen(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'
    search_content = forms.CharField(widget=forms.TextInput(attrs={'placeholder': 'Search here...', 'class': 'form-control'}), required=False)
    search_type = forms.ChoiceField(choices=CHOICES_type)
    search_date = forms.ChoiceField(choices=CHOICES_date)
    searchCode = forms.CharField(widget=forms.TextInput(attrs={'placeholder': 'All Regions', 'class': 'form-control'}))
    #SortType = forms.ChoiceField(widget=forms.RadioSelect, choices=CHOICES_sort, initial='Ascending')
    verdict_status = forms.ChoiceField(choices=CHOICES_verdict, initial='all')

class Map_range(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'
    map_range = forms.ChoiceField(choices=CHOICES_map_range, initial='30 Days')

class Top_range(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'
    top_range = forms.ChoiceField(choices=CHOICES_top_range, initial='30 Days')
    
class FormUpdateVerdict(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'
    search_id = forms.CharField(widget=forms.HiddenInput)
    verdict_status = forms.ChoiceField(choices=CHOICES_verdict)
