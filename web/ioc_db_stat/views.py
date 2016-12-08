from django.shortcuts import render, redirect, render_to_response
from django.core.urlresolvers import reverse
from django.http import HttpResponse, HttpResponseRedirect
from .forms import Formaddioc, FormSearchIOC, UploadFileForm
from django.views.generic.edit import FormView
from django.contrib.auth import authenticate


import datetime
import os
import pymongo
import uuid
import time


os.environ['NO_PROXY'] = '10.17.117.48, 10.17.117.12'
connection = pymongo.MongoClient('localhost', 27017, maxPoolSize=1000)
db = connection.ioc_db_stat

def index(request):
    form = FormSearchIOC()
    request_last_20_index = db.ioc_coll.find().sort('ioc_date_add', pymongo.ASCENDING).limit(20)
    print(db.ioc_coll.find().count())
    
    return render(request, 'index_ioc.html', {'form': form, 'request_last_20_index': request_last_20_index})

def ioc_add(request):
    insert_doc = {}
    number_raw = 0
    context = []
    check_query_double = []
    if request.method == 'POST':
        form = Formaddioc(request.POST)
        if form.is_valid():
            ioc_name = form.cleaned_data['ioc']
            ioc_type = form.cleaned_data['ioc_type']
            ioc_source = form.cleaned_data['ioc_source']
            ioc_author = form.cleaned_data['ioc_author']
            ioc_date_add = request.POST['ioc_dateadd']
            my_id = uuid.uuid3(uuid.NAMESPACE_DNS, ioc_name)
        
            check_search_id = db.ioc_coll.find({ '_id': my_id})

            for row in check_search_id:
                number_raw += 1
                check_query_double.append(row)
            if number_raw == 1:
                not_mess = "This IOC is alredy exist! Check your input >:("
                context = {'form': form, 'check_query_double': check_query_double, 'not_mess': not_mess}
  #             
            else:
                insert_doc = {"_id": my_id, "ioc": ioc_name, "ioc_type": ioc_type, "ioc_source": ioc_source, "ioc_author": ioc_author, "ioc_date_add": ioc_date_add}
                db.ioc_coll.insert(insert_doc)
                reques_last_20 = db.ioc_coll.find().sort('ioc_date_add', pymongo.ASCENDING).limit(20)
                answ_for_insert = "Thanks for add IOC :)"
                form = FormSearchIOC()
                context = {'form': form, 'insert_doc': insert_doc, 'reques_last_20': reques_last_20, 'answ_for_insert': answ_for_insert}
            return render(request, 'index_ioc.html' , context)
    else:
        form = Formaddioc()

    return render(request, 'ioc_add.html', {'form': form, 'context': context})

def ioc_search(request):
    query_search = []
    number_raw = 0
    if request.method == 'POST':
        form = FormSearchIOC(request.POST)
        if form.is_valid():
            ioc_name = form.cleaned_data['ioc']
            search_ioc = uuid.uuid3(uuid.NAMESPACE_DNS, ioc_name)
            request_search_id = db.ioc_coll.find({ '_id': search_ioc})
            for row in request_search_id:
                number_raw += 1
                query_search.append(row)
            if number_raw == 1:
                return render(request, 'index_ioc.html', {'form': form, 'query_search': query_search})
            else:
                form = Formaddioc(initial={'ioc': ioc_name})

                return render(request, 'ioc_add.html', {'form': form, 'ioc_name' : ioc_name})

            return redirect('ioc_db_stat:index')
    return render(request, 'index_ioc.html', {'form': form})

def upload_file_form(request):
    form = UploadFileForm()
    return render(request, 'ioc_import.html', {'form': form})

def upload_file(request):
    if request.method == 'POST':
        form = UploadFileForm(request.POST, request.FILES)
        if form.is_valid():
            file_for_import = request.FILES['file_import']
            tyu = 0
            ioc_cond = []
            bulk_op = False
            bulk = []
            conti = 0
            for line in file_for_import:
                s = str(line)[1:].strip("'")
                s =s[:-2]
                c = s.split(',')
                print(c)
                ioc_name = c[0]
                ioc_type = c[1]
                if len(c)>3:
                    ioc_source = ",".join(c[2:]).strip('"')
                    print(ioc_source)
                else:
                    ioc_source = c[2]
                
                ioc_name_uuid = uuid.uuid3(uuid.NAMESPACE_DNS, ioc_name)
                request_search_id = db.ioc_coll.find({ '_id': ioc_name_uuid})
                if request_search_id.count() == 0:
                    ioc_author = 'import_from_csv'
                    insert_doc = {"_id": ioc_name_uuid, "ioc": ioc_name, "ioc_type": ioc_type, "ioc_source": ioc_source, "ioc_author": ioc_author, "ioc_date_add": datetime.datetime.now().strftime("%d-%m-%Y %H:%M:%S")}
                    result = db.ioc_coll.insert(insert_doc);
                    
                else:
                    ioc_cond.append(ioc_name)

        context = {'form': form, 'insert_status': 'Operation successfully!', 'ioc_cond': ioc_cond}

        return render(request, 'ioc_import.html', context)   

    else:
        form = UploadFileForm()
        
    return render_to_response('ioc_import.html', {'form': form})

