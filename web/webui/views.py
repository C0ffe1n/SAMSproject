from django.shortcuts import render, redirect
from django.http import HttpResponse, JsonResponse, HttpResponseRedirect
from django.template import RequestContext
from bson.objectid import ObjectId
from .forms import FormSearchID, FormSearchGen, FormUpdateVerdict, Map_range, Top_range
from django.core.urlresolvers import reverse
from django.core import serializers
from operator import itemgetter

import requests
import os
import json
import pymongo
import datetime
import collections
import monthdelta
import re
import email
import time

from email.header import Header
from collections import Counter
from datetime import timedelta
from .models import status_machine
from pymongo import MongoClient

mongo_srv = '192.168.0.110'
os.environ['NO_PROXY'] = '10.17.117.48, 10.17.117.12'
_srv_cuckoo = '10.17.117.12:8090'
_rest = 'machines/list'
REST_URL = os.path.join("http://", _srv_cuckoo, _rest)

connection = pymongo.MongoClient(mongo_srv, 27017, maxPoolSize=1000)
db = connection.samsdb


def index(request):
    VM = []
    try:
        request_url = requests.get(REST_URL, timeout=5)
        
        if request_url.status_code == 200:
            json_decoder = json.JSONDecoder()
            list_VM = json_decoder.decode(request_url.text)["machines"]
            for k in list_VM:
                VM.append(k["name"])
                
        else:
            list_VM = {}
    except (requests.ConnectionError, ValueError) as e:
        list_VM = {}
        print(e)
    
    form_map = Map_range
    form_top = Top_range
    
    return render(request, 'index.html', {'form_map' : form_map, 'form_top' : form_top,'VM' : VM })

def get_status(request):

    try:
        request_url = requests.get(REST_URL, timeout=5)
        if request_url.status_code == 200:
            json_decoder = json.JSONDecoder()
            machine_list = json_decoder.decode(request_url.text)
            machine_list = machine_list['machines']
        else:
            machine_list = {}
    except (requests.ConnectionError, ValueError) as e:
        machine_list = {}
        print(e)
    return render(request, 'status_machine.html', {'machine_list' :machine_list} )

def xhr_test(request):
    map_range = request.POST['map_range']
    top_range = request.POST['top_range']
    
    now_date = datetime.datetime.now()
    date_ph = now_date - timedelta(hours = 1)
    date_pd = now_date - timedelta(days = 1)
    date_pw = now_date - timedelta(days = 7)
    date_pm = now_date - monthdelta.monthdelta(1)
    query_date_range = {'1 Day': date_pd, '7 Days': date_pw, '30 Days': date_pm, 'All time': 'All time'}
    req_db = db.fid.find()
    uniq_sample = []
    uniq_send = []
    uniq_recip = []
    uniq_ip_map_tmp = []
    uniq_ip_map = []
    count_md5_uniq = []
    uniq_mta = []
    count_inc_analyz = []
    req_db_day = []
    
    request_date_range_map = query_date_range[map_range]
    request_date_range_top = query_date_range[top_range]
    
    req_db_stats_hour = db.analysis.find({'timestamp': {'$gte': date_ph, '$lt': now_date}})
    req_db_stats_day = db.analysis.find({'timestamp': {'$gte': date_pd, '$lt': 
now_date}})

   
    if request_date_range_map == "All time":
        req_db_stats_map = db.analysis.find()
    else:
        req_db_stats_map = db.analysis.find({'timestamp': {'$gte': request_date_range_map, '$lt': now_date}})
    
    if request_date_range_top == "All time":
        req_db_stats_top = db.analysis.find()
    else:
        req_db_stats_top = db.analysis.find({'timestamp': {'$gte': request_date_range_top, '$lt': now_date}})
        
    for send in req_db_stats_top:
        if send['status'] == 'done':
            try:
                for c in send['sender']:
                    uniq_send.append(c['email'])
                for x in send['recipient']:
                    uniq_recip.append(x['email'])
                for r in send['hashes']:
                    uniq_sample.append(r['md5'])
                uniq_mta.append(send['mta']['ip'])
                
            except:
                pass
    req_db_day = req_db_stats_day.count()

    for z in req_db_stats_map:
        try:
            uniq_ip_map_tmp.append(z['mta']['country_code'])
        except:
            pass
    
    count_inc_analyz = db.analysis.find({'verdict': 'undefined'}).count()
    
    uniq_ip_map = Counter(uniq_ip_map_tmp)
    json.dumps(uniq_ip_map, separators=(',', ':'))
    
    count_sender_uniq = Counter(uniq_send).most_common(10)
    count_recipient_uniq = Counter(uniq_recip).most_common(10)
    uniq_mta = Counter(uniq_mta).most_common(10)
    
        

    count_md5_uniq = Counter(uniq_sample).most_common(10)
    findex = req_db[0]["FIndex"]
    day = req_db[0]["Day"]
    context = {'findex' : findex, 'day' : day, 'req_db_day' : req_db_day, 'count_md5_uniq' : count_md5_uniq, 'count_sender_uniq' : count_sender_uniq, 'count_recipient_uniq' : count_recipient_uniq, 'uniq_mta' : uniq_mta, 'uniq_ip_map' : uniq_ip_map, 'count_inc_analyz': count_inc_analyz}
    return JsonResponse(context)

def global_search(request, **kwargs):
    
    if len(kwargs) is 0:
        form = FormSearchGen
    elif 'searchMd5' in kwargs:
        form = FormSearchGen(initial={'search_content': kwargs['searchMd5'], 'search_type': 'md5'})
    elif 'searchSender' in kwargs:
        form = FormSearchGen(initial={'search_content': kwargs['searchSender'], 'search_type': 'Sender'})
    elif 'searchRecipient' in kwargs:
        form = FormSearchGen(initial={'search_content': kwargs['searchRecipient'], 'search_type': 'Recipient'})
    elif 'searchMta' in kwargs:
        form = FormSearchGen(initial={'search_content': kwargs['searchMta'], 'search_type': 'ip'})   
    elif 'regionCode' in kwargs:
        form = FormSearchGen(initial={'searchCode': kwargs['regionCode']}) 
    elif 'searchVerdict' in kwargs:
        form = FormSearchGen(initial={'verdict_status': kwargs['searchVerdict']})
    elif 'searchExten' in kwargs:
        form = FormSearchGen(initial={'search_content': kwargs['searchExten'], 'search_type': 'file_ext'})

    return render(request, 'global_search.html', {'form': form})

def build_request(search_content, srch_type, srch_date, srch_region, sort_type, verdict_status,request_date):
    _arg_req = []
    now_date = datetime.datetime.now()
    _request = []
    if verdict_status != 'all':
        _arg_req.append({ 'verdict': verdict_status })
    if srch_region != '':
        _arg_req.append({ 'mta.country_code': srch_region })
    if request_date != 'All time':
        _arg_req.append({'timestamp': {'$gte': request_date, '$lt': now_date}})
    if srch_type == "md5" and search_content != '':
        _arg_req.append({ 'hashes.md5': search_content })
    if srch_type == "Recipient" and search_content != '':
        _arg_req.append({ 'recipient.email': search_content })
    if srch_type == "Sender" and search_content != '':
        _arg_req.append({ 'sender.email': search_content })
    if srch_type == "ip" and search_content != '':
        _arg_req.append({ 'mta.ip': search_content })
    if srch_type == "file_ext" and search_content != '':
        _arg_req.append({ 'type_samples.'+search_content: search_content.upper() })    
        
    if len(_arg_req) >= 1:
        _request = {'$and': _arg_req}
 
    else:
        _request = dict()
        return _request
        
    return _request

def console_search(request):
    
    now_date = datetime.datetime.now()
    date_ph = now_date - timedelta(hours = 1)
    date_pd1 = now_date - timedelta(days = 1)
    date_pd3 = now_date - timedelta(days = 3)
    date_pd7 = now_date - timedelta(days = 7)
    date_pm = now_date - monthdelta.monthdelta(1)
    date_all = ''

    sender = []
    recipient = []
    id = []
    time_date = []
    srch_region = []
    md5_query = []
    sort_type = []
    verdict_status = []
    uniq_send = []
    uniq_recip = []
    status_verdict = []
    file_exten = []
    query_date = {'Last 1 hour': date_ph, '1 Day': date_pd1, '3 Days': date_pd3, '7 Days': date_pd7, '30 Days': date_pm, 'All time': 'All time'}
    
    
    search_content = request.POST['search_content']
    srch_type = request.POST['search_type']
    srch_date = request.POST['search_date']
    srch_region = request.POST['searchCode']
    verdict_status = request.POST['verdict_status']
    request_date = query_date[srch_date]

    
    req_to_db = build_request(search_content, srch_type, srch_date, srch_region, sort_type, verdict_status, request_date)
  

    req_db_stats_search = db.analysis.find(req_to_db)
   
    result_array = []
    for send in req_db_stats_search:
        
        
        if send['status'] == 'done':
        
            try:
                st = []
                item = {}
                status_verdict = send['verdict']
                
                
                for x in send['hashes']:
                    md5_query.append(x['md5'])
                for x in send['sender']:
                    uniq_send.append(x['email'])
               
                for x in send['recipient']:
                    uniq_recip.append(x['email'])
            
                item = dict(time_date=send['timestamp'].strftime("%d-%m-%Y %H:%M:%S"),
                        id=send['_id'],
                        md5_list=md5_query,
                        send_list=uniq_send,
                        recip_list=uniq_recip,
                        mta_ip=send['mta']['ip'],
                        mta_name=send['mta']['country_name'],
                        mta_code=send['mta']['country_code'],
                        status_verdict=status_verdict,
                        file_exten = send['type_samples'],
                        )
                
                
                result_array.append(item) 
            except:
                pass
        
        
        st = []
        md5_query = []
        uniq_send = []
        uniq_recip = []
   
     
    form = FormSearchGen(request.POST)
    return render(request, 'global_search.html', {'result_array':result_array, 'form' : form})

  

def global_search_id(request, **kwargs):
    
    if kwargs:
        form = FormSearchID(initial={'search_content': kwargs['searchId']})
        submit_onload = '1'
    else:
        form = FormSearchID()
        submit_onload = '0'
    
    return render(request, 'detail_id.html', {'form': form, 'submit_onload': submit_onload})

def console_search_id(request):

    
    now_date = datetime.datetime.now()
    sender = []
    recipient = []
    from_domain = []
    from_data = []
    by_domain = []
    by_ip = []
    time_date = []
    uniq_send = []
    uniq_recip = []
    received_id = []
    status_verdict = []
    verdict = []
    md5_query = []
    file_info = []
    sample_description = []
    parent_sample = []
    
    subject_inc = []
    
    # Card of incident
    user_agent_id = []
    
    sandbox_sample = []
    sandbox_status = []
    sandbox_id = []
    
    #Detect
    
    detect_yara_name = []
    detect_yara_res = []
    sb_report_file = []
    
    virus_total_detect = []
    virus_total_link = []
    virus_total_list = []
    virus_total_detect_av = []
    virus_total_detect_av_des = []
    virustotal_all = []
    
    local_av_result = []
    local_av_name = []
    
    
    
    
    received_check = ['from_domain', 'from_data', 'by_domain', 'by_ip', 'id']

    if request.method == 'POST':
        form = FormSearchID(request.POST)
        if form.is_valid():
            search_content = form.cleaned_data['search_content']
            req_db_stats_search = db.analysis.find( { '_id': ObjectId(search_content) })
            result_array = []
            for send in req_db_stats_search:
               
                if send['status'] == 'done':
       
                    file_info = send['file']
                    sample_description = send['samples_desc']
                    parent_sample = send['parent']
                    subject_inc = send['subject']
                    if send['sandbox_tasks']:
                        for b in send['sandbox_tasks']:
                            sandbox_sample.append(b['sample'])
                            sandbox_status.append(b['status'])
                            sandbox_id.append(b['id_task'])
                    if send['detect']:
                        try:
                            if send['detect']['yara']:
                                for m in send['detect']['yara']:
                                    detect_yara_name = m['name']
                                    detect_yara_res = m['result']
                        except:
                            pass
                        
                        if send['detect']['agreg_ioc']:
                            if send['detect']['agreg_ioc']['vt']:
                                for j in send['detect']['agreg_ioc']['vt']:
                                    try:
                                        #print(send['detect']['agreg_ioc']['vt'])
                                        virus_total_detect = j['detect']
                                        virus_total_link = j['link']
                                        virus_total_list = j['list_detect']
                                        for v in virus_total_list:
                                            if virus_total_list[v]['detected']:
                                                virus_total_detect_av.append((virus_total_list[v],v))
                                    except:
                                        pass
                        if send['detect']['loc_av']:
                            for m in send['detect']['loc_av']:
                                local_av_result = m['result']
                                local_av_name = m['name']
             
                    try:
                        st = []
                        item = {}
                        
                        status_verdict = send['verdict']
                        for x in send['hashes']:
                            md5_query.append(x['md5'])
                      
                        for x in send['sender']:
                            uniq_send.append(x['email'])
                        
                        for x in send['recipient']:
                            uniq_recip.append(x['email'])
                      
                        item = dict(time_date=send['timestamp'].strftime("%d-%m-%Y %H:%M:%S"),
                                id=send['_id'],
                                md5_list=md5_query,
                                send_list=uniq_send,
                                recip_list=uniq_recip,
                                mta_ip=send['mta']['ip'],
                                mta_name=send['mta']['country_name'],
                                mta_code=send['mta']['country_code'],
                                file_info=file_info,
                                sample_description=sample_description,
                                parent_sample=parent_sample,
                                subject_inc=subject_inc,
                                sandbox_sample=sandbox_sample,
                                sandbox_status=sandbox_status,
                                sandbox_id=sandbox_id,
                                sandbox_tasks=send['sandbox_tasks'],
                                detect_yara_name=detect_yara_name,
                                detect_yara_res=detect_yara_res,
                                virus_total_detect_av=virus_total_detect_av,
                                virus_total_link=virus_total_link,
                                virustotal_all=send['detect']['agreg_ioc']['vt'],
                                local_av_result=local_av_result,
                                local_av_name=local_av_name,
                                )
                        
                        result_array.append(item) 
                        for x in send['received']:
                            received_id.append(x)
                     
                    except:
                        pass
                st = []
                md5_query = []
                uniq_send = []
                uniq_recip = []
        form_verdict = FormUpdateVerdict(initial={'verdict_status':status_verdict, 'search_id': search_content })

        return render(request, 'detail_id.html', {'result_array':result_array,'received_id':received_id, 'form' : form, 'form_verdict': form_verdict})
    else:
        
        form = FormSearchID()

    return render(request, 'detail_id.html', {'form' : form})

   
def create_graph(request):

    
    received_id = []
    id_graph = {}
    y = []
    from_domain = []
    from_data = []
    by_domain = []
    by_ip = []
    received_mta =[]

    if request.method == 'POST':
        form = FormSearchID(request.POST)
        if form.is_valid():
            search_content = form.cleaned_data['search_content']
            req_db_stats_search = db.analysis.find( { '_id': ObjectId(search_content) })
            result_array = []
            for send in req_db_stats_search:
                if send['status'] == 'done':
                    
                    try:
                        for y in send['received']:
                            id_mta = y['id']
                            
                            if y['from_domain']:
                                from_domain.append(y['from_domain'])
                            if y['from_data']:
                                from_data.append(y['from_data'])
                            if y['by_domain']:
                                by_domain.append(y['by_domain'])
                            if y['by_ip']:
                                by_ip.append(y['by_ip'])
                            else:
                                pass
                            received_mta.append(y)
                    except:
                        pass

                received_id.append(id_graph)
                received_id = {'received_mta': send['received']}
                
                
            return JsonResponse(received_id)
    else:
        form = FormSearchID()

    return JsonResponse(received_id)

def change_verdict(request):
    
    if request.method == 'POST':
        form = FormUpdateVerdict(request.POST)
        if form.is_valid():
            status_verdict = form.cleaned_data['verdict_status']
            search_id = form.cleaned_data['search_id']
            req_db_stats_search = db.analysis.update( { '_id': ObjectId(search_id) },
                                                      { '$set': { "verdict": status_verdict }})
            form = FormSearchID(initial={'search_content': search_id})
            return render(request, 'detail_id.html', {'form': form})
    else:
        form = FormUpdateVerdict()   
          
    return render(request, 'detail_id.html', {'form': form})

def analytics(request):
    return render(request, 'analytics.html')

def analytics_charts(request):
    now_date = datetime.datetime.now()
    date_pd1 = now_date - timedelta(days = 1)
    date_pd1t = now_date - timedelta(days = 1)
    date_ph = now_date - timedelta(hours = 1)
    time_hours = date_pd1 + timedelta(hours = 1)
    date_pm = now_date - monthdelta.monthdelta(1)
    time_hours_temp = []
    data_json = {}
    data_json_temp = {}
    uniq_attach = []
    uniq_file = []
    count_uniq_attach = []
    count_uniq_file = []
    
    time_temp= []
    count_uniq_inc_max = [] 
    count_incident_hour = []
    count_uniq_inc = []
    count_final_chart = []
    
    graph_pie_attach = []
    graph_pie_file = []
    
    c = [0]
    x = range(0,24)
    
    req_db_stats_mounth = db.analysis.find({'timestamp': {'$gte': date_pm, '$lt': now_date}})
    for send in req_db_stats_mounth:
        if send['status'] == 'done':
            try:

                for c in send['type_attach']:
                    uniq_attach.append(send['type_attach'][c])
                for v in send['type_samples']:
                    uniq_file.append(send['type_samples'][v])
                    
            except:
                pass
    count_uniq_file = Counter(uniq_file).most_common(10)
    count_uniq_attach = Counter(uniq_attach).most_common(10)
    
    for h in count_uniq_attach:
        graph_pie_attach.append(dict(label=h[0],data=h[1]))
    for h in count_uniq_file:
        graph_pie_file.append(dict(label=h[0],data=h[1]))

    for c in x:    
        if (date_pd1 < now_date):
            date_pd1 = date_pd1 + timedelta(hours = 1)
            time_temp.append(date_pd1.strftime("%d-%m-%Y %H"))
            
        else:
            pass
        
    req_db_stats_line_chart = db.analysis.find({'timestamp': {'$gte': date_pd1t, '$lt': now_date}}).sort('timestamp', pymongo.ASCENDING)
    for k in req_db_stats_line_chart:
        count_summ = k['timestamp'].strftime("%d-%m-%Y %H")
        count_incident_hour.append(count_summ)

    count_uniq_inc = Counter(count_incident_hour)
    count_uniq_inc_max = Counter(count_uniq_inc).most_common(1)

    for x in time_temp:
        n = time.mktime(datetime.datetime.strptime(x, "%d-%m-%Y %H").timetuple()) * 1000
        count_final_chart.append((n,count_uniq_inc[x]))


    if not count_uniq_inc_max:
        max_incidents = [0]
    else:
        max_incidents = count_uniq_inc_max[0][1]
        
    data_json = {'final_chart_line' : count_final_chart,'max_incidents' : max_incidents, 'graph_pie_attach' : graph_pie_attach, 'graph_pie_file' : graph_pie_file}

    max_incidents = count_uniq_inc_max.pop()[1]
    data_json = {'final_chart_line' : count_final_chart,
                 'max_incidents' : max_incidents,
                 'graph_pie_attach' : graph_pie_attach,
                 'graph_pie_file' : graph_pie_file}


    
    return JsonResponse(data_json)
  
