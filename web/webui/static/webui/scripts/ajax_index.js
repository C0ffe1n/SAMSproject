function getCookie(name) {
    var cookieValue = null;
    if (document.cookie && document.cookie != '') {
        var cookies = document.cookie.split(';');
        for (var i = 0; i < cookies.length; i++) {
            var cookie = jQuery.trim(cookies[i]);
            // Does this cookie string begin with the name we want?
            if (cookie.substring(0, name.length + 1) == (name + '=')) {
                cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                break;
            }
        }
    }
    return cookieValue;
}

$(function () {
    $.ajaxSetup({
        headers: { "X-CSRFToken": getCookie("csrftoken") }
    });
});
    function show(){  
         var map_range = $("#id_map_range").val();
         var top_range = $("#id_top_range").val();
        $.ajax({
            data: {'map_range': map_range, 'top_range': top_range},
            type: "POST",  
            url: "ajax",  
            cache: false, 
            success: function(req_fid){
                var m = []
                var n = [] 
                var o = []
                var u = []
                //var csrftoken = $.cookie('csrftoken');
                console.log(req_fid);
                
                //show date update and count mail
               
                mails_day = '<div>' + req_fid.findex + '</div>'
                mails_hour = '<div>' + req_fid.req_db_day + '</div>'
            // req_data = '<div>Date update: ' + req_fid.day + ' Count mail: ' + req_fid.findex + ' Mails/h: ' + req_fid.req_db_day + ' </div>'
                
                //count tops of md5, sender, recipient, mta
                m += '<table class="table table-bordered table-hover table-striped"><thead><tr><th>MD5</th><th>Amount</th></tr></thead><tbody>'
                n += '<table class="table table-bordered table-hover table-striped"><thead><tr><th>Sender</th><th>Amount</th></tr></thead><tbody>'
                o += '<table class="table table-bordered table-hover table-striped"><thead><tr><th>Recipient</th><th>Amount</th></tr></thead><tbody>'
                u += '<table class="table table-bordered table-hover table-striped"><thead><tr><th>MTA</th><th>Amount</th></tr></thead><tbody>'
                
                for (i = 0; i <= req_fid.count_md5_uniq.length - 1; i++){
                    for (j = 0; j < 1; j++){
                        m += '<tr><td><a href="search_md5/' + req_fid.count_md5_uniq[i][j] + '">' + req_fid.count_md5_uniq[i][j] + '</a> </td><td> ' + req_fid.count_md5_uniq[i][j+1] + '</td></tr>'
                    }
                }
                
                for (i = 0; i <= req_fid.count_sender_uniq.length - 1; i++){
                    for (j = 0; j < 1; j++){
                        n += '<tr><td><a href="search_sender/' + req_fid.count_sender_uniq[i][j] + '">' + req_fid.count_sender_uniq[i][j] + ' </td><td> ' + req_fid.count_sender_uniq[i][j+1] + '</td></tr>'

                    }
                } 
                
                for (i = 0; i <= req_fid.count_recipient_uniq.length - 1; i++){
                    for (j = 0; j < 1; j++){
                        o += '<tr><td><a href="search_recipient/' + req_fid.count_recipient_uniq[i][j] + '">' + req_fid.count_recipient_uniq[i][j] + ' </td><td> ' + req_fid.count_recipient_uniq[i][j+1] + '</td></tr>'

                    }
                }
                
                for (i = 0; i <= req_fid.uniq_mta.length - 1; i++){
                    for (j = 0; j < 1; j++){
                        u += '<tr><td><a href="search_mta/' + req_fid.uniq_mta[i][j] + '">' + req_fid.uniq_mta[i][j] + ' </td><td> ' + req_fid.uniq_mta[i][j+1] + '</td></tr>'
                    }
                }
                m += '</tbody>'
                n += '</tbody>'
                o += '</tbody>'
                u += '</tbody>'
                count_analyze = req_fid.count_inc_analyz 
              

            //show on <div>
            $("#top10md5").html(m);
            $("#top10send").html(n);
            $("#top10recip").html(o);
            $("#top10ip").html(u);
            $("#count_analyze").html(count_analyze);
            $("#mails_heand_day").html(mails_day);
            $("#mails_heand_hour").html(mails_hour);
            //$("#").html(req_data);
                
    //Draw fucking map
                        $('#worldmap').empty();
                        $('#worldmap').vectorMap({
                            map: 'world_mill',
                            zoomOnScroll: false,
                            series: {
                                regions: [{
                                    legend: {
                                        horizontal: true,
                                        cssClass: 'jvectormap-legend-icons',
                                        title: 'Плотность распределения писем'
                                        },
                                    // values: ipData,
                                    values: req_fid.uniq_ip_map,
                                    scale: ['#C8EEFF', '#0071A4'],
                                    normalizeFunction: 'polynomial'
                                    }]
                            },
                            onRegionTipShow: function(e, el, code){
                                el.html(el.html()+' (emails - '+req_fid.uniq_ip_map[code]+')');
                                },
                            onRegionClick: function (event, code) {
                                event.preventDefault();
                                window.location.href = "search_region/" + code
                            }
                        });
            setTimeout(show, 100000);
            }
                });  

            }  
