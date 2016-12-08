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
    $('#submit_details').hide();
   
    

    function detail_id(){
          //var msg = $("#formx").serialize();
        
             
             $.ajax({
                 data: {'search_content':id},   
                 type: "POST",
                 url: "detail_id/console_search_id",
                 cache: false,
                 
                 success: function(data){
                     
                     
                     l = [];
                     id_send = [];
                     console.log(data);
                     var v = [];
                     l +='<h4>Small info:</h4>';
                     l +='<table class="table table-bordered table-hover table-striped"><tr><th>ID</th><td>' + data.id_db + '</td></tr><tr><th>MD5</th><td>' + data.md5_query + '</td></tr><tr><th>Sender</th><td><a href="search_sender/' + data.sender + '">' + data.sender + '</td></tr><tr><th>Recipient</th><td><a href="search_recipient/' + data.recipient + '">' + data.recipient + '</td></tr><tr><th>MTA</th><td><a href="search_mta/' + data.mta_req + '">' + data.mta_req + '</td></tr><tr><th>Country</th><td><a href="search_region/' + data.mta_req_country_code + '">' + data.mta_req_country + '; Code: ' + data.mta_req_country_code  + ' </td></tr></table>';
                        
                     id = data.id_db;
                     
                    
                     
                     
//                      for (i = 0; i <= data.id_db.length - 1; i++){
//                         // l += '<tr><td>' + data.time_date[i] + '</td><td><a href="detail_id/' + data.id[i] + '">' + data.id[i] + '</td><td><a href="search_md5/' + data.md5_query[i] + '">' + data.md5_query[i] + '</td><td><a href="search_sender/' + data.sender[i] + '">' + data.sender[i] + '</td><td><a href="search_recipient/' + data.recipient[i] + '">' + data.recipient[i] + '</td><td><a href="search_mta/' + data.mta_req[i] + '">' + data.mta_req[i] + '</td><td><a href="search_region/' + data.mta_req_country_code[i] + '">' + data.mta_req_country[i] + '; Code: ' + data.mta_req_country_code[i]  + ' </td></tr>'
//                         l += '<tr>/tr></tr>'
//                      };
             
                     
                  //   count = 'Find ' + data.count_query  + ' results:'
                   //  $("#count_result").html(count);
                     $("#result_min_id").html(l);
                    
                     $("#submit_details").show();
                    
                     return id;
                    // setTimeout(global_search, 100000);
                 },
                 error: function(data) {
                      $("#result_min_id").html("Something went wrong!");
                 },
                 
                   
             });
    
         return false;
         
   }
   
  
