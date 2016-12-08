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
    function global_search(){
         var msg = $("#formx").serialize();
             
             $.ajax({
                 data: msg,   
                 type: "POST",
                 url: "console_search",
                 cache: false,
                 success: function(data){
                     l = [];
                     console.log(data);
                     var v = [];
                     l += '<table class="table table-bordered table-hover table-striped"><thead><tr><th>Date</th><th>ID</th><th>MD5</th><th>Sender</th><th>Recipient</th><th>MTA</th><th>Country</th></tr></thead><tbody>'
                
                     for (i = 0; i <= data.id.length - 1; i++){
                         l += '<tr><td>' + data.time_date[i] + '</td><td><a href="detail_id/' + data.id[i] + '">' + data.id[i] + '</td><td><a href="search_md5/' + data.md5_query[i] + '">' + data.md5_query[i] + '</td><td><a href="search_sender/' + data.sender[i] + '">' + data.sender[i] + '</td><td><a href="search_recipient/' + data.recipient[i] + '">' + data.recipient[i] + '</td><td><a href="search_mta/' + data.mta_req[i] + '">' + data.mta_req[i] + '</td><td><a href="search_region/' + data.mta_req_country_code[i] + '">' + data.mta_req_country[i] + '; Code: ' + data.mta_req_country_code[i]  + ' </td></tr>'
                     };
                     
                     l += '</tbody></table>'
                     count = 'Find ' + data.count_query  + ' results:'
                     $("#count_result").html(count);
                     $("#result_search").html(l);
                     setTimeout(global_search, 100000);
                 },
                 error: function(data) {
                      $("#result_search").html("Something went wrong!");
                 },
                     
             });
    
         return false;
   }      
