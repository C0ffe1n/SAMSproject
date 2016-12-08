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



function graw_graph(){
        $('#drawnetwork').hide();
        $.ajax({
            data: {'search_content': id},   
            type: "POST",
            url: "/webui/create_graph/",
            cache: false,
            success: function(data){
                var data_graph_nodes = [];
                var data_graph_edges = [];
                console.log(data);
                for (i = 0; i <= data.received_mta.length - 1; i++){
                    
                    if (data.received_mta[i]['from_domain'] == undefined) {
                        if (data.received_mta[i]['from_ip'] != undefined)
                            data_graph_nodes.push({id: i + 1, label:  data.received_mta[i]['from_ip']});
                        }
//                     if ((data.received_mta[i]['from_domain'] == undefined) && (data.received_mta[i]['from_ip'] == undefined)) {
//                         alert(data.received_mta[i]['by_domain'])
// //                         data_graph_nodes.push({id: i + 1, label:  data.received_mta[i]['by_domain']});
//                         }
                    else {
                        data_graph_nodes.push({id: i + 1, label:  data.received_mta[i]['from_domain']});
                        }
                    if (i != data.received_mta.length - 1) {
                    data_graph_edges.push({from: i + 1, to: i + 2})
                    }
                };
                
                var nodes = new vis.DataSet(data_graph_nodes);
                    // create an array with edges
                var edges = new vis.DataSet(data_graph_edges);
      
                // create a network
                var container = document.getElementById('drawnetwork');
                var data = {
                    nodes: nodes,
                    edges: edges
                };
                var options = {};
                var network = new vis.Network(container, data, options);
                $('#drawnetwork').show();

            },
            error: function(data) {
                $("#result_search").html("Something went wrong!");
        },

        });
    return false;
}
