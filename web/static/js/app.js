function hashView(){
    hash = window.location.hash.substr(1);
    if(hash == "") {
        $("#dashboard").show();
        $("#breadcrumb-current").text("Overview");
        $('#pingbacks').removeClass("active");
        $('#fuzzer').removeClass("active");
        $('#administrator').removeClass("active");
        $(".pingbacks").hide();
        $(".fuzzer").hide();
        $("#icon-cards").show();
    } else if(hash == "fuzzer") {
        $("#dashboard").hide();
        $('#fuzzer').addClass("active");
        $('#pingbacks').removeClass("active");
        $('#tools-nav').addClass("active");
        $("#breadcrumb-current").text("Non-HTTP Protocol Fuzzer");
        $("#icon-cards").hide();
        $(".pingbacks").hide();
        $(".fuzzer").show();
    } else if(hash == "pingbacks") {
        $("#dashboard").hide();
        $('#pingbacks').addClass("active");
        $('#fuzzer').removeClass("active");
        $('#tools-nav').addClass("active");
        $('#administrator').removeClass("active");
        $("#breadcrumb-current").text("Successful Pingbacks");
        $("#icon-cards").hide();
        $(".fuzzer").hide();
        $(".pingbacks").show();
        viewPingbacks();
    } else if(hash == "administrator") {
        $("#dashboard").hide();
        $('#administrator').addClass("active");
        $('#pingbacks').removeClass("active");
        $('#tools-nav').addClass("active");
        $("#breadcrumb-current").text("Administrator Panel");
        $("#icon-cards").hide();
        $(".pingbacks").hide();
        $(".admin-panel").show();
    }
}

function viewPayload(payload_id){
    $("#payloadFire").modal("show");
    var xhr = new XMLHttpRequest();
    xhr.withCredentials = true;
    xhr.onreadystatechange = function() {
        if (xhr.readyState == XMLHttpRequest.DONE) {
            alert(xhr.responseText);
        }
    }
    xhr.open('GET', '/api/payload_fires/' + payload_id.toString() + '/', true);
    xhr.send(null);
}

function viewPingbacks(){
    var myNode = document.getElementById("fires");
    while (myNode.firstChild) {
        myNode.removeChild(myNode.firstChild);
    }
    var xhr = new XMLHttpRequest();
    xhr.withCredentials = true;
    xhr.onreadystatechange = function() {
      if (xhr.readyState == XMLHttpRequest.DONE) {
          var payloadFires = xhr.responseText;
          alert(payloadFires);
          for(i = 0; i < JSON.parse(payloadFires)["payloads"].length; i++){
            payloadCategory = JSON.parse(payloadFires)["payloads"][i][1];
            if(payloadCategory == 0) {
              var payloadCategory = "XSS";
            } else if(payloadCategory == 1){
              var payloadCategory = "Remote Code Execution";
            }
            var tr = document.createElement("tr");
            var payloadData = JSON.parse(atob(JSON.parse(payloadFires)["payloads"][i][3]));
            var table_titles = [payloadData['uri'].slice(0,50) + '...', payloadCategory];
            for(i2 = 0; i2 < table_titles.length; i2++){
              var text = document.createTextNode(table_titles[i2]);
              var td = document.createElement("td");
              tr.appendChild(td);
              td.appendChild(text);
              document.getElementById("fires").appendChild(tr);
            }
            var td = document.createElement("td")
            td.innerHTML = '<a href="javascript:viewPayload(' + JSON.parse(payloadFires)["payloads"][i][0] + ');">View Information</a>';
            tr.appendChild(td);
            document.getElementById("fires").appendChild(tr);
        }
      }
    }
    xhr.open('GET', '/api/payload_fires/me/', true);
    xhr.send(null);   
}

hashView();
$(window).on('hashchange', function() {
    hashView();
});

