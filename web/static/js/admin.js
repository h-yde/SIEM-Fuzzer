function hashView(){
    hash = window.location.hash.substr(1);
    if(hash == "") {
        $("#breadcrumb-current").text("Overview");
        $("#pingbacks").removeClass("active");
        $("#fuzzer").removeClass("active");
        $("#administrator").removeClass("active");
        $(".pingbacks").hide();
        $(".fuzzer").hide();
        $("#dashboard").show();
        $(".adminpanel").hide();
    } else if(hash == "fuzzer") {
        $("#fuzzer").addClass("active");
        $("#administrator").removeClass("active");
        $("#pingbacks").removeClass("active");
        $("#breadcrumb-current").text("SIEM Fuzzer");
        $("#dashboard").hide();
        $(".pingbacks").hide();
        $(".fuzzer").show();
        $(".adminpanel").hide();
    } else if(hash == "pingbacks") {
        $("#pingbacks").addClass("active");
        $("#administrator").removeClass("active");
        $("#fuzzer").removeClass("active");
        $("#breadcrumb-current").text("Successful Pingbacks");
        $("#dashboard").hide();
        $(".fuzzer").hide();
        $(".pingbacks").show();
        $(".adminpanel").hide();
        viewPingbacks();
    } else if(hash == "administrator") {
        $("#dashboard").hide();
        $("#administrator").addClass("active");
        $("#fuzzer").removeClass("active");
        $("#pingbacks").removeClass("active");
        $("#breadcrumb-current").text("Administrator Panel");
        $(".pingbacks").hide();
        $(".adminpanel").show();
        $(".fuzzer").hide();
    }
}

hashView();
$(window).on("hashchange", function() {
    hashView();
});

function validateEmail(email) {
    var re = /^(([^<>()[\]\\.,;:\s@\"]+(\.[^<>()[\]\\.,;:\s@\"]+)*)|(\".+\"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
    return re.test(email);
}

function viewPayload(payload_id){
    document.getElementById("payloadInformation").innerHTML = "";
    $("#payloadFire").modal("show");
    var xhr = new XMLHttpRequest();
    xhr.withCredentials = true;
    xhr.onreadystatechange = function() {
        if (xhr.readyState == XMLHttpRequest.DONE) {
            $("#pingback_url").attr("href",JSON.parse(atob(JSON.parse(xhr.responseText)["payloads"][0][3]))["screenshot"]);
            $("#pingback_img").attr("src",JSON.parse(atob(JSON.parse(xhr.responseText)["payloads"][0][3]))["screenshot"]);
            for(key in JSON.parse(atob(JSON.parse(xhr.responseText)["payloads"][0][3]))){
                if(key != "screenshot" && key != "injection_key" && key != "probe_uid"){
                    if(JSON.parse(atob(JSON.parse(xhr.responseText)["payloads"][0][3]))[key] != ""){
                        if(key == "uri"){
                            var e = document.createElement("span");
                            e.innerHTML = "<strong>URI: </strong> " + JSON.parse(atob(JSON.parse(xhr.responseText)["payloads"][0][3]))[key] + "<br/>";
                            document.getElementById("payloadInformation").appendChild(e);
                        } else if(key == "user_agent"){
                            var e = document.createElement("span");
                            e.innerHTML = "<strong>User Agent: </strong> " + JSON.parse(atob(JSON.parse(xhr.responseText)["payloads"][0][3]))[key] + "<br/>";
                            document.getElementById("payloadInformation").appendChild(e);
                        } else if(key == "referrer"){
                            var e = document.createElement("span");
                            e.innerHTML = "<strong>Referrer: </strong> " + JSON.parse(atob(JSON.parse(xhr.responseText)["payloads"][0][3]))[key] + "<br/>";
                            document.getElementById("payloadInformation").appendChild(e);
                        } else if(key == "origin"){
                            var e = document.createElement("span");
                            e.innerHTML = "<strong>Origin: </strong> " + JSON.parse(atob(JSON.parse(xhr.responseText)["payloads"][0][3]))[key] + "<br/>";
                            document.getElementById("payloadInformation").appendChild(e);
                        } else if(key == "cookies"){
                            var e = document.createElement("span");
                            e.innerHTML = "<strong>Cookies: </strong> " + JSON.parse(atob(JSON.parse(xhr.responseText)["payloads"][0][3]))[key] + "<br/>";
                            document.getElementById("payloadInformation").appendChild(e);
                        } else if(key == "ip_address"){
                            var e = document.createElement("span");
                            e.innerHTML = "<strong>IP Address: </strong> " + JSON.parse(atob(JSON.parse(xhr.responseText)["payloads"][0][3]))[key] + "<br/>";
                            document.getElementById("payloadInformation").appendChild(e);
                        } else if(key == "dom"){
                            $("#domData").text(JSON.parse(atob(JSON.parse(xhr.responseText)["payloads"][0][3]))[key]).html();
                        } else if(key == "browser_time"){
                            var e = document.createElement("span");
                            e.innerHTML = "<strong>Browser Time: </strong> " + JSON.parse(atob(JSON.parse(xhr.responseText)["payloads"][0][3]))[key] + "<br/>";
                            document.getElementById("payloadInformation").appendChild(e);
                            $("#localTimeTriggered").text(Date(parseInt(JSON.parse(atob(JSON.parse(xhr.responseText)["payloads"][0][3]))[key])).toString()).html()
                        } else {
                            var e = document.createElement("span");
                            e.innerHTML = "<strong>" + key + ": </strong> " + JSON.parse(atob(JSON.parse(xhr.responseText)["payloads"][0][3]))[key] + "<br/>";
                            document.getElementById("payloadInformation").appendChild(e);
                        }
                    } 
                } 
            }   
        }
    }
    xhr.open("GET", "/api/payload_fires/" + payload_id.toString() + "/", true);
    xhr.send(null);
}

function fuzz(){
    var b64payload = btoa($("#fuzz_payload").val());
    if($("#protocols").val() == "SSH"){
        json_payload = {"protocol":"ssh", "b64payload": b64payload, "port": $("#fuzz_port").val(), "hosts": $("#ssh_hosts").val().trim().split("\n").join(",")};
    } else if($("#protocols").val() == "RDP"){
        json_payload = {"protocol":"rdp", "b64payload": b64payload, "port": $("#fuzz_port").val(), "hosts": $("#ssh_hosts").val().trim().split("\n").join(",")};
    } else if($("#protocols").val() == "SMB"){
        json_payload = {"protocol":"smb", "b64payload": b64payload, "port": $("#fuzz_port").val(), "hosts": $("#ssh_hosts").val().trim().split("\n").join(",")};
    }

    var http = new XMLHttpRequest();
    var url = "http://localhost:5000/fuzz";
    http.open("POST", url, true);
    http.setRequestHeader("Content-type", "text/plain");
    http.onreadystatechange = function() {
        if(http.readyState == 4 && http.status == 200) {
            alert("Fuzzing...");
        }
    }
    http.send(JSON.stringify(json_payload));
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
          for(i = 0; i < JSON.parse(payloadFires)["payloads"].length; i++){
            payloadCategory = JSON.parse(payloadFires)["payloads"][i][1];
            if(payloadCategory == 0) {
              var payloadCategory = "XSS";
            } else if(payloadCategory == 1){
              var payloadCategory = "Remote Code Execution";
            }
            var tr = document.createElement("tr");
            var payloadData = JSON.parse(atob(JSON.parse(payloadFires)["payloads"][i][3]));
            var table_titles = [payloadData["uri"].slice(0,50) + "...", payloadCategory];
            for(i2 = 0; i2 < table_titles.length; i2++){
              var text = document.createTextNode(table_titles[i2]);
              var td = document.createElement("td");
              tr.appendChild(td);
              td.appendChild(text);
              document.getElementById("fires").appendChild(tr);
            }
            var td = document.createElement("td")
            td.innerHTML = "<a href='javascript:viewPayload(" + JSON.parse(payloadFires)["payloads"][i][0] + ");'>View Information</a>";
            tr.appendChild(td);
            document.getElementById("fires").appendChild(tr);
        }
      }
    }
    xhr.open("GET", "/api/payload_fires/me/", true);
    xhr.send(null);   
}

function inviteNewUser(){
    var newUserEmail = $("#newUser").val();
    if(validateEmail(newUserEmail) == true) {
        if($("#userTypeSelection").val() == 0){
            $(".invite-modal-body").text("Invite sent to " + newUserEmail);
        } else if($("#userTypeSelection").val() == 1) {
            $(".invite-modal-body").text("Invite sent to " + newUserEmail);
        } else {
            $(".invite-modal-title").text("Invalid Category!")
            $(".invite-modal-body").text("Please choose a valid user category.")
        }
    } else {
        $(".invite-modal-title").text("Invalid E-Mail Format!")
        $(".invite-modal-body").text("Please enter a valid E-Mail.")
    }
}

function deactivateUser(){
    var deactivateUsername = $("#deactivateUsername").val();
    if(deactivateUsername.length != 0){
        $(".deactivate-modal-body").text(deactivateUsername + " has been deactivated.");
    } else {
        $(".deactivate-modal-body").text("Please enter a username to deactivate.");
    }
}