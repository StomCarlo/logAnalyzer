def fileToDic(filePath):
    line_parser = alp.make_parser(
        "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\""
    )
    with open(filePath) as f:
        content = f.readlines()
        log = []
        for conn in content:

            logData = line_parser(
                conn
            )

            t = logData['time_received'].split()

            d = {
                "RemoteHostAdress": '"' + logData['remote_host'] + '"',
                #"RemoteLogName": logData['remote_logname'],
                #"UserName": logData['remote_user'],
                "TimeStamp": '"' + t[0][1:len(t[0])] + '"',
                #"TimeZone": '"' + t[1][0:-1] + '"',
                "StatusCode": logData['status'],
                "ReturnSize": logData['response_bytes_clf'],
                "Referrer": '"' + logData['request_header_referer'] + '"',
                "UserAgent": '"' + logData['request_header_user_agent'] +
                '"',  #if needed the ua can be splitted in its parts
                "RequestMethod": '"' + logData["request_method"] + '"',
                "ProtocolVersion": '"' + str(logData["request_http_ver"]) + '"',
                "ServerPath": '"' + logData["request_url"] + '"'
            }
            if "request_url_query_simple_dict" in logData:
                d["ReqParameters"] = logData["request_url_query_simple_dict"]
            else:
                d["ReqParameters"] = {}
            if "request_url_path" in logData:
                d["Resource"] = logData["request_url_path"]
            else:
                d["Resource"] = ""
            log.append(d)
    f.close()
    #print log[0]
    return log