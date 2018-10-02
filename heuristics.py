import os
import re
import json
import hashlib
import bencode
import csv
import dnsbls
import utilities
import apache_log_parser as alp
import numpy as np
from datetime import datetime
from geoip import geolite2
from sklearn import svm

report = {}
ipsCache = {}
sessions = {}




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
                "RemoteHostAdress" : logData['remote_host'],
                "RemoteLogName" : logData['remote_logname'],
                "UserName" : logData['remote_user'],
                "TimeStamp" : t[0][1:len(t[0])],
                "TimeZone" : t[1],
                "StatusCode" : logData['status'],
                "ReturnSize" : logData['response_bytes_clf'],
                "Referrer" : '"'+logData['request_header_referer']+'"',
                "UserAgent" :'"'+ logData['request_header_user_agent']+'"', #if needed the ua can be splitted in its parts
                "RequestMethod": logData["request_method"],
                "ProtocolVersion": logData["request_http_ver"],
                "ServerPath": logData["request_url"]
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

def logToCsv(log, dst, short = True): #dst is the name of the csv
    l = log[0]
    with open(dst, 'wb') as csvfile:
        sw = csv.writer(csvfile, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
        k = [key for key, value in l.items() if key != 'ReqParameters']
        k.append("requestLength")
        k.append("nParameters")
        param = set() #it will be the list of all the parameters
        if not short:
            for l in log:
                for key in l["ReqParameters"].keys():
                    param.add('"' + key + '"')
            param = list(param)
            k = k + param
        sw.writerow(k)
        for l in log:
            k = [
                value for key, value in l.items()
                if key != 'ReqParameters'
            ]
            k[3] = 0 if k[3] == '-' else float(k[3]) #converting the return size to float
            k.append(len(l["ServerPath"]))
            k.append(len(l["ReqParameters"]))
            if not short:
                for p in param:
                    p = p[1:-1] #removing quotes
                    if p in l["ReqParameters"]:
                        try:
                            k.append(float(l["ReqParameters"][p]))
                        except:
                            k.append('"' + l["ReqParameters"][p] + '"')
                    else:
                        k.append("")
            sw.writerow(k)

def normalLog(logPath, splitByRes = True):
    log = fileToDic(logPath)
    checkRefAndUserAgentFingerprints(log)
    checkReqFingerprints(log)
    checkStatusCode(log)

    if splitByRes:
        normalLog = {} #dictionary in which the keys are the resources and the values are the normal connections for that resource
        for el in log:
            k = hashlib.md5(bencode.bencode(el)).hexdigest()
            if not k in report: # if the connection has not been reported by the heuristics
                res = el["Resource"]
                if not res in normalLog:
                    normalLog[res] = []
                normalLog[res].append(el.copy())

    else:
        normalLog = [] #the list of all normal connection
        for el in log:
            k = hashlib.md5(bencode.bencode(el)).hexdigest()
            if not k in report:
                normalLog.append(el.copy())

    i = logPath.rfind('/') + 1 if logPath.rfind('/') != -1 else 0
    directory = './outputs/' + 'normal' + logPath[i:len(logPath)]

    if splitByRes:
        if not os.path.exists(directory):
            os.makedirs(directory)
        for k in normalLog:
            logToCsv(normalLog[k], directory + '/' + k.replace('/', '_') + '.csv', False)

    else:
        logToCsv(normalLog, directory +'.csv', False)

def checkReqFingerprints(log):
    with open('./fingerprints/fingerprints.json') as fp:
        fingerprints = json.load(fp)

    for el in log:
        alerts = []
        nAlone = 0
        nOther = 0
        for fp in fingerprints:
            if re.match(fp['fp'], el['ServerPath']):
                if fp['alone'] or (not(fp['alone']) and len(alerts) > 0):
                    alerts.append(fp['attack'])
                if fp['alone']:
                    nAlone += 1
                else:
                    nOther +=1
        if len(alerts) > 0 :
            k = hashlib.md5(bencode.bencode(el)).hexdigest() #compute the MD5 of the connection
            if k in report:
                report[k]["alerts"] += len(alerts)
                report[k]["aloneAlerts"] += nAlone
                report[k]["otherAlerts"] += nOther
            else:
                report[k] = {
                    "connection": el,
                    "alerts" : len(alerts),
                    "aloneAlerts" : nAlone,
                    "otherAlerts" : nOther
                }
            print( el['ServerPath'])
            print( "the connection scored "+ str(len(alerts)) + " misbehaviors:")
            print( alerts)


def checkRefAndUserAgentFingerprints(log):
    with open('./fingerprints/referrer-UserAgentFP.json') as fp:
        fingerprints = json.load(fp)

    for el in log:
        alerts = []
        nAlone = 0
        nOther = 0

        for fp in fingerprints:
            if re.match(fp['fp'], el['Referrer']) or re.match(fp['fp'], el['UserAgent']) :
                if fp['alone'] or (not (fp['alone']) and len(alerts) > 0):
                    alerts.append(fp['attack'])
                if fp['alone']:
                    nAlone += 1
                else:
                    nOther +=1

        if len(alerts) > 0:
            k = hashlib.md5(bencode.bencode(
                el)).hexdigest()  #compute the MD5 of the connection
            if k in report:
                report[k]["alerts"] += len(alerts)
                report[k]["aloneAlerts"] += nAlone
                report[k]["otherAlerts"] += nOther
            else:
                report[k] = {
                    "connection": el,
                    "alerts": len(alerts),
                    "aloneAlerts": nAlone,
                    "otherAlerts": nOther
                }
            print( "Referrer: " ,el['Referrer'])
            print( "UserAgent: " ,el['UserAgent'])
            print( "the connection scored " + str(
                len(alerts)) + " misbehaviors:")
            print( alerts)

def checkStatusCode(log):
    for el in log:
        count = 0
        if el["StatusCode"] == "500":
            count += 1
            print( el)
            print( "Sometimes server error is generated by attacker attempt to avoid security checks whith special character coding")
        if el["StatusCode"] == "403":
            count +=1
            print( el)
            print( "Denied error, it is possible that an attacker is tryng to access forbidden files")
        if count > 0:
            k = hashlib.md5(bencode.bencode(
                el)).hexdigest()  #compute the MD5 of the connection
            if k in report:
                report[k]["alerts"] += count
                report[k]["aloneAlerts"] += count
            else:
                report[k] = {"connection": el, "alerts": count, "aloneAlerts": count, "otherAlerts" : 0}

def sessionConverter(log):

    #t1= l[0]["TimeStamp"]
    for el in log:
        #print el["RemoteHostAdress"], el["TimeStamp"], el["UserAgent"]
        k = el["RemoteHostAdress"] + el["UserAgent"]
        #print k
        FMT = '%d/%b/%Y:%H:%M:%S'
        if not k in sessions:
            sessions[k] = [{
                't0': el["TimeStamp"],
                'connections': [el]}]
        #   print "adding new key"
        else:
            t1 = sessions[k][-1]['t0'] #the last element with key k contains the last session, the only one in which our element can be insterted
            t2=el["TimeStamp"]
            d = datetime.strptime(t2, FMT) - datetime.strptime(t1, FMT)
            #print d
            if d.days > 0 or d.seconds > 1800: #a new session with the same ip + user agent needs to be added
                # print "> 30 min"
                sessions[k].append({
                    't0': el["TimeStamp"],
                    'connections': [el]})
            else: #the request need to be added to the current session
                #print "ok"
                sessions[k][-1]["connections"].append(el)
    #print "----------------------------------------------------------------------"
    #print sessions
    with open('sessions.json', 'w') as fp:
        json.dump(sessions, fp, indent=4, separators=(',', ': '))
    return sessions


def sessionDatasetConverter(sessions):  #this functions takes the raw sessions and ectract the features used in https://www.researchgate.net/publication/276139295_Agglomerative_Approach_for_Identification_and_Elimination_of_Web_Robots_from_Web_Server_Logs_to_Extract_Knowledge_about_Actual_Visitors
    file = './access_log'
    l = fileToDic(file)
    checkRefAndUserAgentFingerprints(l)
    checkReqFingerprints(l)
    checkStatusCode(l)
    print("-------------------REPORT DONE------------------------")
    with open('sessions2.csv', 'wb') as csvfile:
        sw = csv.writer(
            csvfile, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
        sw.writerow([
            'TotalHits', '%Image', '%HTML', '%BinaryDoc', '%BinaryExe',
            '%ASCII', '%Zip', '%Multimedia', '%OtherFile', 'BandWidth',
            'SessionTime', 'avgHtmlReqTime', 'TotalNightTimeReq',
            'TotalRepeatedReq', '%Errors', '%Get', '%Post', '%OtherMethod',
            'IsRobot.txtVisited', '%Head', '%UnassignedReferrer',
            'nMisbehavior', 'nAloneMisbehavior', 'nOtherMisbehavior', 'isBlacklisted', 'geoIp'
        ])
        for k in sessions: #iterate over session outer key
            for s in sessions[k]: #iterate over sessions with the same inner key
                totalHits = len(s["connections"])
                FMT = '%d/%b/%Y:%H:%M:%S'
                sessionTime = (datetime.strptime(
                    s["connections"][-1]["TimeStamp"], FMT) - datetime.strptime(
                        s["connections"][0]["TimeStamp"], FMT)).seconds
                bandWidth = 0
                totalNightTimeReq = 0
                images = 0
                html = 0
                doc = 0
                exe = 0
                Ascii = 0
                Zip = 0
                multimedia = 0
                other = 0
                errors = 0
                gets = 0
                posts = 0
                heads = 0
                otherMethods = 0
                unassignedReferrer = 0
                r0 = 0 #used for counting the time between two html requests
                IsRobotTxtVisited = 0
                times = []
                reqs= []
                nMisbehavior=0
                nAloneMisbehavior = 0
                nOtherMibehavior = 0
                isBlackListed = 0
                geoIp = ''
                ip = s["connections"][0]["RemoteHostAdress"]
                if ip in ipsCache:
                    isBlackListed = ipsCache[ip][0]
                    geoIp = ipsCache[ip][1]
                else:
                    if dnsbls.check(ip):
                        isBlackListed = 1
                    c =  geolite2.lookup(ip)
                    if c is not None:
                        geoIp =c.country
                    ipsCache[ip] = [isBlackListed, geoIp]

                for con in s["connections"]:

                    k = hashlib.md5(bencode.bencode(con)).hexdigest()
                    if k in report:
                        nMisbehavior += report[k]["alerts"]
                        nAloneMisbehavior += report[k]["aloneAlerts"]
                        nOtherMibehavior += report[k]["otherAlerts"]
                    reqs.append(con["ServerPath"]) #used to count repeated requests
                    if ".jpg " in con["ServerPath"] or ".png " in con["ServerPath"] or ".svg " in con["ServerPath"] or ".tiff " in con["ServerPath"] or ".gif " in con["ServerPath"] or ".ico " in con["ServerPath"]:
                        images += 1
                    if ".cgi " in con["ServerPath"] or ".htm " in con["ServerPath"] or ".html " in con["ServerPath"] or ".js " in con["ServerPath"] or ".php " in con["ServerPath"]:
                        html += 1
                        if r0 == 0:
                            r0 = con["TimeStamp"]
                        else:
                            r1 = con["TimeStamp"]
                            t =  (datetime.strptime(r0, FMT) - datetime.strptime(r1, FMT)).seconds
                            times.append(t)
                            r0 = r1
                    if ".doc " in con["ServerPath"] or ".pdf " in con["ServerPath"] or ".ps " in con["ServerPath"] or ".xls " in con["ServerPath"] or ".ppt " in con["ServerPath"]:
                        doc += 1
                    if ".cgi " in con["ServerPath"] or ".exe " in con["ServerPath"] or ".py " in con["ServerPath"] or ".dll " in con["ServerPath"] or ".dat " in con["ServerPath"] or ".jar " in con["ServerPath"] :
                        exe += 1
                    if ".txt " in con["ServerPath"] or ".cpp " in con["ServerPath"] or ".java " in con["ServerPath"] or ".xml " in con["ServerPath"] or ".c " in con["ServerPath"] or ".odf " in con["ServerPath"] or ".csv " in con["ServerPath"]:
                        Ascii += 1
                    if ".zip " in con["ServerPath"] or ".rar " in con["ServerPath"] or ".gzip " in con["ServerPath"] or ".tar " in con["ServerPath"] or ".gz " in con["ServerPath"]:
                        Zip += 1
                    if ".mp3 " in con["ServerPath"] or ".mp4 " in con["ServerPath"] or ".wmv " in con["ServerPath"] or ".avi " in con["ServerPath"] or ".mpeg " in con["ServerPath"]:
                        multimedia += 1
                    if ".css " in con["ServerPath"] or ".com " in con["ServerPath"] or ".swf " in con["ServerPath"] :
                        other += 1
                    if "robots.txt" in con["ServerPath"]:
                        IsRobotTxtVisited = 1
                    if int(con["StatusCode"]) >= 400:
                        errors += 1
                    if con["RequestMethod"] == "GET":
                        gets += 1
                    elif con["RequestMethod"] == "POST":
                        posts += 1
                    elif con["RequestMethod"] == "HEAD":
                        heads += 1
                    else:
                        otherMethods += 1
                    if con["Referrer"] == "\"-\"":
                        unassignedReferrer += 1
                    if con["ReturnSize"] != '"-"' and con["ReturnSize"] != '-':
                        bandWidth += int(con["ReturnSize"])
                    conHour = datetime.strptime(con["TimeStamp"], FMT).hour
                    if conHour >= 00 and conHour <= 7:
                        totalNightTimeReq +=1
                pImages = (images/totalHits) * 100
                pHtml = (html/totalHits) *100
                pDoc = (doc/totalHits) * 100
                pExe = (exe/totalHits) * 100
                pAscii = (Ascii/totalHits) * 100
                pZip = (Zip/totalHits) * 100
                pMultimedia = (multimedia/totalHits) * 100
                pOtherFile = (other/totalHits) * 100
                if len(times) > 0 :
                    avgHtmlReqTime = reduce(lambda x, y: x + y, times) / len(times)
                else:
                    avgHtmlReqTime = 0
                uniqueReq = set(reqs)
                totalRepeatedReq = 0
                for r in uniqueReq:
                    c = reqs.count(r)
                    if c > 1:
                        totalRepeatedReq += c
                pErrors = (errors/totalHits) * 100
                pGet = (gets / totalHits) * 100
                pPost = (posts / totalHits) * 100
                pHead = (heads / totalHits) * 100
                pOtherMethod = (otherMethods / totalHits) * 100
                pUnassignedReferrer = (unassignedReferrer / totalHits) * 100
                #TODO add other features from our heuristics
                sw.writerow([
                    totalHits, pImages, pHtml, pDoc, pExe,
                    pAscii, pZip, pMultimedia, pOtherFile, bandWidth,
                    sessionTime, avgHtmlReqTime, totalNightTimeReq,
                    totalRepeatedReq, pErrors, pGet, pPost,
                    pOtherMethod, IsRobotTxtVisited, pHead, pUnassignedReferrer,
                    nMisbehavior, nAloneMisbehavior, nOtherMibehavior, isBlackListed, geoIp
                ])


normalLog('./access_log')

"""
file = './access_log'
l = fileToDic(file)
checkReqFingerprints(l)
checkRefAndUserAgentFingerprints(l)
checkStatusCode(l)
print( "...........................................................")
print( report)
"""
"""
file = './access_log'
l = fileToDic(file)
sessionConverter(l)
sessionDatasetConverter(sessions)
"""

"""
#normalLog('./access_log')
dt = utilities.loadDataset('./normalaccess_log.csv')
resources = {}
for con in dt:
    if con[1] in resources:
        resources[con[1]]["data"].append(con)
    else:
        resources[con[1] ]= {}
        resources[con[1]]["data"] = [con]
        resources[con[1]]["clf"] = svm.OneClassSVM(nu=0.5, kernel="rbf", gamma=0.01)

print "splitted for resource"

for k in resources:
    resources[k]["clf"].fit( np.array(resources[k]["data"])[:, 2:])

print "models trained"

d = np.array(resources[dt[0][1]]["data"])[0:10, 2:]

print resources[dt[0][1]]["clf"].predict(d)
"""


#TODO: find the right limit for long requests
#TODO: find a better way to catch "cat" because it appears in a lot a words
#TODO: convert all the fingerpring also in HEX
#TODO: add GEOIP information
#TODO: per identificare le soglie sulla lunghezza da non considerare overflow e potenziale DOS usare cdf per capire l'andamento generale del sistem