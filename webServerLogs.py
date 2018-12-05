import os
import re
import json
import hashlib
import bencode
import csv
import dnsbls
import utilities
import heuristics
import random
import apache_log_parser as alp
import numpy as np
from datetime import datetime
from geoip import geolite2
from sklearn import svm
from sklearn.cluster import KMeans
import matplotlib.pyplot as plt
from sklearn.decomposition import PCA
from sklearn.preprocessing import scale
from sklearn.externals import joblib
from statsmodels import robust
from sklearn.preprocessing import MinMaxScaler
from sklearn import metrics
ipsCache = {}
sessions = {}

nexceeding = 0 #used for file names exceeding the maximum name length



def fileToDic(filePath):
    line_parser = alp.make_parser(
        "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\""
    )
    with open(filePath) as f:
        content = f.readlines()
        log = []
        for conn in content:
            if len(conn) <=2:
                continue
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


def logToCsv(
    log, dst, complete, short=True
):  #dst is the name of the csv, set short to True if you don't want the parameters as features
    l = log[0]
    if complete is None:
        complete = log
    if len(dst) > 255:
        global nexceeding
        dst = dst[0:250]+str(nexceeding) + ".csv"
        nexceeding +=1
    with open(dst, 'wb') as csvfile:
        sw = csv.writer(csvfile, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
        k = [key for key, value in l.items() if key != 'ReqParameters']
        k.append("requestLength")
        k.append("nParameters")
        param = set() #it will be the list of all the parameters
        if not short:
            for l in complete:
                for key in l["ReqParameters"].keys():
                    param.add('"' + key + '"')
            param = list(param)
            k = k + param
        sw.writerow(k)
        for l in log:
            l["ReturnSize"] = 0 if l["ReturnSize"] == '-' else float(
                l["ReturnSize"])  #converting the return size to float
            k = [
                value for key, value in l.items()
                if key != 'ReqParameters'
            ]
            #k[1] = 0 if k[1] == '-' else float(k[1]) #converting the return size to float
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

def normalLog(logPath, splitByRes = True, short = False): #set short to True if you don't want the parameters as features
    log = fileToDic(logPath)
    report = heuristics.checkRefAndUserAgentFingerprints(log, {})
    report = heuristics.checkReqFingerprints(log, report )
    report = heuristics.checkStatusCode(log, report)

    if splitByRes:
        normalLog = {} #dictionary in which the keys are the resources and the values are the normal connections for that resource
        signaledLog = {}
        for el in log:
            try:
                k = hashlib.md5(bencode.bencode(el)).hexdigest()
                res = el["Resource"]
                if not k in report or (
                        report[k]["aloneAlerts"] == 0
                        and report[k]["otherAlerts"] <= 1 ):  # if the connection has not been reported by the heuristics
                    if not res in normalLog:
                        normalLog[res] = []
                    normalLog[res].append(el.copy())
                else :
                    if not res in signaledLog:
                        signaledLog[res] = []
                    signaledLog[res].append(el.copy())
            except:
                print "something went wrong"
                print el
    else:
        normalLog = [] #the list of all normal connection
        signaledLog = []
        for el in log:
            try:
                k = hashlib.md5(bencode.bencode(el)).hexdigest()
                if not k in report:
                    normalLog.append(el.copy())
                else:
                    signaledLog.append(el.copy())
            except:
                print "something went wrong"
                print el

    i = logPath.rfind('/') + 1 if logPath.rfind('/') != -1 else 0
    normDir = './outputs/' + 'normal' + logPath[i:len(logPath)]
    signaledDir = './outputs/' + 'signaled' + logPath[i:len(logPath)]

    if splitByRes:
        if not os.path.exists(normDir):
            os.makedirs(normDir)

        complete = None

        for k in normalLog:
            if k in normalLog and k in signaledLog:
                complete = np.concatenate((normalLog[k], signaledLog[k]), axis=0)
            else:
                complete = None
            logToCsv(normalLog[k], normDir + '/' + k.replace('/', '_') + '.csv', complete, short)

        if not os.path.exists(signaledDir):
            os.makedirs(signaledDir)
        for k in signaledLog:
            if k in normalLog and k in signaledLog:
                complete = np.concatenate(
                    (normalLog[k], signaledLog[k]), axis=0)
            else:
                complete = None
            logToCsv(signaledLog[k], signaledDir + '/' + k.replace('/', '_') + '.csv', complete, short)
        print "ONE DONE"
    else:
        logToCsv(normalLog, normDir +'.csv', log, short)
        logToCsv(signaledLog, signaledDir +'.csv', log, short)



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
            t1 = sessions[k][-1]['t0'][1:-1] #the last element with key k contains the last session, the only one in which our element can be insterted
            t2=el["TimeStamp"][1:-1]
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

def sessionVectorizer(sessions):

    uniqueResources = set() #a set of resources
    bw = set()
    for k in sessions:  #iterate over session outer key
        for s in sessions[k]:  #iterate over sessions with the same inner key
            for con in s["connections"]:
                uniqueResources.add(con["Resource"])
                bw.add(con["ReturnSize"])
    print ("uniqueResources done")
    if '-' in bw:
        bw.remove('-')
    print min(bw), max(bw)

    features = [
        'TotalHits', 'TotalNightTimeReq', 'TotalRepeatedReq', 'nErrors',
        'nGet', 'nPost', 'nHead', 'nOtherMethod', 'IsRobot.txtVisited',
        'nUnassignedReferrer', 'nTimeLess1s', 'nTimeGt10s', 'nBwGt20000',
        'nBwLess20000'
    ]
    for r in uniqueResources:
        features.append('res_' + r)
    features.append('res_other')


    print len(features)
    with open('sessionsVector.csv', 'wb') as csvfile:
        sw = csv.writer(
            csvfile, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
        sw.writerow(features)
        for k in sessions:  #iterate over session outer key
            for s in sessions[k]:  #iterate over sessions with the same inner key
                counter = {}
                for k in features:
                    counter[k] = 0
                counter["TotalHits"] = len(s["connections"])
                reqs = []
                FMT = '%d/%b/%Y:%H:%M:%S'

                first = True
                oldTime = 0
                currTime = 0
                for con in s["connections"]:
                    if first:
                        first = False
                        oldTime = datetime.strptime(con["TimeStamp"][1:-1], FMT)
                    else:
                        currTime = datetime.strptime(con["TimeStamp"][1:-1], FMT)
                        if (currTime-oldTime).seconds > 10:
                            counter["nTimeGt10s"] += 1
                        elif (currTime-oldTime).seconds < 1:
                            counter["nTimeLess1s"] += 1
                        oldTime = currTime
                    reqs.append(con["ServerPath"])  #used to count repeated requests
                    if "robots.txt" in con["ServerPath"]:
                        counter["IsRobot.txtVisited"] = 1
                    if int(con["StatusCode"]) >= 400:
                        counter["nErrors"] += 1
                    if con["RequestMethod"] == '"GET"':
                        counter["nGet"] += 1
                    elif con["RequestMethod"] == '"POST"':
                        counter["nPost"] += 1
                    elif con["RequestMethod"] == '"HEAD"':
                        counter["nHead"] += 1
                    else:
                        counter["nOtherMethod"] += 1
                    if con["Referrer"] == "\"-\"":
                        counter["nUnassignedReferrer"] += 1
                    if con["ReturnSize"] != '"-"' and con["ReturnSize"] != '-':
                        if con["ReturnSize"] > 20000:
                            counter["nBwGt20000"] +=1
                        else :
                            counter["nBwLess20000"] += 1
                    conHour = datetime.strptime(con["TimeStamp"][1:-1], FMT).hour
                    if conHour >= 00 and conHour <= 7:
                        counter["TotalNightTimeReq"] += 1
                    found = False
                    for r in uniqueResources:
                        if con['Resource'] == r:
                            counter["res_"+r] += 1
                            found = True
                            break
                    if not found:
                        counter["res_other"] +=1
                uniqueReq = set(reqs)
                totalRepeatedReq = 0
                for r in uniqueReq:
                    c = reqs.count(r)
                    if c > 1:
                        totalRepeatedReq += c
                counter["TotalRepeatedReq"] = totalRepeatedReq
                values = []
                for k in features:
                    values.append(counter[k])
                sw.writerow(values)

def sessionDatasetConverter(sessions, file):  #this functions takes the raw sessions and ectract the features used in https://www.researchgate.net/publication/276139295_Agglomerative_Approach_for_Identification_and_Elimination_of_Web_Robots_from_Web_Server_Logs_to_Extract_Knowledge_about_Actual_Visitors
    l = fileToDic(file)
    report = heuristics.checkRefAndUserAgentFingerprints(l, {})
    report = heuristics.checkReqFingerprints(l, report)
    report = heuristics.checkStatusCode(l, report)
    print("-------------------REPORT DONE------------------------")
    with open('sessions.csv', 'wb') as csvfile:
        sw = csv.writer(
            csvfile, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
        sw.writerow([
            'TotalHits', '%Image', '%HTML', '%BinaryDoc', '%BinaryExe',
            '%ASCII', '%Zip', '%Multimedia', '%OtherFile', 'BandWidth',
            'SessionTime', 'avgHtmlReqTime', 'TotalNightTimeReq',
            'TotalRepeatedReq', '%Errors', '%Get', '%Post', '%OtherMethod',
            'IsRobot.txtVisited', '%Head', '%UnassignedReferrer',
            'nMisbehavior', 'nAloneMisbehavior', 'nOtherMisbehavior', 'geoIp'
        ])
        for k in sessions: #iterate over session outer key
            for s in sessions[k]: #iterate over sessions with the same inner key
                totalHits = len(s["connections"])
                FMT = '%d/%b/%Y:%H:%M:%S'
                sessionTime = (datetime.strptime(
                    s["connections"][-1]["TimeStamp"][1:-1], FMT) - datetime.strptime(
                        s["connections"][0]["TimeStamp"][1:-1], FMT)).seconds
                bandWidth = 0.0
                totalNightTimeReq = 0.0
                images = 0.0
                html = 0.0
                doc = 0.0
                exe = 0.0
                Ascii = 0.0
                Zip = 0.0
                multimedia = 0.0
                other = 0.0
                errors = 0.0
                gets = 0.0
                posts = 0.0
                heads = 0.0
                otherMethods = 0.0
                unassignedReferrer = 0.0
                r0 = 0 #used for counting the time between two html requests
                IsRobotTxtVisited = 0
                times = []
                reqs= []
                nMisbehavior=0
                nAloneMisbehavior = 0
                nOtherMibehavior = 0
                #isBlackListed = 0
                geoIp = ''
                ip = s["connections"][0]["RemoteHostAdress"][1:-1]
                if ip in ipsCache:
                    #    isBlackListed = ipsCache[ip][0]
                    geoIp = ipsCache[ip][1]
                else:
                    #   if dnsbls.check(ip):
                    #       isBlackListed = 1
                    c =  geolite2.lookup(ip)
                    if c is not None:
                        geoIp =c.country
                    #ipsCache[ip] = [isBlackListed, geoIp]
                    ipsCache[ip] = [0, geoIp] # remove this line if you want to check DNSBL

                for con in s["connections"]:

                    k = hashlib.md5(bencode.bencode(con)).hexdigest()
                    if k in report:
                        nMisbehavior += report[k]["alerts"]
                        nAloneMisbehavior += report[k]["aloneAlerts"]
                        nOtherMibehavior += report[k]["otherAlerts"]
                    reqs.append(con["ServerPath"]) #used to count repeated requests
                    if ".jpg" in con["Resource"] or ".png" in con["Resource"] or ".svg" in con["Resource"] or ".tiff" in con["Resource"] or ".gif" in con["Resource"] or ".ico" in con["Resource"]:
                        images += 1
                    if ".cgi" in con["Resource"] or ".htm" in con["Resource"] or ".html" in con["Resource"] or ".js" in con["Resource"] or ".php" in con["Resource"]:
                        html += 1
                        if r0 == 0:
                            r0 = con["TimeStamp"][1:-1]
                        else:
                            r1 = con["TimeStamp"][1:-1]
                            t =  (datetime.strptime(r0, FMT) - datetime.strptime(r1, FMT)).seconds
                            times.append(t)
                            r0 = r1
                    if ".doc" in con["Resource"] or ".pdf" in con["Resource"] or ".ps" in con["Resource"] or ".xls" in con["Resource"] or ".ppt" in con["Resource"]:
                        doc += 1
                    if ".cgi" in con["Resource"] or ".exe" in con["Resource"] or ".py" in con["Resource"] or ".dll" in con["Resource"] or ".dat" in con["Resource"] or ".jar" in con["Resource"] :
                        exe += 1
                    if ".txt" in con["Resource"] or ".cpp" in con["Resource"] or ".java" in con["Resource"] or ".xml" in con["Resource"] or ".c" in con["Resource"] or ".odf" in con["Resource"] or ".csv" in con["Resource"]:
                        Ascii += 1
                    if ".zip" in con["Resource"] or ".rar" in con["Resource"] or ".gzip" in con["Resource"] or ".tar" in con["Resource"] or ".gz" in con["Resource"]:
                        Zip += 1
                    if ".mp3" in con["Resource"] or ".mp4" in con["Resource"] or ".wmv" in con["Resource"] or ".avi" in con["Resource"] or ".mpeg" in con["Resource"]:
                        multimedia += 1
                    if ".css" in con["Resource"] or ".com" in con["Resource"] or ".swf" in con["Resource"] :
                        other += 1
                    if "robots.txt" in con["ServerPath"]:
                        IsRobotTxtVisited = 1
                    if int(con["StatusCode"]) >= 400:
                        errors += 1
                    if con["RequestMethod"] == '"GET"':
                        gets += 1
                    elif con["RequestMethod"] == '"POST"':
                        posts += 1
                    elif con["RequestMethod"] == '"HEAD"':
                        heads += 1
                    else:
                        otherMethods += 1
                    if con["Referrer"] == "\"-\"":
                        unassignedReferrer += 1
                    if con["ReturnSize"] != '"-"' and con["ReturnSize"] != '-':
                        bandWidth += int(con["ReturnSize"])
                    conHour = datetime.strptime(con["TimeStamp"][1:-1], FMT).hour
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
                sw.writerow([
                    totalHits, pImages, pHtml, pDoc, pExe,
                    pAscii, pZip, pMultimedia, pOtherFile, bandWidth,
                    sessionTime, avgHtmlReqTime, totalNightTimeReq,
                    totalRepeatedReq, pErrors, pGet, pPost,
                    pOtherMethod, IsRobotTxtVisited, pHead, pUnassignedReferrer,
                    nMisbehavior, nAloneMisbehavior, nOtherMibehavior, geoIp
                ])



def oneClassSvmTrain(path):
    dt = utilities.loadDataset_oneHotEncoder(path)
    clf = svm.OneClassSVM(nu=0.5, kernel="rbf", gamma=0.01)
    clf.fit(dt)
    return clf


def plotData(dt, n_axes, n_clust, originalDt, attackDt = None, oneClass= False):
    if attackDt is not None:
        alldt = np.concatenate((dt, attackDt), axis=0)
        limit = len(dt)

        reduced_all = PCA(n_components=n_axes).fit_transform(alldt[:,:])
        reduced_data = reduced_all[0:limit, :]
        reduced_data_attack = reduced_all[limit:, :]
        print len(reduced_data)
        print len(reduced_data_attack)

    else :
        reduced_data = PCA(n_components=n_axes).fit_transform(dt[:,:])
    # if attackDt is not None:
    #     reduced_data_attack = PCA(n_components=n_axes).fit_transform(attackDt)
    c = np.array([[-0.73989116, -0.09185221],[ 1.39323709, 0.47200059],[ 2.0422567 ,-0.40404301],[ 0.61062697, 1.54731632]])
    kmeans = KMeans(init=c, n_clusters=n_clust)
    if attackDt is not None:
        kmeans.fit(reduced_all) #if you want to train with the normal change to reduced_data
    else:
        kmeans.fit(reduced_data)
    print kmeans.transform(reduced_data[0:2])
    # Step size of the mesh. Decrease to increase the quality of the VQ.
    h = .02  # point in the mesh [x_min, x_max]x[y_min, y_max].

    if attackDt is None:
        # Plot the decision boundary. For that, we will assign a color to each
        x_min, x_max = reduced_data[:, 0].min() - 1, reduced_data[:, 0].max() + 1
        y_min, y_max = reduced_data[:, 1].min() - 1, reduced_data[:, 1].max() + 1
    else :
        x_min, x_max = reduced_all[:, 0].min() - 1, reduced_all[:, 0].max() + 1
        y_min, y_max = reduced_all[:, 1].min() - 1, reduced_all[:, 1].max() + 1


    xx, yy = np.meshgrid(
        np.arange(x_min, x_max, h), np.arange(y_min, y_max, h))

    labels = kmeans.predict(reduced_data)

    d = {}  #data
    c = {}  #classifiers
    resNorm={} #marked normal by clf
    resOut={} #marked outlier by clf
    #things related to 1 class svm
    if oneClass:

        for i in range(n_clust):
            d[i] = []
            c[i] = svm.OneClassSVM(nu=0.01, kernel="rbf", gamma='auto')
            resNorm[i] = []
            resOut[i] = []

        for i in range(len(reduced_data)): #split data basing on cluster label
            d[ labels[i] ].append(reduced_data[i])
        print "data splitted"
        for k in d:
            print k
            print len(d[k])
        for k in c: #train the 1classSVM
            print k
            print len(d[k])
            c[k].fit(d[k]) #c[k].fit( np.array(d[k])[0:2000,:] )
            res = c[k].predict(d[k])
            print "prediction "+ str(k) + " done"
            for i in range(len(res)):
                if res[i] == 1:
                    resNorm[k].append(d[k][i])
                else:
                    resOut[k].append(d[k][i])
            print "res "+ str(k) + " splitted"



    # Obtain labels for each point in mesh. Use last trained model.
    Z = kmeans.predict(np.c_[xx.ravel(), yy.ravel()])

    #TODO make this code a separate function whith takes the number of clusters
    # with open("./cluster0.csv", 'wb') as csvfile0:
    #     sw0 = csv.writer(
    #         csvfile0, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
    #     with open("./cluster1.csv", 'wb') as csvfile1:
    #         sw1 = csv.writer(
    #             csvfile1, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
    #         with open("./cluster2.csv", 'wb') as csvfile2:
    #             sw2 = csv.writer(
    #                 csvfile2, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
    #             with open("./cluster3.csv", 'wb') as csvfile3:
    #                 sw3 = csv.writer(
    #                     csvfile3, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
    #                 #change the headers if you change the file
    #                 sw0.writerow(
    #                     ['Resource','TimeStamp','ReturnSize','Referrer','RemoteHostAdress','RequestMethod','UserAgent','ProtocolVersion','ServerPath','StatusCode','requestLength','nParameters','"cat"','"rg"','"p_p_col_id"','"gruppo"','"macro"','"p_p_auth"','"p_p_id"','"order"','"_49_struts_action"','"p_p_mode"','"page"','"p_p_col_count"','"p_p_col_pos"','"_49_groupId"','"tab"','"_49_privateLayout"','"p_p_state"','"max"','"vista"','"dn"','"p_p_lifecycle"'])
    #                 sw1.writerow(
    #                     ['Resource','TimeStamp','ReturnSize','Referrer','RemoteHostAdress','RequestMethod','UserAgent','ProtocolVersion','ServerPath','StatusCode','requestLength','nParameters','"cat"','"rg"','"p_p_col_id"','"gruppo"','"macro"','"p_p_auth"','"p_p_id"','"order"','"_49_struts_action"','"p_p_mode"','"page"','"p_p_col_count"','"p_p_col_pos"','"_49_groupId"','"tab"','"_49_privateLayout"','"p_p_state"','"max"','"vista"','"dn"','"p_p_lifecycle"'])
    #                 sw2.writerow(
    #                     ['Resource','TimeStamp','ReturnSize','Referrer','RemoteHostAdress','RequestMethod','UserAgent','ProtocolVersion','ServerPath','StatusCode','requestLength','nParameters','"cat"','"rg"','"p_p_col_id"','"gruppo"','"macro"','"p_p_auth"','"p_p_id"','"order"','"_49_struts_action"','"p_p_mode"','"page"','"p_p_col_count"','"p_p_col_pos"','"_49_groupId"','"tab"','"_49_privateLayout"','"p_p_state"','"max"','"vista"','"dn"','"p_p_lifecycle"'])
    #                 sw3.writerow(
    #                     ['Resource','TimeStamp','ReturnSize','Referrer','RemoteHostAdress','RequestMethod','UserAgent','ProtocolVersion','ServerPath','StatusCode','requestLength','nParameters','"cat"','"rg"','"p_p_col_id"','"gruppo"','"macro"','"p_p_auth"','"p_p_id"','"order"','"_49_struts_action"','"p_p_mode"','"page"','"p_p_col_count"','"p_p_col_pos"','"_49_groupId"','"tab"','"_49_privateLayout"','"p_p_state"','"max"','"vista"','"dn"','"p_p_lifecycle"'])

    #                 for i in range( len(labels) ):
    #                     sw = sw0
    #                     if labels[i] == 1:
    #                         sw = sw1
    #                     elif labels[i] == 2:
    #                         sw = sw2
    #                     elif labels[i] == 3:
    #                         sw = sw3
    #                     sw.writerow( np.append(originalDt[i],labels[i]) )

    #put the result into a color plotnan
    Z = Z.reshape(xx.shape)

    plt.figure(1)
    plt.clf()
    plt.imshow(
        Z,
        interpolation='nearest',
        extent=(xx.min(), xx.max(), yy.min(), yy.max()),
        cmap=plt.cm.binary,
        aspect='auto',
        origin='lower')
    if oneClass:
        for k in resNorm:
            print k, "norm " + str(len(resNorm[k])), "out " + str(len(resOut[k]))
            plt.plot(np.array(resNorm[k])[:, 0], np.array(resNorm[k])[:, 1], 'b.', markersize=1)
            plt.plot(np.array(resOut[k])[:, 0], np.array(resOut[k])[:, 1], 'r.', markersize=1)
    else:
        plt.plot(reduced_data[:, 0], reduced_data[:, 1], 'b.', markersize=1)
        if attackDt is not None:
            plt.plot(reduced_data_attack[:, 0], reduced_data_attack[:, 1], 'r.', markersize=1 )
    # Plot the centroids as a white X
    centroids = kmeans.cluster_centers_
    print centroids
    for i in range(n_clust):
        plt.scatter(
          centroids[i, 0],
          centroids[i, 1],
          marker='x',
          s=169,
          linewidths=3,
          color='r',
          zorder=10)

    # plt.scatter(
    #     centroids[0, 0],
    #     centroids[0, 1],
    #     marker='x',
    #     s=169,
    #     linewidths=3,
    #     color='w',
    #     zorder=10)
    # plt.scatter(
    #     centroids[1, 0],
    #     centroids[1, 1],
    #     marker='x',
    #     s=169,
    #     linewidths=3,
    #     color='r',
    #     zorder=10)
    # plt.scatter(
    #     centroids[2, 0],
    #     centroids[2, 1],
    #     marker='x',
    #     s=169,
    #     linewidths=3,
    #     color='g',
    #     zorder=10)
    # plt.scatter(
    #     centroids[3, 0],
    #     centroids[3, 1],
    #     marker='x',
    #     s=169,
    #     linewidths=3,
    #     color='b',
    #     zorder=10)
    plt.title('K-means clustering on the digits dataset (PCA-reduced data)\n'
              'Centroids are marked with white cross')
    plt.xlim(x_min, x_max)
    plt.ylim(y_min, y_max)
    plt.xticks(())
    plt.yticks(())
    plt.show()
    return plt

def outlier1CSVMTrain(dt, n_clust, th, gamma = 'auto'):
    kmeans = KMeans(init='k-means++', n_clusters=n_clust)

    kmeans.fit(dt)
    labels = kmeans.predict(dt)

    res = {}
    res["kmean"] = kmeans
    for i in range(n_clust):
        res[i] = {}
        res[i]["data"] = [] #indices of data assigned to cluster i
        res[i]["clf"] = svm.OneClassSVM(nu=th, kernel="rbf", gamma=gamma) #1class svm for cluster i
        res[i]["trainNormIndices"] = [] #indices of items marked as actually belonging to cluster i
        res[i]["trainOutIndices"] = [] #indices of items marked as outlier for the cluster i

    for i in range( len(dt) ):  #split data basing on cluster label
        res[ labels[i] ]["data"].append(i)
    print "data splitted"

    for k in range(n_clust):
        print k
        print len(res[k]["data"])

    for k in range(n_clust):  #train the 1classSVM
        data = [dt[j] for j in res[k]["data"]]
        predictions = res[k]["clf"].fit_predict(data)  #c[k].fit( np.array(d[k])[0:2000,:] )
        print "prediction " + str(k) + " done"
        for i in range(len(predictions)):
            if predictions[i] == 1:
                res[k]["trainNormIndices"].append(res[k]["data"][i])
            else:
                res[k]["trainOutIndices"].append(res[k]["data"][i])

    for k in range(n_clust):
        print k
        print len(res[k]["trainOutIndices"]), len(res[k]["data"])
    return res

def outlierDistanceBased(dt, n_clust, th):
    kmeans = KMeans(init='k-means++', n_clusters=n_clust)

    dist = kmeans.fit_transform(dt)
    print dist[0]
    labels = kmeans.predict(dt)

    dist_to_cluster = {}
    for i in range(len(labels)):
        l = labels[i]
        if not l in dist_to_cluster:
            dist_to_cluster[l] = []
        dist_to_cluster[l].append( dist[i][l] )

    for k in dist_to_cluster:
        avg = reduce(lambda x, y: x + y, dist_to_cluster[k]) / len(
            dist_to_cluster[k])
        print k, " avg: ", avg, " max: ", max(dist_to_cluster[k]), " min: ", min(
            dist_to_cluster[k]), " mean dev: ", np.std( dist_to_cluster[k]), " median dev: ", robust.mad(dist_to_cluster[k])

    outliersIndices= []
    for i in range(n_clust):
        outliersIndices.append([])
        print i, np.count_nonzero(labels == i)
    for i in range(len(dt)):
        if dist[i][labels[i]] > th:
            outliersIndices[labels[i]].append(i) #append the index to the list related to his cluster


    return outliersIndices, kmeans



def subsetGenerator(path, percentage):
    percentage = 10
    dt = fileToDic(path)
    res = {}
    print dt[0]
    for el in dt:
        r = el["Resource"]
        if not  r in res:
            res[r] = []
        res[r].append(el)
    outSrc = { # the sources where to take outliers
        "name" : ['/alimenti', '/', '/combo/'],
        "n_clusts" : [4,2,4],
        "numbers" : [0,0,0],
        "outliers" : [[],[],[]]
        }
    output = []
    output1 = []

    for k in res: #k is a resource
        n = (len(res[k])*percentage) / 100 #number of connection the we can take from this resource
        if k in outSrc["name"]:
            name = 'alimenti'
            if k == '/':
                name = 'home'
            elif k == '/combo/':
                name = 'combo'
            ind = outSrc["name"].index(k)
            outSrc["numbers"][ind] = n
            print name
            path1 = '/home/carlo/Documenti/Progetti/tesi/log/kmeanRes/all_'+name+'/distance_1.0/'
            path2 = '/home/carlo/Documenti/Progetti/tesi/log/kmeanRes/all_'+name+'/1CLASS_001/'
            for j in range(outSrc["n_clusts"][ind]):
                cluster = 'outliers' + str(j) + '.csv'
                p1 = path1 + cluster
                p2 = path2 + cluster
                d1 = utilities.loadDataset(p1)
                d2 = utilities.loadDataset(p2)
                if outSrc["outliers"][ind] == []:
                    outSrc["outliers"][ind] = d1[:,:]
                else:
                    outSrc["outliers"][ind] = np.concatenate((outSrc["outliers"][ind], d1), axis=0)
                outSrc["outliers"][ind] = np.concatenate((outSrc["outliers"][ind], d2), axis=0)

            if len(outSrc["outliers"][ind] > n/2):
                # random.shuffle(outSrc["outliers"][ind])
                # if output == []:
                #     output=outSrc["outliers"][ind][0:n/2, 0:12]
                # else:
                #     output = np.concatenate(( output, outSrc["outliers"][ind][0:n/2, 0:12]), axis=0)
                n = n/2
            else:
                # if output == []:
                #     output = outSrc["outliers"][ind][:,0:12]
                # else:
                #     output = np.concatenate(
                #         (output, outSrc["outliers"][ind][:,0:12]), axis=0)
                n = n - len(outSrc["outliers"][ind])

        random.shuffle(res[k]) #change the order
        if n == 0:
            n = 1
        if output == []:
            output=res[k][0:n]
        else :
            output = np.concatenate( (output,res[k][0:n]), axis=0 )
        m = n/10
        if m == 0:
            m = 1
        if output1 == []:
            output1=res[k][n:n+m]
        else :
            output1 = np.concatenate( (output1,res[k][n:n+m]), axis=0 )
    dst1 = 'evaluation_dt' + str(percentage) + 'percent.csv'
    logToCsv(output, dst1 ,None)
    dst2 = 'evaluation_dt' + str(1) + 'percent.csv'
    logToCsv(output1, dst2 ,None)

    with open(dst1, 'a') as csvfile:
        with open(dst2, 'a') as csvfile2:
            for i in range(3):
                print '-----------', outSrc["numbers"][i]
                sw = csv.writer(
                    csvfile, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
                sw2 = csv.writer(
                    csvfile2, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)

                n = min(len(outSrc["outliers"][i]), outSrc["numbers"][i]/2)
                n2 = min(len(outSrc["outliers"][i]), outSrc["numbers"][i]/20)
                random.shuffle(outSrc["outliers"][i])
                for o in outSrc["outliers"][i][0:n+1, 0:12] :
                    sw.writerow(o)
                random.shuffle(outSrc["outliers"][i])
                for o in outSrc["outliers"][i][0:n2 + 1, 0:12]:
                    sw2.writerow(o)



#session generation
# file = './logs/merged_anon_access_log'
# l = fileToDic(file)
#sessions=sessionConverter(l)
# with open('sessions.json') as f:
#     sessions = json.load(f)
#     sessionVectorizer(sessions)
# sessionDatasetConverter(sessions,file)


"""
#normalLog('./access_log')
dt = utilities.loadDataset('./outputs/normalaccess_log/_alimenti.csv')
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
    print "----------------------------- " + k + " ------------------"
    resources[k]["clf"].fit( np.array(resources[k]["data"])[:, 2:])

print "models trained"

d = np.array(resources[dt[0][1]]["data"])[0:10, 2:]

print resources[dt[0][1]]["clf"].predict(d)

"""
#kmean over all access log, calculate min, man and avg dists
#normalLog('./logs/merged_anon_access_log', splitByRes=False)
#print "normalLogDone"

# kmeans = KMeans(n_clusters=4, random_state=0).fit(dt)
# labels = kmeans.labels_
# dst = kmeans.transform(dt) #array of array
# print "dst"
# print dst[0]

# dist_to_cluster = {}
# for i in range(len(labels)):
#     l = labels[i]
#     if not l in dist_to_cluster:
#         dist_to_cluster[l] = []
#     dist_to_cluster[l].append( dst[i][l] )


# for k in dist_to_cluster:
#     avg = reduce(lambda x, y: x + y, dist_to_cluster[k]) / len(
#         dist_to_cluster[k])
#     print k, " avg: ", avg, " max: ", max(dist_to_cluster[k]), " min: ", min(
#         dist_to_cluster[k]), " mean dev: ", np.std( dist_to_cluster[k]), " median dev: ", robust.mad(dist_to_cluster[k])

#model usage

#dt = utilities.loadDataset_hash( #'./outputs/web_server_datasets/sessions/sessions.csv')
#'~/Documenti/Progetti/tesi/log/outputs/normalmerged_anon_access_log/_alimenti.csv')
#'./outputs/normalraw_complete_evaluation/_alimenti.csv')


#evaluation = utilities.loadDataset_hash( #'./outputs/web_server_datasets/sessions/sessions.csv')
#'./eval_correct.csv')
#'./allEvaluation_long.csv')
#'./outputs/normalraw_complete_evaluation/_alimenti.csv')

# train, evaluation = utilities.loadDatasets_hash(
#     '~/Documenti/Progetti/tesi/log/outputs/normalraw_complete_evaluation.csv',
#     './allEvaluation_long.csv')
#'~/Documenti/Progetti/tesi/log/outputs/signaledraw_complete_evaluation.csv'

#     #'~/Documenti/Progetti/tesi/log/outputs/signaledmerged_anon_access_log/_alimenti.csv')
#     './eval_correct.csv')
# print dt.shape, evaluation.shape

# attackDt = utilities.loadDataset_hash(
#     './outputs/signaledraw_complete_evaluation.csv')

# originalDt = utilities.loadDataset('./outputs/normalmerged_anon_access_log/_alimenti.csv')
# print originalDt[98875]
#     '~/Documenti/Progetti/tesi/log/outputs/signaledmerged_anon_access_log.csv')
# './outputs/signaledmerged_anon_access_log/_combo_.csv')
#'./outputs/normalraw_complete_evaluation.csv')
#print dt.shape

# #evaluation
# log = fileToDic('./logs/raw_complete_evaluation')
# logToCsv(log, 'allEvaluation_long.csv', log,)
#normalLog('./logs/raw_complete_evaluation', splitByRes=False)
labelsDT = utilities.loadDataset('./outputs/evaluation/evaluation_dt1percent.csv', separetor=',')
# # c = 0
# # for e in evaluationDT:
# #     if c < 4790:
# #         if len(e[6]) > 2:
# #             rsize = e[6][0:-2]
# #         else:
# #             rsize = e[6]
# #         print e[2][1:-1] + ' - - [' + e[1][1:-1] + ' +0100] "' + e[4][1:-1] + ' ' + e[9][1:-1] + ' HTTP/' +  e[3][1:-1]+'" '+e[5]+ ' '+rsize+" " +e[7]+ ' ' + e[8]
# #     else:
# #         if len(str(e[1])) > 2:
# #             rsize = str(e[1])[0:-2]
# #         else:
# #             rsize = str(e[1])
# #         print e[3][1:-1] + ' - - [' + e[2][1:-1] + ' +0100] "' + e[5][1:-1] + ' ' + e[8][1:-1] + ' HTTP/' +  e[4][1:-1]+'" '+str(e[10])+ ' '+str(rsize)+" " +e[7]+ ' ' + e[6]
# #     c += 1

# labels = []
# for c in labelsDT:
#     if c[0] == '/alimenti':
#         labels.append(c[-1])

labels = labelsDT[:,-1]

# print len(labels)

#balanced dt
# n_attacks = 325
# indices = range(len(evaluation))
# random.shuffle(indices)
# #indices = indices[0:n_attacks*2]

# count = 0
# ind=[]
# for i in indices:
#     if i < len(labels):
#         if labels[i] == 0 and count < n_attacks*2:
#             ind.append(i)
#             count += 1
#         elif labels[i] == 1:
#             ind.append(i)
#     else:
#         ind.append(i)
# indices = ind
# print indices
# print len(indices), '-----------'
#indices for alimenti
# indices = [
#     2175, 3894, 7176, 4008, 4607, 1098, 3811, 5038, 97, 625, 267, 6210, 7278,
#     6680, 4750, 2852, 2847, 6559, 49, 7056, 2694, 5924, 5583, 2168, 1103, 2753,
#     6610, 1383, 398, 457, 5309, 7282, 3915, 2555, 3684, 1867, 368, 822, 1169,
#     1939, 2877, 4254, 6106, 3272, 6770, 2105, 7027, 6776, 46, 7213, 4016, 2263,
#     357, 6010, 6304, 6446, 4591, 5260, 3062, 277, 2468, 4482, 1711, 721, 159,
#     1528, 716, 6389, 7201, 5615, 5378, 2341, 5014, 4498, 1258, 1828, 6507, 98,
#     1538, 388, 3862, 5448, 5767, 335, 6684, 2645, 2265, 6097, 201, 3446, 1377,
#     2885, 1834, 6013, 5122, 3344, 698, 107, 1879, 2883, 3843, 4874, 7142, 5291,
#     235, 4796, 969, 1203, 4951, 3921, 7173, 1658, 2464, 2141, 6644, 385, 4227,
#     6125, 3522, 1581, 3513, 6131, 3190, 4977, 4442, 4915, 5711, 4426, 5838,
#     1008, 3496, 7075, 3572, 371, 4778, 6437, 404, 3930, 6178, 5520, 644, 3250,
#     2515, 35, 6501, 1473, 1547, 1716, 1967, 4687, 5739, 4525, 1181, 6101, 3404,
#     5487, 2574, 1664, 5064, 4855, 2900, 7324, 4384, 5456, 243, 2242, 6040,
#     2874, 1274, 3911, 3972, 1037, 4, 3420, 2678, 4770, 4857, 2067, 5373, 0, 68,
#     1200, 1764, 6510, 6295, 333, 3301, 5719, 3176, 6506, 121, 5369, 5443, 2023,
#     2439, 3711, 684, 5905, 4239, 297, 2280, 3135, 949, 860, 491, 397, 818,
#     6327, 2411, 2921, 5401, 3320, 3626, 4907, 361, 396, 4416, 908, 3251, 7264,
#     3783, 4773, 873, 3210, 967, 2075, 2853, 5618, 4225, 2169, 3600, 4924, 3641,
#     5875, 1391, 5446, 5843, 3222, 4666, 2113, 5277, 3580, 5685, 7031, 4966,
#     7107, 5246, 2881, 6128, 6849, 6062, 720, 36, 2481, 336, 7304, 3702, 6875,
#     1904, 2815, 3165, 1594, 1378, 1480, 825, 5998, 5237, 1541, 1593, 7227, 603,
#     1402, 7392, 6611, 2367, 101, 978, 3905, 6078, 7156, 3745, 1739, 4059, 3227,
#     2126, 7315, 3865, 3648, 722, 588, 4713, 4204, 7290, 6118, 4290, 1482, 6245,
#     1166, 1219, 6349, 1514, 3955, 158, 1058, 5894, 2475, 2278, 1155, 5210,
#     6374, 1138, 4211, 5353, 5856, 3727, 5370, 5244, 2656, 1164, 1917, 5916,
#     5495, 850, 6633, 3016, 6256, 5810, 4083, 7155, 6892, 2929, 3685, 2394,
#     3197, 4497, 926, 2791, 3397, 3323, 47, 6780, 1796, 7309, 1442, 1059, 4064,
#     765, 4391, 1747, 5965, 5594, 3853, 3990, 2710, 7010, 998, 2609, 3202, 5285,
#     1686, 1469, 7015, 3264, 5777, 5356, 4302, 2354, 2833, 572, 6120, 2838,
#     3294, 7086, 6464, 266, 1901, 387, 1073, 7083, 2425, 4319, 3861, 2543, 6487,
#     6533, 449, 6250, 456, 1463, 6339, 3234, 3910, 2646, 1810, 2690, 4095, 876,
#     7087, 185, 4082, 5963, 163, 3738, 5362, 1816, 6697, 7281, 3218, 425, 4986,
#     3132, 4630, 510, 5131, 802, 1868, 6011, 7101, 6553, 2638, 285, 1727, 952,
#     1242, 6368, 1745, 1068, 1370, 3713, 5681, 1708, 2670, 6664, 6135, 3009,
#     5032, 6333, 5742, 1387, 4942, 1863, 4014, 5632, 508, 6885, 6539, 4464,
#     2708, 6702, 4732, 347, 130, 5007, 5863, 4776, 6996, 1690, 6055, 4466, 2213,
#     5960, 563, 1640, 2489, 3514, 5383, 1782, 3994, 1644, 1254, 5334, 183, 611,
#     5895, 2873, 5842, 3565, 7362, 7276, 5539, 2361, 1055, 2952, 4331, 184,
#     5156, 6960, 6588, 7303, 2120, 1842, 3286, 2496, 1139, 2217, 1412, 3427,
#     3491, 1829, 7341, 356, 1886, 426, 7049, 5184, 7099, 4183, 6221, 4916, 1616,
#     6878, 743, 6100, 1610, 2108, 4583, 4096, 4194, 5682, 5655, 3945, 4656,
#     4250, 3275, 453, 3312, 902, 717, 1450, 2234, 4031, 2378, 1709, 714, 5970,
#     6289, 5837, 3981, 857, 3194, 3966, 6612, 3444, 4365, 5547, 53, 4486, 1228,
#     211, 6194, 72, 7041, 5162, 6858, 6228, 6240, 5232, 4009, 231, 1382, 5758,
#     6818, 6268, 6447, 1399, 597, 5870, 4354, 1299, 1420, 5017, 889, 4109, 2381,
#     1823, 2835, 4431, 2932, 2032, 2937, 2748, 5636, 5029, 224, 963, 2934, 1289,
#     430, 4983, 1979, 5589, 3752, 5278, 538, 2399, 3583, 337, 1844, 5774, 1081,
#     7091, 5306, 4202, 6725, 847, 669, 7194, 4408, 5486, 1029, 6038, 4324, 4279,
#     3826, 5513, 178, 1374, 2985, 109, 547, 428, 3920, 2135, 710, 2805, 5801,
#     4349, 2035, 1710, 5986, 3540, 5899, 7148, 3382, 977, 3497, 1883, 3656,
#     2864, 696, 6204, 4084, 6574, 3916, 4743, 2310, 6317, 6096, 5835, 2146, 45,
#     4494, 4495, 5822, 1637, 3055, 4343, 2855, 2925, 2397, 6342, 5715, 3158,
#     4323, 5984, 5978, 6490, 3162, 2696, 4710, 1199, 6385, 4594, 6051, 4117,
#     2021, 4321, 1183, 5413, 4053, 1428, 7271, 7293, 7292, 1833, 1120, 60, 4284,
#     1540, 160, 4317, 236, 7338, 1561, 1861, 757, 1536, 7286, 7370, 7365, 1553,
#     7375, 403, 4283, 359, 7356, 7323, 1133, 4527, 196, 4052, 688, 7326, 7275,
#     1035, 7374, 138, 7267, 1425, 4663, 186, 7378, 798, 7342, 4671, 7294, 7262,
#     4309, 1153, 4568, 7398, 102, 7274, 4298, 7335, 7385, 7349, 1429, 4492,
#     7343, 995, 7339, 7391, 4706, 7337, 1171, 4027, 1847, 7312, 1675, 7347,
#     1453, 7298, 7307, 171, 4604, 1179, 4727, 7379, 7364, 7297, 379, 7340, 275,
#     7357, 7268, 372, 7395, 4468, 1231, 1427, 1805, 7284, 4557, 7369, 7299,
#     7285, 401, 7353, 1202, 4296, 4664, 7291, 1269, 7270, 4291, 7317, 1454,
#     1530, 7325, 4551, 795, 759, 7288, 4680, 7302, 4762, 7301, 1403, 4097, 7296,
#     775, 7393, 7361, 1812, 93, 7377, 173, 392, 1042, 7350, 7355, 7314, 255,
#     4157, 1801, 7345, 1800, 4115, 1142, 7327, 7334, 195, 1543, 86, 7372, 7367,
#     1817, 7305, 7269, 4072, 7397, 4105, 7332, 7280, 1722, 730, 7289, 7366,
#     4266, 7352, 1093, 4765, 771, 1090, 1074, 1099, 1845, 7386, 1768, 7310, 415,
#     7263, 7283, 1430, 7279, 7359, 4665, 4285, 4493, 4060, 165, 7333, 7382,
#     1670, 7344, 4667, 7331, 4735, 738, 1172, 4214, 1456, 4702, 7390, 291, 4107,
#     7387, 4707, 167, 7394, 1574, 1555, 7351, 7321, 191, 1475, 7371, 4662, 316,
#     7380, 222, 1669, 4102, 1408, 7273, 1426, 26, 4622, 7328, 7346, 7287, 4599,
#     7358, 4518, 1088, 7368, 1695, 177, 4487, 443, 7308, 7318, 7389, 4071, 4282,
#     7384, 7396, 7336, 1091, 7330, 1445, 1451, 7320, 7354, 7376, 245, 762, 1554,
#     1156, 7277, 4559, 4210, 7388, 1432, 413, 1431, 7329, 4553, 4286, 7295,
#     7306, 223, 1819, 1821, 4677, 1767, 234, 7322, 7319, 4670, 1243, 7300, 1703,
#     1404, 737, 4716, 7348, 796, 4473, 7383, 4193, 7363, 7266, 7381, 7311, 1349,
#     279, 4761, 7360, 7313, 7316, 7272, 7265, 4104, 7373
# ]

# indices = [
#     3605, 862, 2461, 3750, 816, 1120, 713, 1619, 2741, 3465, 2721, 4178, 2147,
#     1582, 3250, 3301, 3866, 358, 3223, 2267, 1579, 3216, 1763, 1949, 880, 310,
#     1038, 457, 1986, 3479, 2556, 3361, 2452, 2542, 850, 937, 3542, 775, 993,
#     291, 3967, 380, 241, 2702, 1914, 2677, 2321, 1070, 3526, 1869, 815, 1242,
#     3876, 2303, 3593, 2300, 968, 3913, 3398, 1791, 660, 3755, 1823, 2552, 852,
#     1917, 3838, 84, 2355, 1131, 1836, 1014, 1688, 3679, 1272, 2239, 2454, 1937,
#     342, 1822, 2315, 36, 565, 3830, 3028, 114, 1287, 2713, 3782, 973, 303, 387,
#     1346, 301, 740, 19, 2576, 906, 3971, 4074, 4216, 1029, 2107, 3629, 2919,
#     3752, 1819, 3378, 1474, 648, 464, 3567, 698, 2920, 230, 1493, 4190, 363,
#     2177, 1197, 2034, 372, 1787, 3244, 272, 3307, 3467, 960, 1508, 545, 13,
#     485, 2948, 289, 792, 1117, 3701, 445, 1776, 814, 325, 890, 1995, 257, 2158,
#     4111, 3348, 1308, 1694, 3841, 1262, 2372, 1366, 2420, 3921, 3990, 4128,
#     4087, 3725, 2121, 2842, 2060, 1533, 412, 100, 2449, 2979, 4026, 2444, 2574,
#     1613, 1618, 2390, 3854, 2774, 564, 642, 2647
# ]

tmp = np.array([1] * 148)
labels = np.concatenate((labels,tmp))
# balanced = np.take(evaluation, indices, axis=0)
# print balanced.shape, evaluation[len(labels):, :].shape
# balanced = np.concatenate((balanced, evaluation[len(labels):, :]), axis = 0)
# labels=np.take(labels,indices)

#plotData(dt,2,4,"normal", oneClass=False)
#print len(labels), len(evaluation)
#print originalDt[0:5]


#--------- outlier distance based
# th = 0.55
# n_clust = 4
# res, kmean = outlierDistanceBased(train, n_clust , th)
# for i in range(n_clust):
#     print i, len(res[i])

# #to check on a subset
# dist = kmean.transform(balanced)
# clustersInd = kmean.predict(balanced)
# count = 0
# predicted = []
# for i in range(len(balanced)):
#     if dist[i][clustersInd[i]] > th :
#         count +=1
#         predicted.append(1)
#     else:
#         predicted.append(0)
# print "found " + str(count) + " ouliers over " + str(len(balanced)) + " connections "
# print str( (count/len(balanced))*100) + "%"

# # #get all the outliers reported in the training data
# # # dt_outliers = [dt[j] for j in res[0]]
# # # for i in range(1, n_clust):
# # #     outliers = [dt[j] for j in res[i]]
# # #     print len(outliers)
# # #     print len(dt_outliers)
# # #     dt_outliers = np.concatenate((dt_outliers, outliers), axis=0)
# # dt_outliers = np.concatenate((dt_outliers, evaluation), axis = 0)
# # plotData(dt,2,n_clust,'ciao',evaluation, oneClass=False)

# #to check directly on the training data
# # predicted = [0] * len(evaluation)
# # for k in range(n_clust):
# #     for i in res[k]:
# #         predicted[i] = 1

# labels= list(labels)
# # print labels[0:10]
# # print predicted[0:10]

# print "len of labels and predicted:"
# print len(labels), len(predicted)
# labels = labels[0:len(predicted)]

# #random guessing
# for i in range(len(predicted)):
#     predicted[i] = random.randint(0,1)

# cm = metrics.confusion_matrix(list(labels), list(predicted), labels=[1, 0])
# print cm
# tp, fn, fp, tn = cm.ravel()

# print tp, fp, fn, tn
# print 'accuracy ', (tp + tn) / (tp + tn + fp + fn + 0.0) * 100
# print 'precision ', (tp) / (tp + fp + 0.0) * 100
# print 'recall ', (tp) / (tp + fn + 0.0) * 100
# print 'far ', fp / (fp + tn + 0.0) * 100




#-------------outlier 1class svm
# n_clust = 4

# r = []
# r.append(outlier1CSVMTrain(train,n_clust, 0.5))
# # r.append(outlier1CSVMTrain(evaluation,n_clust, 0.15))
# # r.append(outlier1CSVMTrain(evaluation,n_clust, 0.15,))
# # r.append(outlier1CSVMTrain(evaluation,n_clust, 0.15))
# #load models
# # res = {}
# # res["kmean"] = joblib.load('./models/kmeanNormalAlimenti.joblib')
# # for i in range(n_clust):
# #     res[i] = {}
# #     res[i]["clf"] = joblib.load('./models/oneCsvm_'+str(i)+'_001.joblib')
# c=0
# for res in r:
#     print '--------------',  c, '-----------------'
#     km = res["kmean"]
#     c+=1
#     for i in range(n_clust):
#         print "cluster " + str(i) + ": " + str(len(res[i]["trainNormIndices"])) + " normals, " + str(len(res[i]["trainOutIndices"])) + " outliers"

#     # #plot model result
#     # dt_outliers = [dt[j] for j in res[0]["trainOutIndices"]]
#     # dt_normals = [dt[j] for j in res[0]["trainNormIndices"]]
#     # for i in range(1,n_clust):
#     #     outliers = [dt[j] for j in res[i]["trainOutIndices"]]
#     #     normals = [dt[j] for j in res[i]["trainNormIndices"]]
#     #     dt_outliers = np.concatenate((dt_outliers, outliers), axis=0)
#     #     dt_normals = np.concatenate((dt_normals, normals), axis=0)
#     #plotData(dt_normals,2,n_clust,'ciao',dt_outliers, oneClass=False)

#     #evaluation only on evaluation dataset
#     # predicted = [0] * len(evaluation)
#     # for k in range(n_clust):
#     #     for i in res[k]["trainOutIndices"]:
#     #         predicted[i] = 1
#     # print "len of labels and predicted:"
#     # print len(labels), len(predicted)

#     #PREDICTION on a subset
#     attackClusters = km.predict(evaluation)
#     outliersCount = 0.0
#     predicted = []
#     for i in range(len(evaluation)):
#         k = attackClusters[i]
#         r = res[k]["clf"].predict(evaluation[i].reshape(1,-1))
#         if r == -1:
#             outliersCount += 1
#             predicted.append(1)
#         else:
#             predicted.append(0)

#     # # dt_outliers = np.concatenate((dt_outliers, evaluation), axis = 0)
#     # plotData(dt_normals,2,n_clust,'ciao',dt_outliers, oneClass=False)
#     # print "found " + str(outliersCount) + " ouliers over " + str(len(evaluation)) + " connections "
#     # print str( (outliersCount/len(evaluation))*100) + "%"

   
#     labels = labels[0:len(predicted)]
#     cm = metrics.confusion_matrix(
#             list(labels), list(predicted), labels=[1, 0])
#     print cm
#     tp, fn, fp, tn = cm.ravel()

#     print tp, fp, fn, tn
#     print 'accuracy ', (tp + tn) / (tp + tn + fp + fn + 0.0) * 100
#     print 'precision ', (tp) / (tp + fp + 0.0) * 100
#     print 'recall ', (tp) / (tp + fn + 0.0) * 100
#     print 'far ', fp / (fp + tn + 0.0) * 100


# # save model
# joblib.dump(km, './models/kmeanNormalAlimenti.joblib')
# for k in range(n_clust):
#     joblib.dump(res[k]["clf"], './models/oneCsvm_'+str(k)+'_001.joblib')


# for i in range(n_clust):
#     name = "outliers"+str(i)+".csv"
#     outliers = [originalDt[j] for j in res[i]["trainOutIndices"]]
#     with open(name, 'wb') as csvfile:
#         sw = csv.writer(
#             csvfile, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
#         for con in outliers:
#            sw.writerow(con)
#TODO: find a better way to catch "cat" because it appears in a lot a words
#TODO: per identificare le soglie sulla lunghezza da non considerare overflow e potenziale DOS usare cdf per capire l'andamento generale del sistem

#subsetGenerator('./logs/merged_anon_access_log', 10)


#pure one class svm
# clf = svm.OneClassSVM(nu=0.01, kernel="rbf", gamma='auto')
# pred = clf.fit_predict(dt)
# outIndices = []
# for i in range(len(pred)):
#     if pred[i] == -1:
#         outIndices.append(i)


#session evaluation
# dt = utilities.loadDataset('./sessionsVector.csv')
# print dt.shape
# scaler = MinMaxScaler(feature_range=(0, 1))
# #dt = np.delete(dt, [1,2,3,4,5,6,7,8,16,17,19], axis=1)
#dt = scaler.fit_transform(dt[:,:])

# print len(dt), len(outIndices)

#plotData(dt, 2, 3, "normal", oneClass=False)
# # --------- outlier distance based
# th = 1.0
# n_clust = 4
# res, kmean = outlierDistanceBased(dt, n_clust , th)
# for i in range(n_clust):
#     print i, len(res[i])

#-------------outlier 1class svm
# n_clust = 2

# res = outlier1CSVMTrain(dt,n_clust)
# km = res["kmean"]
# for i in range(n_clust):
#     print "cluster " + str(i) + ": " + str(len(res[i]["trainNormIndices"])) + " normals, " + str(len(res[i]["trainOutIndices"])) + " outliers"

# dt_outliers = [dt[j] for j in res[0]["trainOutIndices"]]
# dt_normals = [dt[j] for j in res[0]["trainNormIndices"]]
# for i in range(1,n_clust):
#     outliers = [dt[j] for j in res[i]["trainOutIndices"]]
#     normals = [dt[j] for j in res[i]["trainNormIndices"]]
#     dt_outliers = np.concatenate((dt_outliers, outliers), axis=0)
#     dt_normals = np.concatenate((dt_normals, normals), axis=0)
# plotData(dt_normals,2,n_clust,'ciao',dt_outliers, oneClass=False)
#save model
# joblib.dump(km, './models/kmeanNormalAlimenti.joblib')
# for k in range(n_clust):
#     joblib.dump(res[k]["clf"], './models/oneCsvm_'+k+'_001.joblib')



# for i in range(n_clust):
#     name = "outliers"+str(i)+".csv"
#     outliers = [dt[j] for j in res[i]["trainOutIndices"]]
#     with open(name, 'wb') as csvfile:
#         sw = csv.writer(
#             csvfile, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
#         for con in outliers:
#            sw.writerow(con)

# #heuristic evaluation
log = fileToDic('./logs/raw_complete_evaluation')
report = heuristics.checkRefAndUserAgentFingerprints(log, {})
report = heuristics.checkReqFingerprints(log, report )
report = heuristics.checkStatusCode(log, report)
print log[0:2]
hpred = []
for c in log:
    k = hashlib.md5(bencode.bencode(c)).hexdigest()
    if not k in report or ( report[k]["aloneAlerts"] == 0 and report[k]["otherAlerts"] <= 1 ):
        hpred.append(0)
    else:
        hpred.append(1)
print len(labels), len(hpred)

labels = labels[0:len(hpred)]
cm = metrics.confusion_matrix(
        list(labels), list(hpred), labels=[1, 0])
print cm
tp, fn, fp, tn = cm.ravel()

print tp, fp, fn, tn
print 'accuracy ', (tp + tn) / (tp + tn + fp + fn + 0.0) * 100
print 'precision ', (tp) / (tp + fp + 0.0) * 100
print 'recall ', (tp) / (tp + fn + 0.0) * 100
print 'far ', fp / (fp + tn + 0.0) * 100

#migliora label delle immagini
#fai test con dataset bilianciato (pochi normali, circa il doppio o il triplo degli attacchi)
#dividi la sitografia