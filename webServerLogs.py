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

nexceeding = 0  #used for file names exceeding the maximum name length


def fileToDic(filePath): #takes a raw web server log and returns a list of connections represented as a dictionary (for an example look che a connection in session.json)
    line_parser = alp.make_parser(
        "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"")
    with open(filePath) as f:
        content = f.readlines()
        log = []
        for conn in content:
            if len(conn) <= 2:
                continue
            logData = line_parser(conn)

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
                "ProtocolVersion":
                '"' + str(logData["request_http_ver"]) + '"',
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


def logToCsv( #takes a json describing the log and saves it in csv format
        log, dst, complete, short=True
):  #dst is the name of the csv, set short to True if you don't want the parameters as features
    l = log[0]
    if complete is None:
        complete = log
    if len(dst) > 255:
        global nexceeding
        dst = dst[0:250] + str(nexceeding) + ".csv"
        nexceeding += 1
    with open(dst, 'wb') as csvfile:
        sw = csv.writer(
            csvfile, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
        k = [key for key, value in l.items() if key != 'ReqParameters']
        k.append("requestLength")
        k.append("nParameters")
        param = set()  #it will be the list of all the parameters
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
            k = [value for key, value in l.items() if key != 'ReqParameters']
            #k[1] = 0 if k[1] == '-' else float(k[1]) #converting the return size to float
            k.append(len(l["ServerPath"]))
            k.append(len(l["ReqParameters"]))
            if not short:
                for p in param:
                    p = p[1:-1]  #removing quotes
                    if p in l["ReqParameters"]:
                        try:
                            k.append(float(l["ReqParameters"][p]))
                        except:
                            k.append('"' + l["ReqParameters"][p] + '"')
                    else:
                        k.append("")
            sw.writerow(k)


def normalLog( #takes a raw log file as input and creates the csv files of connections marked as attacks and normals by the heuristics
        logPath, splitByRes=True, short=False
):  #set short to True if you don't want the request parameters as features; set splitByRes to false if you don't want a different csv for each resource
    log = fileToDic(logPath)
    report = heuristics.checkRefAndUserAgentFingerprints(log, {})
    report = heuristics.checkReqFingerprints(log, report)
    report = heuristics.checkStatusCode(log, report)

    if splitByRes:
        normalLog = {
        }  #dictionary in which the keys are the resources and the values are the normal connections for that resource
        signaledLog = {}
        for el in log:
            try:
                k = hashlib.md5(bencode.bencode(el)).hexdigest()
                res = el["Resource"]
                if not k in report or (
                        report[k]["aloneAlerts"] == 0
                        and report[k]["otherAlerts"] <= 1
                ):  # if the connection has not been reported by the heuristics
                    if not res in normalLog:
                        normalLog[res] = []
                    normalLog[res].append(el.copy())
                else:
                    if not res in signaledLog:
                        signaledLog[res] = []
                    signaledLog[res].append(el.copy())
            except:
                print "something went wrong"
                print el
    else:
        normalLog = []  #the list of all normal connection
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
                complete = np.concatenate(
                    (normalLog[k], signaledLog[k]), axis=0)
            else:
                complete = None
            logToCsv(normalLog[k],
                     normDir + '/' + k.replace('/', '_') + '.csv', complete,
                     short)

        if not os.path.exists(signaledDir):
            os.makedirs(signaledDir)
        for k in signaledLog:
            if k in normalLog and k in signaledLog:
                complete = np.concatenate(
                    (normalLog[k], signaledLog[k]), axis=0)
            else:
                complete = None
            logToCsv(signaledLog[k],
                     signaledDir + '/' + k.replace('/', '_') + '.csv',
                     complete, short)
        print "ONE DONE"
    else:
        logToCsv(normalLog, normDir + '.csv', log, short)
        logToCsv(signaledLog, signaledDir + '.csv', log, short)


def sessionConverter(log): #takes as input a log list (coming from fileToDict) and return a json describing sessions (an example is sessiongs.json)

    #t1= l[0]["TimeStamp"]
    for el in log:
        #print el["RemoteHostAdress"], el["TimeStamp"], el["UserAgent"]
        k = el["RemoteHostAdress"] + el["UserAgent"]
        #print k
        FMT = '%d/%b/%Y:%H:%M:%S'
        if not k in sessions:
            sessions[k] = [{'t0': el["TimeStamp"], 'connections': [el]}]
        #   print "adding new key"
        else:
            t1 = sessions[k][-1]['t0'][
                1:
                -1]  #the last element with key k contains the last session, the only one in which our element can be insterted
            t2 = el["TimeStamp"][1:-1]
            d = datetime.strptime(t2, FMT) - datetime.strptime(t1, FMT)
            #print d
            if d.days > 0 or d.seconds > 1800:  #a new session with the same ip + user agent needs to be added
                # print "> 30 min"
                sessions[k].append({
                    't0': el["TimeStamp"],
                    'connections': [el]
                })
            else:  #the request need to be added to the current session
                #print "ok"
                sessions[k][-1]["connections"].append(el)
    #print "----------------------------------------------------------------------"
    #print sessions
    with open('sessions.json', 'w') as fp:
        json.dump(sessions, fp, indent=4, separators=(',', ': '))
    return sessions


def sessionVectorizer(sessions): #takes a sessions json and express session in csv format using frequency features

    uniqueResources = set()  #a set of resources
    bw = set()
    for k in sessions:  #iterate over session outer key
        for s in sessions[k]:  #iterate over sessions with the same inner key
            for con in s["connections"]:
                uniqueResources.add(con["Resource"])
                bw.add(con["ReturnSize"])
    print("uniqueResources done")
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
            for s in sessions[
                    k]:  #iterate over sessions with the same inner key
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
                        oldTime = datetime.strptime(con["TimeStamp"][1:-1],
                                                    FMT)
                    else:
                        currTime = datetime.strptime(con["TimeStamp"][1:-1],
                                                     FMT)
                        if (currTime - oldTime).seconds > 10:
                            counter["nTimeGt10s"] += 1
                        elif (currTime - oldTime).seconds < 1:
                            counter["nTimeLess1s"] += 1
                        oldTime = currTime
                    reqs.append(
                        con["ServerPath"])  #used to count repeated requests
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
                            counter["nBwGt20000"] += 1
                        else:
                            counter["nBwLess20000"] += 1
                    conHour = datetime.strptime(con["TimeStamp"][1:-1],
                                                FMT).hour
                    if conHour >= 00 and conHour <= 7:
                        counter["TotalNightTimeReq"] += 1
                    found = False
                    for r in uniqueResources:
                        if con['Resource'] == r:
                            counter["res_" + r] += 1
                            found = True
                            break
                    if not found:
                        counter["res_other"] += 1
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


def sessionDatasetConverter(
        sessions, file
):  #this functions takes a json describing sessions and ectract the features used in https://www.researchgate.net/publication/276139295_Agglomerative_Approach_for_Identification_and_Elimination_of_Web_Robots_from_Web_Server_Logs_to_Extract_Knowledge_about_Actual_Visitors
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
        for k in sessions:  #iterate over session outer key
            for s in sessions[
                    k]:  #iterate over sessions with the same inner key
                totalHits = len(s["connections"])
                FMT = '%d/%b/%Y:%H:%M:%S'
                sessionTime = (datetime.strptime(
                    s["connections"][-1]["TimeStamp"][1:-1],
                    FMT) - datetime.strptime(
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
                r0 = 0  #used for counting the time between two html requests
                IsRobotTxtVisited = 0
                times = []
                reqs = []
                nMisbehavior = 0
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
                    c = geolite2.lookup(ip)
                    if c is not None:
                        geoIp = c.country
                    #ipsCache[ip] = [isBlackListed, geoIp]
                    ipsCache[ip] = [
                        0, geoIp
                    ]  # remove this line if you want to check DNSBL

                for con in s["connections"]:

                    k = hashlib.md5(bencode.bencode(con)).hexdigest()
                    if k in report:
                        nMisbehavior += report[k]["alerts"]
                        nAloneMisbehavior += report[k]["aloneAlerts"]
                        nOtherMibehavior += report[k]["otherAlerts"]
                    reqs.append(
                        con["ServerPath"])  #used to count repeated requests
                    if ".jpg" in con["Resource"] or ".png" in con["Resource"] or ".svg" in con["Resource"] or ".tiff" in con["Resource"] or ".gif" in con["Resource"] or ".ico" in con["Resource"]:
                        images += 1
                    if ".cgi" in con["Resource"] or ".htm" in con["Resource"] or ".html" in con["Resource"] or ".js" in con["Resource"] or ".php" in con["Resource"]:
                        html += 1
                        if r0 == 0:
                            r0 = con["TimeStamp"][1:-1]
                        else:
                            r1 = con["TimeStamp"][1:-1]
                            t = (datetime.strptime(r0, FMT) -
                                 datetime.strptime(r1, FMT)).seconds
                            times.append(t)
                            r0 = r1
                    if ".doc" in con["Resource"] or ".pdf" in con["Resource"] or ".ps" in con["Resource"] or ".xls" in con["Resource"] or ".ppt" in con["Resource"]:
                        doc += 1
                    if ".cgi" in con["Resource"] or ".exe" in con["Resource"] or ".py" in con["Resource"] or ".dll" in con["Resource"] or ".dat" in con["Resource"] or ".jar" in con["Resource"]:
                        exe += 1
                    if ".txt" in con["Resource"] or ".cpp" in con["Resource"] or ".java" in con["Resource"] or ".xml" in con["Resource"] or ".c" in con["Resource"] or ".odf" in con["Resource"] or ".csv" in con["Resource"]:
                        Ascii += 1
                    if ".zip" in con["Resource"] or ".rar" in con["Resource"] or ".gzip" in con["Resource"] or ".tar" in con["Resource"] or ".gz" in con["Resource"]:
                        Zip += 1
                    if ".mp3" in con["Resource"] or ".mp4" in con["Resource"] or ".wmv" in con["Resource"] or ".avi" in con["Resource"] or ".mpeg" in con["Resource"]:
                        multimedia += 1
                    if ".css" in con["Resource"] or ".com" in con["Resource"] or ".swf" in con["Resource"]:
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
                    conHour = datetime.strptime(con["TimeStamp"][1:-1],
                                                FMT).hour
                    if conHour >= 00 and conHour <= 7:
                        totalNightTimeReq += 1
                pImages = (images / totalHits) * 100
                pHtml = (html / totalHits) * 100
                pDoc = (doc / totalHits) * 100
                pExe = (exe / totalHits) * 100
                pAscii = (Ascii / totalHits) * 100
                pZip = (Zip / totalHits) * 100
                pMultimedia = (multimedia / totalHits) * 100
                pOtherFile = (other / totalHits) * 100
                if len(times) > 0:
                    avgHtmlReqTime = reduce(lambda x, y: x + y,
                                            times) / len(times)
                else:
                    avgHtmlReqTime = 0
                uniqueReq = set(reqs)
                totalRepeatedReq = 0
                for r in uniqueReq:
                    c = reqs.count(r)
                    if c > 1:
                        totalRepeatedReq += c
                pErrors = (errors / totalHits) * 100

                pGet = (gets / totalHits) * 100
                pPost = (posts / totalHits) * 100
                pHead = (heads / totalHits) * 100
                pOtherMethod = (otherMethods / totalHits) * 100
                pUnassignedReferrer = (unassignedReferrer / totalHits) * 100
                sw.writerow([
                    totalHits, pImages, pHtml, pDoc, pExe, pAscii, pZip,
                    pMultimedia, pOtherFile, bandWidth, sessionTime,
                    avgHtmlReqTime, totalNightTimeReq, totalRepeatedReq,
                    pErrors, pGet, pPost, pOtherMethod, IsRobotTxtVisited,
                    pHead, pUnassignedReferrer, nMisbehavior,
                    nAloneMisbehavior, nOtherMibehavior, geoIp
                ])



def plotData(dt, n_axes=2, n_clust=4, originalDt = None, attackDt=None, oneClass=False): #plot data in 2d, dt is the dataset to plot, n_axes is usually 2 for 2d, n_clust is the number of clusters for kmean, originaldt should not be used, attackDt is usefull if you want to plot two sets of datapoints with different colors. OneClass SVM = true will train a oneClass svm for each cluster, and shows you the output
    if attackDt is not None:
        alldt = np.concatenate((dt, attackDt), axis=0)
        limit = len(dt)

        reduced_all = PCA(n_components=n_axes).fit_transform(alldt[:, :])
        reduced_data = reduced_all[0:limit, :]
        reduced_data_attack = reduced_all[limit:, :]
        print len(reduced_data)
        print len(reduced_data_attack)

    else:
        reduced_data = PCA(n_components=n_axes).fit_transform(dt[:, :])
    # if attackDt is not None:
    #     reduced_data_attack = PCA(n_components=n_axes).fit_transform(attackDt)
    c = np.array([[-0.73989116, -0.09185221], [1.39323709, 0.47200059],
                  [2.0422567, -0.40404301], [0.61062697, 1.54731632]])
    kmeans = KMeans(init=c, n_clusters=n_clust)
    if attackDt is not None:
        kmeans.fit(
            reduced_all
        )  #if you want to train with the normal change to reduced_data
    else:
        kmeans.fit(reduced_data)
    print kmeans.transform(reduced_data[0:2])
    # Step size of the mesh. Decrease to increase the quality of the VQ.
    h = .02  # point in the mesh [x_min, x_max]x[y_min, y_max].

    if attackDt is None:
        # Plot the decision boundary. For that, we will assign a color to each
        x_min, x_max = reduced_data[:, 0].min() - 1, reduced_data[:,
                                                                  0].max() + 1
        y_min, y_max = reduced_data[:, 1].min() - 1, reduced_data[:,
                                                                  1].max() + 1
    else:
        x_min, x_max = reduced_all[:, 0].min() - 1, reduced_all[:, 0].max() + 1
        y_min, y_max = reduced_all[:, 1].min() - 1, reduced_all[:, 1].max() + 1

    xx, yy = np.meshgrid(
        np.arange(x_min, x_max, h), np.arange(y_min, y_max, h))

    labels = kmeans.predict(reduced_data)

    d = {}  #data
    c = {}  #classifiers
    resNorm = {}  #marked normal by clf
    resOut = {}  #marked outlier by clf
    #things related to 1 class svm
    if oneClass:

        for i in range(n_clust):
            d[i] = []
            c[i] = svm.OneClassSVM(nu=0.01, kernel="rbf", gamma='auto')
            resNorm[i] = []
            resOut[i] = []

        for i in range(len(reduced_data)):  #split data basing on cluster label
            d[labels[i]].append(reduced_data[i])
        print "data splitted"
        for k in d:
            print k
            print len(d[k])
        for k in c:  #train the 1classSVM
            print k
            print len(d[k])
            c[k].fit(d[k])  #c[k].fit( np.array(d[k])[0:2000,:] )
            res = c[k].predict(d[k])
            print "prediction " + str(k) + " done"
            for i in range(len(res)):
                if res[i] == 1:
                    resNorm[k].append(d[k][i])
                else:
                    resOut[k].append(d[k][i])
            print "res " + str(k) + " splitted"

    # Obtain labels for each point in mesh. Use last trained model.
    Z = kmeans.predict(np.c_[xx.ravel(), yy.ravel()])


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
            print k, "norm " + str(len(resNorm[k])), "out " + str(
                len(resOut[k]))
            plt.plot(
                np.array(resNorm[k])[:, 0],
                np.array(resNorm[k])[:, 1],
                'b.',
                markersize=1)
            plt.plot(
                np.array(resOut[k])[:, 0],
                np.array(resOut[k])[:, 1],
                'r.',
                markersize=1)
    else:
        plt.plot(reduced_data[:, 0], reduced_data[:, 1], 'b.', markersize=1)
        if attackDt is not None:
            plt.plot(
                reduced_data_attack[:, 0],
                reduced_data_attack[:, 1],
                'r.',
                markersize=1)
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
    plt.title('K-means clustering on PCA-reduced data\n'
              'Centroids are marked with red cross')
    plt.xlim(x_min, x_max)
    plt.ylim(y_min, y_max)
    plt.xticks(())
    plt.yticks(())
    plt.show()
    return plt


def outlier1CSVMTrain(dt, n_clust, th, gamma='auto'): #trains the model using kmeans and oneClass SVM, th is the nu parameter for the oneclass svm
    #the result is a dictionary like the following:
    # {
    #     "kmean": kmeans trained model,
    #     "0":{
    #         "data": indices of connections assigned to the cluster 0
    #         "clf": trained one class svm
    #         "trainNormIndices": indices of normal items for this cluster
    #         "trainOutIndices": indices of outliers items for this cluster
    #     }
    #     "1" reapeated for each cluster
    #     .
    #     .
    #     .
    # }
    kmeans = KMeans(init='k-means++', n_clusters=n_clust)

    kmeans.fit(dt)
    labels = kmeans.predict(dt)

    res = {}
    res["kmean"] = kmeans
    for i in range(n_clust):
        res[i] = {}
        res[i]["data"] = []  #indices of data assigned to cluster i
        res[i]["clf"] = svm.OneClassSVM(
            nu=th, kernel="rbf", gamma=gamma)  #1class svm for cluster i
        res[i]["trainNormIndices"] = [
        ]  #indices of items marked as actually belonging to cluster i
        res[i]["trainOutIndices"] = [
        ]  #indices of items marked as outlier for the cluster i

    for i in range(len(dt)):  #split data basing on cluster label
        res[labels[i]]["data"].append(i)
    print "data splitted"

    for k in range(n_clust):
        print k
        print len(res[k]["data"])

    for k in range(n_clust):  #train the 1classSVM
        data = [dt[j] for j in res[k]["data"]]
        predictions = res[k]["clf"].fit_predict(
            data)  #c[k].fit( np.array(d[k])[0:2000,:] )
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


def outlierDistanceBased(
        dt, n_clust, th
):  #trains the model using kmeans and oneClass SVM, th is the nu parameter for the oneclass svm
    kmeans = KMeans(init='k-means++', n_clusters=n_clust)

    dist = kmeans.fit_transform(dt)
    print dist[0]
    labels = kmeans.predict(dt)

    dist_to_cluster = {}
    for i in range(len(labels)):
        l = labels[i]
        if not l in dist_to_cluster:
            dist_to_cluster[l] = []
        dist_to_cluster[l].append(dist[i][l])

    for k in dist_to_cluster:
        avg = reduce(lambda x, y: x + y, dist_to_cluster[k]) / len(
            dist_to_cluster[k])
        print k, " avg: ", avg, " max: ", max(
            dist_to_cluster[k]), " min: ", min(
                dist_to_cluster[k]), " mean dev: ", np.std(
                    dist_to_cluster[k]), " median dev: ", robust.mad(
                        dist_to_cluster[k])

    outliersIndices = []
    for i in range(n_clust):
        outliersIndices.append([])
        print i, np.count_nonzero(labels == i)
    for i in range(len(dt)):
        if dist[i][labels[i]] > th:
            outliersIndices[labels[i]].append(
                i)  #append the index to the list related to his cluster

    return outliersIndices, kmeans


def subsetGenerator(path, percentage): #takes a raw log file and create a subset with the gives percentage of connections
    percentage = 10
    dt = fileToDic(path)
    res = {}
    print dt[0]
    for el in dt:
        r = el["Resource"]
        if not r in res:
            res[r] = []
        res[r].append(el)
    outSrc = {  # the sources where to take outliers
        "name": ['/alimenti', '/', '/combo/'],
        "n_clusts": [4, 2, 4],
        "numbers": [0, 0, 0],
        "outliers": [[], [], []]
    }
    output = []
    output1 = []

    for k in res:  #k is a resource
        n = (len(res[k]) * percentage
             ) / 100  #number of connection the we can take from this resource
        if k in outSrc["name"]:
            name = 'alimenti'
            if k == '/':
                name = 'home'
            elif k == '/combo/':
                name = 'combo'
            ind = outSrc["name"].index(k)
            outSrc["numbers"][ind] = n
            print name
            path1 = '/home/carlo/Documenti/Progetti/tesi/log/kmeanRes/all_' + name + '/distance_1.0/'
            path2 = '/home/carlo/Documenti/Progetti/tesi/log/kmeanRes/all_' + name + '/1CLASS_001/'
            for j in range(outSrc["n_clusts"][ind]):
                cluster = 'outliers' + str(j) + '.csv'
                p1 = path1 + cluster
                p2 = path2 + cluster
                d1 = utilities.loadDataset(p1)
                d2 = utilities.loadDataset(p2)
                if outSrc["outliers"][ind] == []:
                    outSrc["outliers"][ind] = d1[:, :]
                else:
                    outSrc["outliers"][ind] = np.concatenate(
                        (outSrc["outliers"][ind], d1), axis=0)
                outSrc["outliers"][ind] = np.concatenate(
                    (outSrc["outliers"][ind], d2), axis=0)

            if len(outSrc["outliers"][ind] > n / 2):
                # random.shuffle(outSrc["outliers"][ind])
                # if output == []:
                #     output=outSrc["outliers"][ind][0:n/2, 0:12]
                # else:
                #     output = np.concatenate(( output, outSrc["outliers"][ind][0:n/2, 0:12]), axis=0)
                n = n / 2
            else:
                # if output == []:
                #     output = outSrc["outliers"][ind][:,0:12]
                # else:
                #     output = np.concatenate(
                #         (output, outSrc["outliers"][ind][:,0:12]), axis=0)
                n = n - len(outSrc["outliers"][ind])

        random.shuffle(res[k])  #change the order
        if n == 0:
            n = 1
        if output == []:
            output = res[k][0:n]
        else:
            output = np.concatenate((output, res[k][0:n]), axis=0)
        m = n / 10
        if m == 0:
            m = 1
        if output1 == []:
            output1 = res[k][n:n + m]
        else:
            output1 = np.concatenate((output1, res[k][n:n + m]), axis=0)
    dst1 = 'evaluation_dt' + str(percentage) + 'percent.csv'
    logToCsv(output, dst1, None)
    dst2 = 'evaluation_dt' + str(1) + 'percent.csv'
    logToCsv(output1, dst2, None)

    with open(dst1, 'a') as csvfile:
        with open(dst2, 'a') as csvfile2:
            for i in range(3):
                print '-----------', outSrc["numbers"][i]
                sw = csv.writer(
                    csvfile,
                    delimiter=',',
                    quotechar='"',
                    quoting=csv.QUOTE_MINIMAL)
                sw2 = csv.writer(
                    csvfile2,
                    delimiter=',',
                    quotechar='"',
                    quoting=csv.QUOTE_MINIMAL)

                n = min(len(outSrc["outliers"][i]), outSrc["numbers"][i] / 2)
                n2 = min(len(outSrc["outliers"][i]), outSrc["numbers"][i] / 20)
                random.shuffle(outSrc["outliers"][i])
                for o in outSrc["outliers"][i][0:n + 1, 0:12]:
                    sw.writerow(o)
                random.shuffle(outSrc["outliers"][i])
                for o in outSrc["outliers"][i][0:n2 + 1, 0:12]:
                    sw2.writerow(o)

