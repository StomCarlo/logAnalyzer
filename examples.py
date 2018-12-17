import utilities
import webServerLogs as wsl
import numpy as np
import matplotlib.pyplot as plt
from sklearn.externals import joblib
from sklearn import metrics


#this files reports many examples, to run one of them uncomment it and run this file

#session generation (from raw log to sessions in csv)

file = './logs/merged_anon_access_log' #change the file name as needed
l = wsl.fileToDic(file)
sessions=wsl.sessionConverter(l)
wsl.sessionVectorizer(sessions) #use this one if you want sessions features with  frequencies and percentages
#wsl.sessionDatasetConverter(sessions,file) #use this is you want sessions features with only as frequencies

#session generation (from session json to sessions csv)

#with open('sessions.json') as f:
#     sessions = json.load(f)
#     wsl.sessionVectorizer(sessions) #use this one if you want sessions features with  frequencies and percentages
#     wsl.sessionDatasetConverter(sessions,file) #use this is you want sessions features with only as frequencies

#create csv file describing normal and signaled connestions as marked by the heuristics, splitted by resource
#wsl.normalLog('./logs/merged_anon_access_log', splitByRes=True) #change the file name as needed

#kmean over a log file , calculate min, man and avg dists
# dt = utilities.loadDataset_hash(FILEPATH) #file path is the path to a csv
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

# train, evaluation = utilities.loadDatasets_hash(
#     '~/Documenti/Progetti/tesi/log/outputs/normalraw_complete_evaluation.csv',
#     './allEvaluation_long.csv')

# labelsDT = utilities.loadDataset(
#     './outputs/evaluation/evaluation_dt1percent.csv', separetor=',')

# labels = labelsDT[:, -1]

# #--------- outlier distance based
# th = 0.58
# n_clust = 4
# res, kmean = wsl.outlierDistanceBased(train, n_clust, th)
# for i in range(n_clust):
#     print i, len(res[i])

# #to check on a subset
# dist = kmean.transform(evaluation)
# clustersInd = kmean.predict(evaluation)
# count = 0
# predicted = []
# for i in range(len(evaluation)):
#     if dist[i][clustersInd[i]] > th:
#         count += 1
#         predicted.append(1)
#     else:
#         predicted.append(0)

# print "len of labels and predicted:"
# print len(labels), len(predicted)
# labels = labels[0:len(predicted)]

# cm = metrics.confusion_matrix(list(labels), list(predicted), labels=[1, 0])
# print cm
# tp, fn, fp, tn = cm.ravel()

# print tp, fp, fn, tn
# print 'accuracy ', (tp + tn) / (tp + tn + fp + fn + 0.0) * 100
# print 'precision ', (tp) / (tp + fp + 0.0) * 100
# print 'recall ', (tp) / (tp + fn + 0.0) * 100
# print 'far ', fp / (fp + tn + 0.0) * 100

# -------------outlier 1class svm
# n_clust = 4
# res = wsl.outlier1CSVMTrain(train,n_clust, 0.5)_clust, 0.15))
# load models
# res = {}
# res["kmean"] = joblib.load('./models/kmeanNormalAlimenti.joblib')
# for i in range(n_clust):
#     res[i] = {}
#     res[i]["clf"] = joblib.load('./models/oneCsvm_'+str(i)+'_001.joblib')

# km = res["kmean"]
# c+=1
# for i in range(n_clust):
#     print "cluster " + str(i) + ": " + str(len(res[i]["trainNormIndices"])) + " normals, " + str(len(res[i]["trainOutIndices"])) + " outliers"

# #plot model result
# dt_outliers = [dt[j] for j in res[0]["trainOutIndices"]]
# dt_normals = [dt[j] for j in res[0]["trainNormIndices"]]
# for i in range(1,n_clust):
#     outliers = [dt[j] for j in res[i]["trainOutIndices"]]
#     normals = [dt[j] for j in res[i]["trainNormIndices"]]
#     dt_outliers = np.concatenate((dt_outliers, outliers), axis=0)
#     dt_normals = np.concatenate((dt_normals, normals), axis=0)
# plotData(dt_normals,2,n_clust,'ciao',dt_outliers, oneClass=False)

# PREDICTION on a subset
# attackClusters = km.predict(evaluation)
# outliersCount = 0.0
# predicted = []
# for i in range(len(evaluation)):
#     k = attackClusters[i]
#     r = res[k]["clf"].predict(evaluation[i].reshape(1,-1))
#     if r == -1:
#         outliersCount += 1
#         predicted.append(1)
#     else:
#         predicted.append(0)

# labels = labels[0:len(predicted)]
# cm = metrics.confusion_matrix(
#         list(labels), list(predicted), labels=[1, 0])
# print cm
# tp, fn, fp, tn = cm.ravel()

# print tp, fp, fn, tn
# print 'accuracy ', (tp + tn) / (tp + tn + fp + fn + 0.0) * 100
# print 'precision ', (tp) / (tp + fp + 0.0) * 100
# print 'recall ', (tp) / (tp + fn + 0.0) * 100
# print 'far ', fp / (fp + tn + 0.0) * 100

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

# session evaluation
# dt = utilities.loadDataset('./sessionsVector.csv')
# print dt.shape
# scaler = MinMaxScaler(feature_range=(0, 1))
# #dt = np.delete(dt, [1,2,3,4,5,6,7,8,16,17,19], axis=1)
# dt = scaler.fit_transform(dt[:,:])

# print len(dt), len(outIndices)

# wsl.plotData(dt, 2, 3, "normal", oneClass=False)
# # --------- outlier distance based
# th = 1.0
# n_clust = 4
# res, kmean = wsl.outlierDistanceBased(dt, n_clust , th)
# for i in range(n_clust):
#     print i, len(res[i])
