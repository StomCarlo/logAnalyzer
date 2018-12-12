import utilities
import webServerLogs as wsl

#this files reports many examples, to run one of them unsomment it and run this file

#session generation (from raw log to sessions in csv)

# file = './logs/merged_anon_access_log' #change the file name as needed
# l = fileToDic(file)
# sessions=sessionConverter(l)
# sessionVectorizer(sessions) #use this one if you want sessions features with  frequencies and percentages
# sessionDatasetConverter(sessions,file) #use this is you want sessions features with only as frequencies

#session generation (from session json to sessions csv)

#with open('sessions.json') as f:
#     sessions = json.load(f)
#     sessionVectorizer(sessions) #use this one if you want sessions features with  frequencies and percentages
#     sessionDatasetConverter(sessions,file) #use this is you want sessions features with only as frequencies


#create csv file describing normal and signaled connestions as marked by the heuristics, splitted by resource
#normalLog('./logs/merged_anon_access_log', splitByRes=True) #change the file name as needed

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

#dt = utilities.loadDataset_hash( #'./outputs/web_server_datasets/sessions/sessions.csv')
#'~/Documenti/Progetti/tesi/log/outputs/normalmerged_anon_access_log/_alimenti.csv')
#'./outputs/normalraw_complete_evaluation/_alimenti.csv')

#evaluation = utilities.loadDataset_hash( #'./outputs/web_server_datasets/sessions/sessions.csv')
#'./eval_correct.csv')
#'./allEvaluation_long.csv')
#'./outputs/normalraw_complete_evaluation/_alimenti.csv')

train, evaluation = utilities.loadDatasets_hash(
    '~/Documenti/Progetti/tesi/log/outputs/normalraw_complete_evaluation.csv',
    './allEvaluation_long.csv')
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
labelsDT = utilities.loadDataset(
    './outputs/evaluation/evaluation_dt1percent.csv', separetor=',')
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

labels = labelsDT[:, -1]

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
#indices = ind
# print indices
# print len(indices), '-----------'
indices = [
    2175, 3894, 7176, 4008, 4607, 1098, 3811, 5038, 97, 625, 267, 6210, 7278,
    6680, 4750, 2852, 2847, 6559, 49, 7056, 2694, 5924, 5583, 2168, 1103, 2753,
    6610, 1383, 398, 457, 5309, 7282, 3915, 2555, 3684, 1867, 368, 822, 1169,
    1939, 2877, 4254, 6106, 3272, 6770, 2105, 7027, 6776, 46, 7213, 4016, 2263,
    357, 6010, 6304, 6446, 4591, 5260, 3062, 277, 2468, 4482, 1711, 721, 159,
    1528, 716, 6389, 7201, 5615, 5378, 2341, 5014, 4498, 1258, 1828, 6507, 98,
    1538, 388, 3862, 5448, 5767, 335, 6684, 2645, 2265, 6097, 201, 3446, 1377,
    2885, 1834, 6013, 5122, 3344, 698, 107, 1879, 2883, 3843, 4874, 7142, 5291,
    235, 4796, 969, 1203, 4951, 3921, 7173, 1658, 2464, 2141, 6644, 385, 4227,
    6125, 3522, 1581, 3513, 6131, 3190, 4977, 4442, 4915, 5711, 4426, 5838,
    1008, 3496, 7075, 3572, 371, 4778, 6437, 404, 3930, 6178, 5520, 644, 3250,
    2515, 35, 6501, 1473, 1547, 1716, 1967, 4687, 5739, 4525, 1181, 6101, 3404,
    5487, 2574, 1664, 5064, 4855, 2900, 7324, 4384, 5456, 243, 2242, 6040,
    2874, 1274, 3911, 3972, 1037, 4, 3420, 2678, 4770, 4857, 2067, 5373, 0, 68,
    1200, 1764, 6510, 6295, 333, 3301, 5719, 3176, 6506, 121, 5369, 5443, 2023,
    2439, 3711, 684, 5905, 4239, 297, 2280, 3135, 949, 860, 491, 397, 818,
    6327, 2411, 2921, 5401, 3320, 3626, 4907, 361, 396, 4416, 908, 3251, 7264,
    3783, 4773, 873, 3210, 967, 2075, 2853, 5618, 4225, 2169, 3600, 4924, 3641,
    5875, 1391, 5446, 5843, 3222, 4666, 2113, 5277, 3580, 5685, 7031, 4966,
    7107, 5246, 2881, 6128, 6849, 6062, 720, 36, 2481, 336, 7304, 3702, 6875,
    1904, 2815, 3165, 1594, 1378, 1480, 825, 5998, 5237, 1541, 1593, 7227, 603,
    1402, 7392, 6611, 2367, 101, 978, 3905, 6078, 7156, 3745, 1739, 4059, 3227,
    2126, 7315, 3865, 3648, 722, 588, 4713, 4204, 7290, 6118, 4290, 1482, 6245,
    1166, 1219, 6349, 1514, 3955, 158, 1058, 5894, 2475, 2278, 1155, 5210,
    6374, 1138, 4211, 5353, 5856, 3727, 5370, 5244, 2656, 1164, 1917, 5916,
    5495, 850, 6633, 3016, 6256, 5810, 4083, 7155, 6892, 2929, 3685, 2394,
    3197, 4497, 926, 2791, 3397, 3323, 47, 6780, 1796, 7309, 1442, 1059, 4064,
    765, 4391, 1747, 5965, 5594, 3853, 3990, 2710, 7010, 998, 2609, 3202, 5285,
    1686, 1469, 7015, 3264, 5777, 5356, 4302, 2354, 2833, 572, 6120, 2838,
    3294, 7086, 6464, 266, 1901, 387, 1073, 7083, 2425, 4319, 3861, 2543, 6487,
    6533, 449, 6250, 456, 1463, 6339, 3234, 3910, 2646, 1810, 2690, 4095, 876,
    7087, 185, 4082, 5963, 163, 3738, 5362, 1816, 6697, 7281, 3218, 425, 4986,
    3132, 4630, 510, 5131, 802, 1868, 6011, 7101, 6553, 2638, 285, 1727, 952,
    1242, 6368, 1745, 1068, 1370, 3713, 5681, 1708, 2670, 6664, 6135, 3009,
    5032, 6333, 5742, 1387, 4942, 1863, 4014, 5632, 508, 6885, 6539, 4464,
    2708, 6702, 4732, 347, 130, 5007, 5863, 4776, 6996, 1690, 6055, 4466, 2213,
    5960, 563, 1640, 2489, 3514, 5383, 1782, 3994, 1644, 1254, 5334, 183, 611,
    5895, 2873, 5842, 3565, 7362, 7276, 5539, 2361, 1055, 2952, 4331, 184,
    5156, 6960, 6588, 7303, 2120, 1842, 3286, 2496, 1139, 2217, 1412, 3427,
    3491, 1829, 7341, 356, 1886, 426, 7049, 5184, 7099, 4183, 6221, 4916, 1616,
    6878, 743, 6100, 1610, 2108, 4583, 4096, 4194, 5682, 5655, 3945, 4656,
    4250, 3275, 453, 3312, 902, 717, 1450, 2234, 4031, 2378, 1709, 714, 5970,
    6289, 5837, 3981, 857, 3194, 3966, 6612, 3444, 4365, 5547, 53, 4486, 1228,
    211, 6194, 72, 7041, 5162, 6858, 6228, 6240, 5232, 4009, 231, 1382, 5758,
    6818, 6268, 6447, 1399, 597, 5870, 4354, 1299, 1420, 5017, 889, 4109, 2381,
    1823, 2835, 4431, 2932, 2032, 2937, 2748, 5636, 5029, 224, 963, 2934, 1289,
    430, 4983, 1979, 5589, 3752, 5278, 538, 2399, 3583, 337, 1844, 5774, 1081,
    7091, 5306, 4202, 6725, 847, 669, 7194, 4408, 5486, 1029, 6038, 4324, 4279,
    3826, 5513, 178, 1374, 2985, 109, 547, 428, 3920, 2135, 710, 2805, 5801,
    4349, 2035, 1710, 5986, 3540, 5899, 7148, 3382, 977, 3497, 1883, 3656,
    2864, 696, 6204, 4084, 6574, 3916, 4743, 2310, 6317, 6096, 5835, 2146, 45,
    4494, 4495, 5822, 1637, 3055, 4343, 2855, 2925, 2397, 6342, 5715, 3158,
    4323, 5984, 5978, 6490, 3162, 2696, 4710, 1199, 6385, 4594, 6051, 4117,
    2021, 4321, 1183, 5413, 4053, 1428, 7271, 7293, 7292, 1833, 1120, 60, 4284,
    1540, 160, 4317, 236, 7338, 1561, 1861, 757, 1536, 7286, 7370, 7365, 1553,
    7375, 403, 4283, 359, 7356, 7323, 1133, 4527, 196, 4052, 688, 7326, 7275,
    1035, 7374, 138, 7267, 1425, 4663, 186, 7378, 798, 7342, 4671, 7294, 7262,
    4309, 1153, 4568, 7398, 102, 7274, 4298, 7335, 7385, 7349, 1429, 4492,
    7343, 995, 7339, 7391, 4706, 7337, 1171, 4027, 1847, 7312, 1675, 7347,
    1453, 7298, 7307, 171, 4604, 1179, 4727, 7379, 7364, 7297, 379, 7340, 275,
    7357, 7268, 372, 7395, 4468, 1231, 1427, 1805, 7284, 4557, 7369, 7299,
    7285, 401, 7353, 1202, 4296, 4664, 7291, 1269, 7270, 4291, 7317, 1454,
    1530, 7325, 4551, 795, 759, 7288, 4680, 7302, 4762, 7301, 1403, 4097, 7296,
    775, 7393, 7361, 1812, 93, 7377, 173, 392, 1042, 7350, 7355, 7314, 255,
    4157, 1801, 7345, 1800, 4115, 1142, 7327, 7334, 195, 1543, 86, 7372, 7367,
    1817, 7305, 7269, 4072, 7397, 4105, 7332, 7280, 1722, 730, 7289, 7366,
    4266, 7352, 1093, 4765, 771, 1090, 1074, 1099, 1845, 7386, 1768, 7310, 415,
    7263, 7283, 1430, 7279, 7359, 4665, 4285, 4493, 4060, 165, 7333, 7382,
    1670, 7344, 4667, 7331, 4735, 738, 1172, 4214, 1456, 4702, 7390, 291, 4107,
    7387, 4707, 167, 7394, 1574, 1555, 7351, 7321, 191, 1475, 7371, 4662, 316,
    7380, 222, 1669, 4102, 1408, 7273, 1426, 26, 4622, 7328, 7346, 7287, 4599,
    7358, 4518, 1088, 7368, 1695, 177, 4487, 443, 7308, 7318, 7389, 4071, 4282,
    7384, 7396, 7336, 1091, 7330, 1445, 1451, 7320, 7354, 7376, 245, 762, 1554,
    1156, 7277, 4559, 4210, 7388, 1432, 413, 1431, 7329, 4553, 4286, 7295,
    7306, 223, 1819, 1821, 4677, 1767, 234, 7322, 7319, 4670, 1243, 7300, 1703,
    1404, 737, 4716, 7348, 796, 4473, 7383, 4193, 7363, 7266, 7381, 7311, 1349,
    279, 4761, 7360, 7313, 7316, 7272, 7265, 4104, 7373
]

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
labels = np.concatenate((labels, tmp))
balanced = np.take(evaluation, indices, axis=0)
print balanced.shape, evaluation[len(labels):, :].shape
balanced = np.concatenate((balanced, evaluation[len(labels):, :]), axis=0)
labels = np.take(labels, indices)

#plotData(dt,2,4,"normal", oneClass=False)
#print len(labels), len(evaluation)
#print originalDt[0:5]

#--------- outlier distance based
th = 0.58
n_clust = 4
res, kmean = outlierDistanceBased(train, n_clust, th)
for i in range(n_clust):
    print i, len(res[i])

# #to check on a subset
dist = kmean.transform(balanced)
clustersInd = kmean.predict(balanced)
count = 0
predicted = []
for i in range(len(balanced)):
    if dist[i][clustersInd[i]] > th:
        count += 1
        predicted.append(1)
    else:
        predicted.append(0)
print "found " + str(count) + " ouliers over " + str(
    len(balanced)) + " connections "
print str((count / len(balanced)) * 100) + "%"

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

print "len of labels and predicted:"
print len(labels), len(predicted)
labels = labels[0:len(predicted)]

# #random guessing
# for i in range(len(predicted)):
#     predicted[i] = random.randint(0,1)

cm = metrics.confusion_matrix(list(labels), list(predicted), labels=[1, 0])
print cm
tp, fn, fp, tn = cm.ravel()

print tp, fp, fn, tn
print 'accuracy ', (tp + tn) / (tp + tn + fp + fn + 0.0) * 100
print 'precision ', (tp) / (tp + fp + 0.0) * 100
print 'recall ', (tp) / (tp + fn + 0.0) * 100
print 'far ', fp / (fp + tn + 0.0) * 100

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
# log = fileToDic('./logs/raw_complete_evaluation')
# report = heuristics.checkRefAndUserAgentFingerprints(log, {})
# report = heuristics.checkReqFingerprints(log, report)
# report = heuristics.checkStatusCode(log, report)
# print log[0:2]
# hpred = []
# for c in log:
#     k = hashlib.md5(bencode.bencode(c)).hexdigest()
#     if not k in report or (report[k]["aloneAlerts"] == 0
#                            and report[k]["otherAlerts"] <= 1):
#         hpred.append(0)
#     else:
#         hpred.append(1)
# print len(labels), len(hpred)

# labels = labels[0:len(hpred)]
# cm = metrics.confusion_matrix(list(labels), list(hpred), labels=[1, 0])
# print cm
# tp, fn, fp, tn = cm.ravel()

# print tp, fp, fn, tn
# print 'accuracy ', (tp + tn) / (tp + tn + fp + fn + 0.0) * 100
# print 'precision ', (tp) / (tp + fp + 0.0) * 100
# print 'recall ', (tp) / (tp + fn + 0.0) * 100
# print 'far ', fp / (fp + tn + 0.0) * 100

#valuta se scrivere l'alternativa sull'uso delle sessioni