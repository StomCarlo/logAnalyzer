from keras.preprocessing.text import hashing_trick
from sklearn.preprocessing import MinMaxScaler
from sklearn.preprocessing import OneHotEncoder
import pandas
import numpy as np


def text2hash(df): #hash all the colums which contains string values in a dataframe
    for el in df.columns:
        if not isNumeric(df[el]) :
            #print el, df[el][0]
            df[el] = df[el].apply(
                lambda x: hashing_trick(str(x), 200, hash_function='md5', filters='!"#$%&()*+,-./:;<=>?@[\]^`{|}~ '))


def removeNan(df): #removes nan from a df and puts -1 
    for el in df.columns:
        df[el] = df[el].apply(
                lambda x: -1 if pandas.isnull(x) else x)




def isNumeric(col): #check if a column contains only numeric values
    for el in col:
        if not isinstance(el, int) and not isinstance(el, float) and el is not None:
            return False
    return True


def removeListValues(matrix): #remove nested lists from matrix
    i = 0
    for row in matrix[:, :]:
        j = 0
        for el in row:
            if isinstance(el, list):
                if len(el) > 0:
                    matrix[i][j] = float(el[0])
                else:
                    matrix[i][j] = -1
            j += 1
        i += 1
    return matrix


def loadDataset_oneHotEncoder(path, separetor=','): #loads a dataset (CSV) applying one hot encoding to remove strings
    # load the dataset
    dt = pandas.read_csv(
        path,  #'../NSL-KDD-Dataset-master/KDDdt+.csv'
        engine='python',
        skipfooter=0,
        sep=separetor)

    enc = OneHotEncoder(handle_unknown='ignore')
    removeNan(dt)

    enc.fit(dt)
    dt = enc.transform(dt)
    return dt

#DON'T USE THIS TO LOAD TWO DATASETS SEPARATELY BECAUSE THERE WILL BE DIFFERENCES IN THE SCALING, USE THE NEXT FUNCTION INSTEAD
def loadDataset_hash(path, separetor = ','):  #loads a dataset(csv) applyng hash to remove strings and minmax scaling
    dt = pandas.read_csv(
        path,  #'../NSL-KDD-Dataset-master/KDDdt+.csv'
        engine='python',
        skipfooter=0,
        sep=separetor)
    removeNan(dt)
    text2hash(dt)
    dt = dt.values
    dt = removeListValues(dt)
    # normalize the dataset
    scaler = MinMaxScaler(feature_range=(0, 1))
    dt = scaler.fit_transform(dt[:,:])
    return dt


def loadDatasets_hash(path1, path2, separetor=','): #loads to dataset applying hash and scaling. Use this if you need to work on two datasets
    dt1 = pandas.read_csv(
        path1,  #'../NSL-KDD-Dataset-master/KDDdt+.csv'
        engine='python',
        skipfooter=0,
        sep=separetor)
    
    limit = dt1.shape[0]
    dt2 = pandas.read_csv(
        path2,  #'../NSL-KDD-Dataset-master/KDDdt+.csv'
        engine='python',
        skipfooter=0,
        sep=separetor)
    dt = pandas.concat([dt1,dt2], ignore_index = True)
    print dt.shape
    removeNan(dt)
    text2hash(dt)
    dt = dt.values
    dt = removeListValues(dt)
    # normalize the dataset
    scaler = MinMaxScaler(feature_range=(0, 1))
    dt = scaler.fit_transform(dt[:,:])
    return dt[0:limit, :], dt[limit:,:]


def loadDataset(path, separetor=','): #loads a dataset(csv) keeping the string values as thay are
    dt = pandas.read_csv(
        path,  #'../NSL-KDD-Dataset-master/KDDdt+.csv'
        engine='python',
        skipfooter=0,
        sep=separetor)
    removeNan(dt)
    dt = dt.values
    dt = removeListValues(dt)
    return dt

def matchColums(d1,d2): #check if d2 has the same columns of d1 (d2 is the smaller), and return d2 with the same columns of d1
    c1 = d1.columns
    c2 = d2.columns
    missing = []
    for el in c1:
        if el not in c2:
            missing.append(el)
    for c in missing:
        d2[c] = np.array([None] * d2.shape[0]) #add the empty column

    d2 = d2[c1]
    return d2