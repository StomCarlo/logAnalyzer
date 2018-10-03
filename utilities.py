from keras.preprocessing.text import hashing_trick
from sklearn.preprocessing import MinMaxScaler
from sklearn.preprocessing import OneHotEncoder
import pandas
import numpy as np


def text2hash(df):
    for el in df.columns:
        if not isNumeric(df[el]) :
            #print el, df[el][0]
            df[el] = df[el].apply(
                lambda x: hashing_trick(str(x), 200, hash_function='md5', filters='!"#$%&()*+,-./:;<=>?@[\]^`{|}~ '))


def removeNan(df):
    for el in df.columns:
        df[el] = df[el].apply(
                lambda x: -1 if pandas.isnull(x) else x)




def isNumeric(col):
    for el in col:
        if not isinstance(el, int) and not isinstance(el, float) and el is not None:
            return False
    return True


def removeListValues(matrix):
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


def loadDataset(path):
    # load the dataset
    dt = pandas.read_csv(
        path,  #'../NSL-KDD-Dataset-master/KDDdt+.csv'
        engine='python',
        skipfooter=0,
        sep=',')

    enc = OneHotEncoder(handle_unknown='ignore')
    removeNan(dt)

    enc.fit(dt)

    return enc.transform(dt)

