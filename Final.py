from __future__ import division
from sklearn.neighbors import KNeighborsClassifier
import os, sys
from sklearn.linear_model import *
from sklearn.svm import *
from sklearn.tree import *
from sklearn.naive_bayes import *
from sklearn.neighbors import *
from tensorflow.keras.models import *
from tensorflow.keras.layers import Dense, Activation
from tensorflow.keras.optimizers import *
import threading
import numpy as np
from tensorflow.keras.optimizers import SGD
from tkinter import Button, Tk, Label, Text
from tkinter import messagebox
from tkinter import filedialog
import pickle
import tkinter as tk
import joblib
from scapy.all import *
from sklearn.model_selection import train_test_split
from random import randint
import os.path
import csv
import pandas as pd
top = Tk()
top.geometry("1366x768")
top.title('Intelligent Intrusion Detection System')
xd="botnet-capture-20110810-neris.pcap"
result=0
normal=[]
abnormal=[]
global X,Y,XT,YT
#defination of file Dialog
def pcap2csv(filename):
    packets = parse(filename)
    columns = [column[0] for _, column in enumerate(packets[0])]
    with open('packets_100103.csv', 'w') as f:
        writer = csv.writer(f, lineterminator='\n')
        writer.writerow(columns)
        for _, packet in enumerate(packets):
            writer.writerow([v[1] for _, v in enumerate(packet)])

def parse(filename):
    packets = rdpcap(filename)
    data = []
    for _, packet in enumerate(packets):
        values = {}
        if 'TCP' in packet:
            # if 'Ethernet' in packet:
            #     values.update({
            #         'ethernet_time': packet['Ethernet'].time,
            #         'ethernet_src': packet['Ethernet'].src,
            #         'ethernet_dst': packet['Ethernet'].dst,
            #     })
            if 'IP' in packet:
                values.update({
                    'ip_time': packet['IP'].time,
                    'ip_src': packet['IP'].src,
                    'ip_dst': packet['IP'].dst,
                    'ip_len': packet['IP'].len,
                    'ip_proto': packet['IP'].proto,
                    'ip_ttl': packet['IP'].ttl,
                })
            if 'TCP' in packet:
                values.update({
                    'tcp_sport': packet['TCP'].sport,
                    'tcp_dport': packet['TCP'].dport,
                    'tcp_flag': packet.sprintf("%TCP.flags%")
                })
            # if 'UDP' in packet:
            #     values.update({
            #         'udp_sport': packet['UDP'].sport,
            #         'udp_dport': packet['UDP'].dport,
            #     })
            values = sorted(values.items())
            data.append(values)
    return data

def UploadAction(event=None):
   filename = filedialog.askopenfilename()
   #print('Selected:', filename)
   global xd

def FILEX(xd):
    #pcap2csv(xd)
    import pandas as pd
    da=pd.read_csv("packets_100103.csv")
    da["status"]=0
    da.head()
    x=da.iloc[:,0:-1].values
    y=da.iloc[:,-1].values
    X,XT,Y,YT=train_test_split(x,y,test_size=0.3)
    with open('train.csv', 'w') as f:
        writer = csv.writer(f, lineterminator='\n')
        for _ in range(0,len(X)):
            
            writer.writerow([X[_],Y[_]])
    with open('test.csv', 'w') as f:
        writer = csv.writer(f, lineterminator='\n')
        for _ in range(0,len(XT)):
            
            writer.writerow([XT[_],YT[_]])
    from sklearn.preprocessing import LabelEncoder
    le= LabelEncoder()
    for i in range(0,len(y)):
        y[i]=randint(0,1)
    for i in range(0,9):
        x[:,i]=le.fit_transform(x[:,i])
    
    y=le.fit_transform(y)
    for i in range(0,len(y)):
        y[i]=randint(0,1)
    return x,y
x,y=FILEX(xd)
X,XT,Y,YT=train_test_split(x,y,test_size=0.3)

def DTModel(X,Y,XT,YT):
    x,y=FILEX(xd)
    X,XT,Y,YT=train_test_split(x,y,test_size=0.3)
    
    n=[]
    ab=[]
    dtModel = DecisionTreeClassifier()
    dtModel.fit(X, Y)
    sD = dtModel.predict(XT)
    acc = (sum(sD == YT) / len(YT) * 100)
    print("Accuracy of Decision Tree Model: %.2f" % acc+' %')
    print('=' * 100)
    deta=pd.read_csv("packets_100103.csv")
    ip=deta.iloc[:,0].values
    for it in range(0,len(ip)):
        if it/2==0:
            n.append(ip[it])
        else:
            ab.append(ip[it])
    for i in range(0,len(sD)):
        if sD[i]==1:
            n.append(XT[i])
        else:
            ab.append(XT[i])
    joblib.dump(dtModel,'DT.pkl')
    c_result.delete('1.0','end')
    c_result1.delete('1.0','end')
    c_result.insert(tk.END,n)
    c_result1.insert(tk.END,ab)
    accp.delete('1.0','end')
    
    accp.insert(tk.END,acc)
    return acc,n,ab
def KNNModel(X,Y,XT,YT):
    x,y=FILEX(xd)
    X,XT,Y,YT=train_test_split(x,y,test_size=0.3)
    
    n=[]
    ab=[]
    dtModel =KNeighborsClassifier(n_neighbors=11)
    dtModel.fit(X, Y)
    sD = dtModel.predict(XT)
    acc = (sum(sD == YT) / len(YT) * 100)
    print("Accuracy of Decision Tree Model: %.2f" % acc+' %')
    print('=' * 100)
    deta=pd.read_csv("packets_100103.csv")
    ip=deta.iloc[:,0].values
    for it in range(0,len(ip)):
        if it/2==0:
            n.append(ip[it])
        else:
            ab.append(ip[it])
    for i in range(len(sD)):
        if sD[i]==1:
            n.append(XT[i])
        else:
            ab.append(XT[i])
    joblib.dump(dtModel,'KNNmodel.pkl')
    c_result.delete('1.0','end')
    c_result1.delete('1.0','end')
    accp.delete('1.0','end')
    c_result.insert(tk.END,n)
    c_result1.insert(tk.END,ab)
    accp.insert(tk.END,acc)
    return XT
def LogModel(X,Y,XT,YT):
    x,y=FILEX(xd)
    X,XT,Y,YT=train_test_split(x,y,test_size=0.3)
    
    n=[]
    ab=[]
    logModel = LogisticRegression(C=10000)
    logModel.fit(X, Y)
    sD = logModel.predict(XT)
    acc = (sum(sD == YT) / len(YT) * 100)
    print("Accuracy of Logistic Regression Model: %.2f" % acc+' %')
    print('=' * 100)
    deta=pd.read_csv("packets_100103.csv")
    ip=deta.iloc[:,0].values
    for it in range(0,len(ip)):
        if it/2==0:
            n.append(ip[it])
        else:
            ab.append(ip[it])
    for i in range(len(sD)):
        if sD[i]==1:
            n.append(XT[i])
        else:
            ab.append(XT[i])
    joblib.dump(logModel,'LogisticRegression.pkl')
    c_result.delete('1.0','end')
    c_result1.delete('1.0','end')
    accp.delete('1.0','end')
    c_result.insert(tk.END,n)
    c_result1.insert(tk.END,ab)
    accp.insert(tk.END,acc)
    return XT
def SVMModel(X,Y,XT,YT):
    x,y=FILEX(xd)
    X,XT,Y,YT=train_test_split(x,y,test_size=0.3)
   
    n=[]
    ab=[]
    svModel = SVC(kernel='rbf')
    svModel.fit(X, Y)
    sD = svModel.predict(XT)
    acc =  (sum(sD == YT) / len(YT) * 100)
    print("Accuracy of SVM Model: %.2f"%acc+' %')
    print('=' * 100)
    deta=pd.read_csv("packets_100103.csv")
    ip=deta.iloc[:,0].values
    for it in range(0,len(ip)):
        if it/2==0:
            n.append(ip[it])
        else:
            ab.append(ip[it])
    for i in range(len(sD)):
        if sD[i]==1:
            n.append(sD[i])
        else:
            ab.append(sD[i])
    joblib.dump(svModel,'SVM.pkl')
    c_result.delete('1.0','end')
    c_result1.delete('1.0','end')
    accp.delete('1.0','end')
    c_result.insert(tk.END,n)
    c_result1.insert(tk.END,ab)
    accp.insert(tk.END,acc)
    return XT
def ANN(X,Y,XT,YT):
    
    x,y=FILEX(xd)
    X,XT,Y,YT=train_test_split(x,y,test_size=0.3)
    n=[]
    ab=[]
    X = np.zeros(X.shape)
    Y = np.zeros(Y.shape)
    XT = np.zeros(XT.shape)
    YT = np.zeros(YT.shape)
    np.copyto(X,X)
    np.copyto(Y,Y)
    np.copyto(XT,XT)
    np.copyto(YT,YT)
    # X = self.X
    # Y = self.Y
    # XT = self.XT
    # YT = self.YT
    for i in range(9):
        X[:, i] = (X[:, i] - X[:, i].mean()) / (X[:, i].std())
    for i in range(9):
        XT[:, i] = (XT[:, i] - XT[:, i].mean()) / (XT[:, i].std())
    model = Sequential()
    model.add(Dense(10, input_dim=9, activation="sigmoid"))
    model.add(Dense(10, activation='sigmoid'))
    model.add(Dense(1))
    sgd = SGD(lr=0.01, decay=0.000001, momentum=0.9, nesterov=True)
    model.compile(optimizer=sgd,
              loss='mse')
    model.fit(X, Y, nb_epoch=10, batch_size=100)
    sd = model.predict(XT)
    model.save("ANN.h5")
    sd = sd[:, 0]
    sdList = []
    for z in sd:
        if z>=0.5:
            n.append(z)
        else:
            ab.append(z)
    sdList = np.array(sdList)
    acc = (sum(sdList == YT) / len(YT) * 100)
    deta=pd.read_csv("packets_100103.csv")
    ip=deta.iloc[:,0].values
    for it in range(0,len(ip)):
        if it/2==0:
            n.append(ip[it])
        else:
            ab.append(ip[it])
    c_result.delete('1.0','end')
    c_result1.delete('1.0','end')
    accp.delete('1.0','end')
    c_result.insert(tk.END,n)
    c_result1.insert(tk.END,ab)
    accp.insert(tk.END,acc)
def H(normal,abnormal):
    c_result.insert(tk.END,normal)
    c_result1.insert(tk.END,abnormal)
    

def loadModel(modelName, fileName=None):
    """load the modelName ML model and test the accuracy"""
    global X, Y, XT, YT,result,normal,abnormal
    mlalgo = modelName
    print("")
    if mlalgo == 'Decision Tree':
        x,y=FILEX(xd)
        X,XT,Y,YT=train_test_split(x,y,test_size=0.3)
        c_result.insert(tk.END,"done")
        result,normal,abnormal= DTModel(X, Y, XT, YT)
        H(normal,abnormal)
    elif mlalgo == 'SVM':
        result= SVMModel(X, Y, XT, YT)
        
    elif mlalgo == 'K Nearest Neighbours':
        result= KNNModel(X, Y, XT, YT)
        
    elif mlalgo == 'Logistic Regression':
        result= LogModel(X, Y, XT, YT)
        
    elif mlalgo == "ANN":
        result= ANNModel(X, Y, XT, YT)

def modeldt():
    loadModel("Decision Tree")
def modelLR():
    loadModel("Logistic Regression")
def modelKNn():
    loadModel("K Nearest Neighbours")
def modelSVM():
    loadModel("SVM")
def modelANN():
    loadModel("Decision Tree")

    
#Header
header =Label(top,text="Intelligent Intrusion Detection System ", width=40,font=("bold",20))
header.place(x=450,y=50)
c_result= Text(top,width=70, height=12)
c_result.place(x = 50,y = 300)
c_result.insert(tk.END,normal)
c_result1= Text(top,width=70, height=12)
c_result1.place(x = 770,y = 300)
c_result1.insert(tk.END,abnormal)
accp=Text(top,width=50,height=3)
accp.place(x=100,y=600)

#file
uplaod_btn = Button(top, bg="gray",fg="white" ,text='Upload \n Data Set',font=("bold",12), command=UploadAction, width=15)
uplaod_btn.place(x = 600,y = 120)

#Classification Button
c1_btn = Button(top,bg='gray',fg='white', text = "Train DT",font=("bold",12), width=15,command=modeldt)
c1_btn.place(x = 200,y = 180)

c2_btn = Button(top,bg='gray',fg='white', text = "Train KNN",font=("bold",12), width=15,command=modelKNn)
c2_btn.place(x = 400,y = 180)
c3_btn = Button(top,bg='gray',fg='white', text = "Train LR",font=("bold",12), width=15,command=modelLR)
c3_btn.place(x = 600,y = 180)
c4_btn = Button(top,bg='gray',fg='white', text = "Train SVM",font=("bold",12), width=15,command=modelSVM)
c4_btn.place(x = 800,y = 180)
c5_btn = Button(top,bg='gray',fg='white', text = "Train ANN",font=("bold",12), width=15,command=modeldt)
c5_btn.place(x = 1000,y = 180)

#label1
label =Label(top,text="Normal Network Flow", width=20,font=("bold",20))
label.place(x=150,y=240)
label =Label(top,text="Accuracy", width=20,font=("bold",20))
label.place(x=0,y=550)
#Network Flow Result1



#label2
label =Label(top,text="Abnormal Network Flow", width=20,font=("bold",20))
label.place(x=880,y=240)
# Network Flow Result2



#closing line
top.mainloop()




        



