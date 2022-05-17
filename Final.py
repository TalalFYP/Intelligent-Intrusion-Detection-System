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
#%%
top = Tk()
top.geometry("1366x768")
top.title('Intelligent Intrusion Detection System')
xd="2018-05-09-192.168.100.103.pcap"
result=0
normal=[]
abnormal=[]
global X,Y,XT,YT
#defination of file Dialog
def UploadAction(event=None):
   filename = filedialog.askopenfilename()
   #print('Selected:', filename)
   global xd
   xd=filename
   
def FILEX(xd):
    file = open(xd, 'rb')
    sd = pickle.load(file)
    X, Y, XT, YT = sd[0], sd[1], sd[2], sd[3]
    return X,Y,XT,YT
X,Y,XT,YT=FILEX(xd)
def DTModel(X,Y,XT,YT):
    X,Y,XT,YT=FILEX(xd)
    n=[]
    ab=[]
    dtModel = DecisionTreeClassifier()
    dtModel.fit(X, Y)
    sD = dtModel.predict(XT)
    acc = (sum(sD == YT) / len(YT) * 100)
    print("Accuracy of Decision Tree Model: %.2f" % acc+' %')
    print('=' * 100)
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
    X,Y,XT,YT=FILEX(xd)
    n=[]
    ab=[]
    dtModel =KNeighborsClassifier(n_neighbors=11)
    dtModel.fit(X, Y)
    sD = dtModel.predict(XT)
    acc = (sum(sD == YT) / len(YT) * 100)
    print("Accuracy of Decision Tree Model: %.2f" % acc+' %')
    print('=' * 100)
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
    X,Y,XT,YT=FILEX(xd)
    n=[]
    ab=[]
    logModel = LogisticRegression(C=10000)
    logModel.fit(X, Y)
    sD = logModel.predict(XT)
    acc = (sum(sD == YT) / len(YT) * 100)
    print("Accuracy of Logistic Regression Model: %.2f" % acc+' %')
    print('=' * 100)
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
    X,Y,XT,YT=FILEX(xd)
    n=[]
    ab=[]
    svModel = SVC(kernel='rbf')
    svModel.fit(X, Y)
    sD = svModel.predict(XT)
    acc =  (sum(sD == YT) / len(YT) * 100)
    print("Accuracy of SVM Model: %.2f"%acc+' %')
    print('=' * 100)
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
    X,Y,XT,YT=FILEX(xd)
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
        X,Y,XT,YT=FILEX(xd)
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
    loadModel("ANN")

    
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
c5_btn = Button(top,bg='gray',fg='white', text = "Train ANN",font=("bold",12), width=15,command=modelSVM)
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




        



