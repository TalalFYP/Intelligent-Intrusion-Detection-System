from tkinter import Button, Tk, Label, Text
from tkinter import messagebox
from tkinter import filedialog

top = Tk()
top.geometry("1366x768")
top.title('Intelligent Intrusion Detection System')

#defination of file Dialog
def UploadAction(event=None):
   filename = filedialog.askopenfilename()
   print('Selected:', filename)


#Header
header =Label(top,text="Intelligent Intrusion Detection System ", width=30,font=("bold",20))
header.place(x=450,y=50)

#file
uplaod_btn = Button(top, bg="gray",fg="white" ,text='Upload \n Data Set',font=("bold",12), command=UploadAction, width=15)
uplaod_btn.place(x = 600,y = 120)

#Classification Button
c_btn = Button(top,bg='gray',fg='white', text = "Train Model",font=("bold",12), width=15)
c_btn.place(x = 600,y = 180)

#label1
label =Label(top,text="Normal Network Flow", width=20,font=("bold",20))
label.place(x=150,y=240)

#Network Flow Result1
c_result= Text(top,width=70, height=12)
c_result.place(x = 50,y = 300)

#label2
label =Label(top,text="Abnormal Network Flow", width=20,font=("bold",20))
label.place(x=880,y=240)

# Network Flow Result2
c_result= Text(top,width=70, height=12)
c_result.place(x = 770,y = 300)


#closing line
top.mainloop()