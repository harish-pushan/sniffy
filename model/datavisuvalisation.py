import pandas as pd 
import numpy as np
import matplotlib.pyplot as plt
from time import sleep

df = pd.read_csv('dataset0.csv')

for col_name ,items in df.items():
    plt.hist(df[df['Label']==1][col_name], color='green',label= 'attack',alpha=0.7,density=True)
    plt.hist(df[df['Label']==0][col_name], color='red',label= 'normal',alpha=0.7,density=True)
    plt.title(col_name)
    plt.ylabel("Probility")
    plt.xlabel(col_name)
    plt.legend()
    plt.show()
    sleep(30)
    pass
