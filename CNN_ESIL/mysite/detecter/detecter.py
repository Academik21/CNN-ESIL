#!/usr/bin/python3
import r2pipe
import sys
import re
import csv
import os
import argparse
from progress.bar import Bar, ChargingBar
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3' 
import time
from tensorflow.keras import utils
from tensorflow.keras.preprocessing.sequence import pad_sequences
from tensorflow.keras.preprocessing.text import Tokenizer
# from tensorflow.keras.callbacks import ModelCheckpoint
from tensorflow.keras import utils
from tensorflow.keras.models import load_model
#import pandas as pd
import numpy as np
# import matplotlib.pyplot as plt
import pickle

num_words=20000


def parse():
    parser = argparse.ArgumentParser()
    parser.add_argument('-f','--file', help = 'Путь к сканируемому файлу', action='store')
    parser.add_argument('-d','--dir', help = 'Путь к сканируемой директории', action='store')
    parser.add_argument('-o','--out', help = 'Путь к файлу для сохранения отчета', action='store')
    return parser


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


from tensorflow.keras import backend as K

def recall_m(y_true, y_pred):
    true_positives = K.sum(K.round(K.clip(y_true * y_pred, 0, 1)))
    possible_positives = K.sum(K.round(K.clip(y_true, 0, 1)))
    recall = true_positives / (possible_positives + K.epsilon())
    return recall

def precision_m(y_true, y_pred):
    true_positives = K.sum(K.round(K.clip(y_true * y_pred, 0, 1)))
    predicted_positives = K.sum(K.round(K.clip(y_pred, 0, 1)))
    precision = true_positives / (predicted_positives + K.epsilon())
    return precision

def f1_m(y_true, y_pred):
    precision = precision_m(y_true, y_pred)
    recall = recall_m(y_true, y_pred)
    return 2*((precision*recall)/(precision+recall+K.epsilon()))


def get_functions_list(N,r):
    function_dict={}
    function_mass={}
    function_adresses=[]
    # print(len(N))
    i=0
    while (i<len(N)):
        # temp=r.cmdj('aflj')[i]
        temp=N[i]
        function_mass.update({temp['offset']:i})
        function_dict.update({temp['offset']:temp['name']})
        function_adresses.append(temp['offset'])
        i+=1
    # print(function_dict)
    # print(function_mass)
    # print(function_adresses)
    return (function_adresses)

def check_jump(esil):
    jz = je = r'^zf,\?{,[0-9]+,rip,=,}$'
    jnz = jne = r'^zf,!,\?{,[0-9]+,rip,=,}$'
    jae = jnc =r'^cf,!,\?{,[0-9]+,rip,=,}$'
    jb = jnae = jc =r'^cf,\?{,[0-9]+,rip,=,}$'
    jl = jnge =r'^of,sf,\^,\?{,[0-9],rip,=,}$'
    jle = jng = r'^of,sf,\^,zf,\|,\?{,[0-9]+,rip,=,}$'
    jg = jnle = r'^sf,of,!,\^,zf,\!,\&,\?{,[0-9]+,rip,=,}$'
    jge = jnl = r'^of,\!,sf,\^,\?{,[0-9]+,rip,=,}$'
    jp= r'^pf,\?{,[0-9]+,rip,=,}$'
    jnp= r'^pf,!,\?{,[0-9]+,rip,=,}$'
    js= r'^sf,\?{,[0-9]+,rip,=,}$'
    jns= r'^sf,!,\?{,[0-9]+,rip,=,}$'
    jo= r'^of,\?{,[0-9]+,rip,=,}$'
    jno= r'^of,!,\?{,[0-9]+,rip,=,}$'
    ja= jnbe=r'^cf,zf,\|,!,\?{,[0-9]+,rip,=,}$'
    jna = jbe =r'^zf,cf,\|,\?{,[0-9]+,rip,=,}$'
    jmp = r'^0x[0-9a-fA-F]+,rip,=$'
    call = r'^[0-9]+,rip,8,rsp,-=,rsp,=\[\],rip,=$'
    patterns = dict()
    patterns['jz']=jz
    patterns['jnz']=jnz
    patterns['jae']=jae
    patterns['jb']=jb
    patterns['jl']=jl
    patterns['jle']=jle
    patterns['jg']=jg
    patterns['jge']=jge
    patterns['jp']=jp
    patterns['jnp']=jnp
    patterns['js']=js
    patterns['jns']=jns
    patterns['jo']=jo
    patterns['jno']=jno
    patterns['ja']=ja
    patterns['jna']=jna
    patterns['jmp']=jmp
    patterns['call']=call
    for k,v in patterns.items():
        match = re.fullmatch(v, esil)
        if match:
            #print(k, esil)
            esil = k
    return (esil)

def get_esil(bin):
    r = r2pipe.open(bin, flags=['-2'])
    r.cmd('aaa')
    r.cmd('e asm.emu=true')
    N=r.cmdj('aflj')
    s=''
    s2=''
    function_adresses = get_functions_list(N,r)
    time1 = time.time()
    for i in range(len(N)):
        r.cmd('s '+str(function_adresses[i]))
        instructions=r.cmdj('pdfj')
        # s+='\n-----------------'+str(i)+'-------------------\n'
        for j in instructions['ops']:
            try:
                esil = j['esil']
                print(esil) # ---------------
                esil = check_jump(esil)
                if esil =='':
                    esil='syscall'
                asm = j['opcode']  
                s += esil+' '
                s2 += asm+' '
            except:
                pass
        time2 = time.time()
        if time2-time1>60:
            #print('------------TIME---------------')
            time1=time2
            continue
    #print(s)
    #count = s.split(' ')
    #print(len(count))
    return (s)

def warning():
    print('\n'+bcolors.FAIL+'#####################################################')
    print('###                 Файл упакован                 ###')
    print('#####################################################'+bcolors.ENDC)

def ok():
    print(bcolors.OKGREEN+'###################################################')
    print('###               Файл не упакован              ###')
    print('###################################################'+bcolors.ENDC)

def is_exec(file):
    with open(file,'rb') as f:
        sig = f.read(2)
        #print(sig)
    if sig == b'MZ' or sig == b'\x7fE':
        return 1

    else: return 0

def load_network():
    print('[*] Загрузка нейронной сети...')
    with open('5tokenizer.pickle', 'rb') as f:
        tokenizer = pickle.load(f)
    model = load_model('5model.hdf5', compile=False)
    print('[+] Нейронная сеть загружена')
    return model, tokenizer

parser = parse()
args = parser.parse_args()
if args.file:
    model, tokenizer = load_network()
    bin = args.file             # sys.argv[1]
    # print(bin, type(bin))
    s= get_esil(bin)
    print('[*] Определены инструкции')

    sequences = tokenizer.texts_to_sequences([s])
    data = pad_sequences(sequences, maxlen=20000)

    result = model.predict(data)
    print(result, type(result))
    if result>=0.5:
        warning()
    else:
        ok()

elif args.dir:
    model, tokenizer = load_network()
    folder=[]
    for i in os.walk(args.dir):
        folder.append(i)

    exec_files=[]

    for address,dirs,files in folder:
        for file in files:
            path_to_file = address+'/'+file
            # print(path_to_file)
            if is_exec(path_to_file):
                exec_files.append(path_to_file)

    # print(exec_files)
    count = str(len(exec_files))
    print('[+] Определены исполняемые файлы')
    print('[*] Исполняемых файлов: ' + count)
    bar = Bar('Сканирование',max = len(exec_files))
    packed_files=[]
    for i in range(len(exec_files)):
        # print('\n'+exec_files[i]+'\n')
        try:
            s= get_esil(exec_files[i])
        except:
            #pass
            print(exec_files[i])
        # print('[*] Определены инструкции ' + exec_files[i])
        sequences = tokenizer.texts_to_sequences([s])
        data = pad_sequences(sequences, maxlen=20000)

        result = model.predict(data)
        print(result, type(result))
        if result>=0.5:
            warning()
            packed_files.append(exec_files[i])
            print(bcolors.WARNING + '[!] ' + exec_files[i] + bcolors.ENDC)
        else:
            #ok()
            pass
        
        bar.next()
    bar.finish()

    if args.out:
        with open(args.out,'w') as f:
            for i in packed_files:
                f.write(i+'\n')

        print('[+] Отчет сохранен в файл '+ args.out)

else:
    parser.print_help()
