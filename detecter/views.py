from django.shortcuts import render
from django.http import HttpResponse
from django.conf import settings
from django.core.files.storage import FileSystemStorage
import pickle
import numpy as np
import time
import os
import re
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3' 
from tensorflow.keras.preprocessing.sequence import pad_sequences
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.python.keras.engine.sequential import Sequential
from tensorflow.keras import utils
from tensorflow.keras.models import load_model
# Подключение новой формы для регистрации
from .forms import RegistrForm
import r2pipe

# Create your views here.
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
    time.sleep(0.1)
    s = str()
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
                #print(esil) # ---------------
                esil = check_jump(esil)
                if esil == '':
                    esil='syscall'
                # asm = j['opcode']  
                s += esil+' '
                # s2 += asm+' '
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
    time.sleep(0.1)
    return (s)

model = Sequential()
tokenizer = Tokenizer()
def load_network():
    print('[*] Загрузка нейронной сети...')
    with open('/home/dimas/Downloads/mysite/detecter/5tokenizer.pickle', 'rb') as f:
        tokenizer = pickle.load(f)
    model = load_model('/home/dimas/Downloads/mysite/detecter/5model.hdf5', compile=False)
    # print(type(model), type(tokenizer))
    print('[+] Нейронная сеть загружена')
    return model, tokenizer


def index(request):
    global model
    global tokenizer
    model, tokenizer = load_network()
    return render(request, 'detecter/first.html')
    

def simple_upload(request):
    if request.method == 'POST' and request.FILES['myfile']:
            myfile = request.FILES['myfile']
            fs = FileSystemStorage('tmp')
            filename = fs.save(myfile.name, myfile)
            uploaded_file_url = fs.url(filename)
            return render(request, 'detecter/detect.html', {
                'uploaded_file_url': uploaded_file_url
            })

    return render(request, 'detecter/detect.html')


def main(request):

    if request.method == 'GET':
        pass


    if request.method == 'POST' and request.FILES['myfile']:
            myfile = request.FILES['myfile']
            fs = FileSystemStorage('tmp')
            filename = fs.save(myfile.name, myfile)
            uploaded_file_url = fs.url(filename)
            bin = '/home/dimas/Downloads/mysite/tmp' + uploaded_file_url            
            print(bin, type(bin))
            s = get_esil(bin)
            print(s, type(s))
            print('[*] Определены инструкции')
            
            sequences = tokenizer.texts_to_sequences([s])
            data = pad_sequences(sequences, maxlen=20000)
            result = model.predict(data)
            print(result, type(result))
            # print(result)
            if result>=0.5:
                status = 'packed'
            else:
                status = 'normal'

            with open('hisrory.txt', 'a') as f:
                for_write = uploaded_file_url + ':' + status
                f.write(for_write)

            return render(request, 'detecter/scan.html', {
                'uploaded_file_url': uploaded_file_url,
                'status': status
            })

    return render(request, 'detecter/main.html')

def scan(request):
    return render(request, 'detecter/scan.html')


def history(request):
    hist = dict()
    try:
        with open('history.txt', 'r') as f:
            for line in f.readlines():
                a, b = line.split(':')
                hist[a] = b
            
    except:
        pass

    context = {'files': hist}
    return render(request, 'detecter/history.html', context=context)
 

# Функция регистрации
def registr(request):
    # Массив для передачи данных шаблонны
    data = {}
    # Проверка что есть запрос POST
    if request.method == 'POST':
        # Создаём форму
        form = RegistrForm(request.POST)
        # Валидация данных из формы
        if form.is_valid():
            # Сохраняем пользователя
            form.save()
            # Передача формы к рендару
            data['form'] = form
            # Передача надписи, если прошло всё успешно
            data['res'] = "Всё прошло успешно"
            # Рендаринг страницы
            # save to database
            return render(request, 'detecter/main.html', data)
        else:
            print(form.errors)
            # Создаём форму
            form = RegistrForm()
            # Передаём форму для рендеринга
            data['form'] = form
            return render(request, 'detecter/registr.html', data)

    else: # Иначе
        # Создаём форму
        form = RegistrForm()
        # Передаём форму для рендеринга
        data['form'] = form
        # Рендаринг страницы
        return render(request, 'detecter/registr.html', data)

def auth(request):
    pass
