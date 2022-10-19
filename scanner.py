from os.path import isfile , basename , abspath , isdir , getsize , expanduser
from socket import socket , AF_INET , SOCK_STREAM , gethostbyname , gaierror
from os import getlogin , walk , getenv , remove , getcwd , system
from random import choice , _urandom
from platform import system as iden
from subprocess import Popen , PIPE
from hashlib import sha256
from colorama import Fore
from shutil import copy
from time import sleep
from gtts import gTTS
import requests
w = Fore.WHITE
r = Fore.RED
g = Fore.GREEN
b = Fore.BLUE
c = Fore.CYAN
colors = [w ,r, g, b , c]
voice = int(open("voice.txt" , 'r').readlines()[0])
if iden() == 'Windows':
  paths_tool = [getenv("AppData") + '//scan_files' , getenv("AppData") + '//scan_files_ext' , getenv("AppData") + '//maps_files']
elif iden() == 'Linux':
  if not Popen('uname -o',shell=True,stdout=PIPE).communicate()[0].decode() == 'Android':
   paths_tool = ['/home/.scan_files.txt', '/home/.scan_files_ext.txt' , '/home/.maps_files.txt']
  else:
   paths_tool = ['/sdcard/.scan_files.txt', '/sdcard/.scan_files_ext.txt' , '/sdcard/.maps_files.txt']
def start_up():
    name = basename(__file__).split('.')[0]
    pathN = getcwd() + f'//{name}'
    if iden() == 'Windows':
        name += '.exe'
        pathN += '.exe'
        if not isfile(f'C:\\\\Users\\\\{getlogin()}\\\\AppData\\\\Roaming\\\\Microsoft\\\\Windows\\\\Start Menu\\\\Programs\\\\Startup\\\\{name}'):copy(pathN,f'C:\\\\Users\\\\{getlogin()}\\\\AppData\\\\Roaming\\\\Microsoft\\\\Windows\\\\Start Menu\\\\Programs\\\\Startup')
    elif iden() == 'Linux':
        name += '.py'
        pathN += '.py'
        if not isfile(expanduser("~") + '//.startup.txt'):
          with open(expanduser('~') + '//.bashrc' , 'a')as f:
            f.write(f"python3 {pathN}")
          copy("voice.txt" , expanduser('~'))
          with open(expanduser("~") + '//.startup.txt' , 'w')as f:f.write("Done")
def SpeakDone(num):
    language = "ar"
    myobj = gTTS(text=num, lang=language, slow=False)
    myobj.save("welcome.mp3")
    if iden() == 'Windows':
       system("start welcome.mp3")
       sleep(5)
    #else:system("nvlc welcome.mp3")
    remove("welcome.mp3")
def results():
    if isfile("results_scan.txt") and getsize("results_scan.txt") != 0:
        if not voice == 1:SpeakDone("مرحبا لقد تم الانتهاء من الفحص ويوجد بعض البرامج الضاره يرجي الاطلاع علي ملف النتائج لحذفهم")
        else:print (f'{w}[{b}-{w}] Scanner Are Finished There Are Some Malicious Please See results File To Delete Them')
    else:
        if not voice == 1:SpeakDone("مرحبا لقد تم الانتهاء من الفحص ولا يوجد اي برامج ضاره")
        else:print (f'{w}[{b}+{w}] Scanner Are Finished And There Aren\'t Malicious :)')
def banner_0():
    print (f"""{choice(colors)}
                                                
                         _____                                 
                        / ____|                                
                        | (___   ___ __ _ _ __  _ __   ___ _ __ 
                        \___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
                        ____) | (_| (_| | | | | | | |  __/ |   
                        |_____/ \___\__,_|_| |_|_| |_|\___|_|V1.0   
                                                                                                        
                                Developed By : Ali Mansour                                  
""")
def upload_pe(malware_path):
 if not isfile(malware_path):exit(f"{w}[{r}!{w}] Path Invalid")
 global file_id , VT_API_KEY , VT_API_URL , VT_ANA_URL , headers
 VT_API_KEY = "42ab3ee70a7f596b586155e4a9653ef4e103485ce0f0da4cb9cf2bfe029ef891"
 VT_API_URL = "https://www.virustotal.com/api/v3/files"
 VT_ANA_URL = "https://www.virustotal.com/api/v3/analyses/"
 headers = {
            "x-apikey" : VT_API_KEY,
            "User-Agent" : "vtscan v.1.0",
            "Accept-Encoding" : "gzip, deflate",
           }
 files = {"file" : (
            basename(malware_path),
            open(abspath(malware_path), "rb"))
         }
 res = requests.post(VT_API_URL, headers = headers, files = files)
 if res.status_code == 200:
     result = res.json()
     file_id = result.get("data").get("id")
     print (f"{w}[{b}+{w}] Id Program : {file_id}")
     print (f"{w}[{b}+{w}] Successfully Upload File : " + malware_path.split('\\')[-1])
     analyze(malware_path)
 else:
     print (f"{w}[{r}-{w}] Failed To Upload File : " + malware_path.split('\\')[-1])
     print (f"{w}[{r}!{w}] Status Code: {str(res.status_code)}")
def GetNamePart(kwargs):
    if iden() == 'Windows':
        if kwargs == 'All':
            path_d = [f'C:\\Users\\{getlogin()}\\Desktop' , getenv('AppData') , "C:\\Windows\\temp"]
        else:
            path_d = [f'C:\\Users\\{getlogin()}\\Desktop' , getenv('AppData')]
            for i in range(65,91):
                if isdir(f'{chr(i)}:\\') and chr(i) != 'C':
                    path_ = chr(i) + ':\\\\'
                    path_d.append(path_)
    elif iden() == 'Linux':
        if not Popen('uname -o',shell=True,stdout=PIPE).communicate()[0].decode() == 'Android':
           path_d = ['/home']
        else:
           path_d = ['/sdcard']
    return path_d
def analyze(malware_path):
 b = Fore.BLUE
 global fx
 analysis_url = VT_ANA_URL + file_id
 res = requests.get(analysis_url, headers = headers)
 if res.status_code == 200:
  result = res.json()
  status = result.get("data").get("attributes").get("status")
  if status == "completed":
   stats = result.get("data").get("attributes").get("stats")
   results = result.get("data").get("attributes").get("results")
   print (f'{w}[{r}-{w}] Malicious: {str(stats.get("malicious"))}')
   print (f'{w}[{r}!{w}] Undetected : {str(stats.get("undetected"))}')
   for k in results:
    if results[k].get("category") == "malicious":
     print (results[k].get("engine_name"))
     print (f'{w}[{r}-{w}] version : {results[k].get("engine_version")}')
     print (f'{w}[{r}-{w}] category : {results[k].get("category")}')
     print (f'{w}[{r}-{w}] result : {results[k].get("result")}')
     print (f'{w}[{r}-{w}] method : {results[k].get("method")}')
     print (f'{w}[{r}-{w}] update : {results[k].get("engine_update")}')
     with open("results_scan.txt" , 'a')as fx:
      fx.write(f'''
      {malware_path}
      {results[k].get("engine_name")}
      "version : " {results[k].get("engine_version")}
      "category : " {results[k].get("category")}
      "result : "  {results[k].get("result")}
      "method : "  {results[k].get("method")}
      "update : " {results[k].get("engine_update")}
      ''')
   print (f"{w}[{b}+{w}] Successfully Analyse : " + malware_path.split('\\')[-1])
 elif status == "queued":
  print (f"{w}[{g}~{w}] status QUEUED ...")
  with open(abspath(malware_path), "rb") as f:
   b = f.read()
   hashsum = sha256(b).hexdigest()
   info(hashsum)
 else:
  print (f"{w}[{r}!{w}] Failed To Get Results Of Analysis")
  print (f"{w}[{b}+{w}] Status Code : {str(res.status_code)}")
def info(file_hash):
 print (f"{w}[{g}~{w}] Get File Info By ID: {file_hash}")
 info_url = VT_API_URL + file_hash
 res = requests.get(info_url, headers = headers)
 if res.status_code == 200:
  result = res.json()
  if result.get("data").get("attributes").get("last_analysis_results"):
   stats = result.get("data").get("attributes").get("last_analysis_stats")
   results = result.get("data").get("attributes").get("last_analysis_results")
   print (f'{w}[{r}!{w}] Malicious : {str(stats.get("malicious"))}')
   print (f'{w}[{r}!{w}] Undetected : {str(stats.get("undetected"))}')
   fx.write(f'{w}[{r}!{w}] Malicious : {str(stats.get("malicious"))}\n')
   fx.write(f'{w}[{r}!{w}] Undetected : {str(stats.get("undetected"))}\n')
   for k in results:
    if results[k].get("category") == "malicious":
     print (results[k].get("engine_name"))
     print (f'{w}[{r}-{w}] version : {results[k].get("engine_version")}')
     print (f'{w}[{r}-{w}] category : {results[k].get("category")}')
     print (f'{w}[{r}-{w}] result : {results[k].get("result")}')
     print (f'{w}[{r}-{w}] method : {results[k].get("method")}')
     print (f'{w}[{r}-{w}] update : {results[k].get("engine_update")}')
     fx.write(f'''
      {results[k].get("engine_name")}
      "version : " {results[k].get("engine_version")}
      "category : " {results[k].get("category")}
      "result : "  {results[k].get("result")}
      "method : "  {results[k].get("method")}
      "update : " {results[k].get("engine_update")}
      ''')
   print (f"{w}[{b}+{w}] Successfully Analyse")
  else:
      print (f"{w}[{r}-{w}] Failed To Analyse")
 else:
      print (f"{w}[{r}!{w}] Failed To Get Information")
      print (f"{w}[{r}!{w}] Status Code: {str(res.status_code)}")
def check_files(*kwargs): # Edit It To Dump Ext With New NaME filE tO Save Paths
    ext = []
    name = ''
    if kwargs:
        for e in kwargs:
            for ee in e:
                ext.append(ee)
        name = paths_tool[1]
    else:name = paths_tool[0]
    if not isfile(name):
        fws = open(name , 'w')
        pathf = GetNamePart("All")
        for path in pathf:
            for dir,dirs,files in walk(path):
                for file in files:
                    pathF = dir + '/' + file
                    if isfile(pathF):
                        try:
                            if ext:
                                if ('.' + pathF.split('\\')[-1].split('.')[-1]) in ext:
                                    fws.write(str(pathF) + '\n')
                            else:
                                fws.write(str(pathF)  + '\n')
                        except UnicodeEncodeError:continue
        fws.close()
    with open(name , 'r')as ff:
        ff_l = ff.readlines()
        x = []
        for pathff in ff_l:
            pathff = pathff.rstrip()
            if isfile(r"{}".format(pathff)):
                upload_pe(pathff)
                x.append(pathff)
                f2 = open(name , 'w')
                for o in ff_l:
                    if o.rstrip() != pathff:
                       if o.rstrip() not in x:
                          f2.write(o)
                f2.close()
                print (f"{w}[{b}+{w}] SUCCESS SCAN {pathff.split('/')[-1]}")
    ff.close()
    sleep(10)
    try:
        remove(name)
    except:
        print (f'{w}[{g}!{w}] Delete {name} To Scanner Work')
        with open("scanners_notes" , 'w')as ffr:
            ffr.write(f'[!] Delete {name} To Scanner Work\n')
            if not voice == 1:SpeakDone("قم بالاطلاع علي ملف الملاحظات للنتائج")
            else:print (f'{w}[{b}+{w}] Please Look At Result File')
    if not voice == 1:SpeakDone("لقد تم الانتهاء من فحص كل ملفات الجهاز")
    else:print (f'{w}[{b}+{w}] Scanner Are Finished From Scanning All Files')
    results()
def maps_files():
    if not isfile(paths_tool[2]):
        f_map = open(paths_tool[2] , 'w')
        pathf = GetNamePart("All")
        for path in pathf:
            for dir,dirs,files in walk(path):
                for file in files:
                    pathF = dir + '/' + file
                    try:
                        if isfile(r"{}".format(pathF)):
                            f_map.write(pathF + ',,' + str(getsize(r"{}".format(pathF))) + '\n')
                    except UnicodeEncodeError:continue
def get_new():
   if not isfile(paths_tool[2]):exit(f"[{w}{r}!{w}] {paths_tool[2]} Was Deleted Reinstall The Tool Or Run Function maps_files")
   else:
    f_new = open("files_new" , 'w')
    new = []
    f = open(paths_tool[2] , 'r')
    rea = f.readlines()
    path_ = GetNamePart("part")
    for path in path_:
        for dir ,dirs, files in walk( path ):
                for file in files:
                    pathF = dir + '/' + file
                    if isfile (pathF):
                        pathF_ = pathF + ',,' + str(getsize(r"{}".format(pathF))) + '\n'
                    if pathF_ in rea:
                        continue
                    else:
                        new.append(pathF_)
    f.close()
    f_w = open(paths_tool[2] , 'a')
    for file in new:
        try:
           f_new.write(r"{}".format(file))
           f_w.write(r"{}".format(file))
           if isfile(file.rstrip()):
            upload_pe(r"{}".format(file.rstrip()))
            print (f"{w}[{g}+{w}] SUCCESS SCAN {file.rstrip().split('/')[-1]}")
        except:continue
    f_new.close()
    f_w.close()
    numb = str(len(open("files_new" , 'r').readlines()))
    if not voice == 1:SpeakDone('تم فحص الملفات والبرامج الجديدة')
    else:print (f'{w}[{b}+{w}] Scanner Are Finished Scanning New Files')
    results()
    print (f"{w}[{c}+{w}] Success Scan New Files {numb}")
def scan_paths(path):
    if not isdir(path):
        if not voice == 1:SpeakDone("المسار غير موجود")
        else:print(f"{w}[{r}!{w}] Path Invalid")
    else:
        for dir,dirs,files in walk(path):
            for file in files:
                pathF = dir + '/' + file
                if isfile(r"{}".format(pathF)):
                    try:
                        upload_pe(r"{}".format(pathF))
                        print (f"{w}[{g}+{w}] SUCCESS SCAN {pathF.split('/')[-1]}")
                    except :
                        continue
        if not voice == 1:SpeakDone("لقد تم الانتهاء من فحص ملفات المسار")
        else:print (f'{w}[{b}+{w}] Scanner Are Finished From Scanning')
        results() 
def check():
    data = _urandom(65000)
    s = socket(AF_INET,SOCK_STREAM)
    try:
        ip = gethostbyname('www.google.com')
        s.connect((ip,80))
        s.sendto(data,(ip,80))
        s.close()
        return True
    except gaierror:
        sleep(1)
        check()
        return False
def main():
    banner_0()
    if not voice == 1:SpeakDone("مرحبا بك قم باختيار احد الوظائف")
    while True:
        SpeakDone("صلي علي محمد")
        print(f"""{choice(colors)}
                                1. Scan All Files
                                2. Scan Specific Extensions
                                3. Scan Specific Path
                                4. Scan New Files
                                5. Quit
        """)
        ask = input(f'{w}{r}Scanner >> {w}')
        if ask == '1':
            if check():check_files()
        elif ask =='2':
            if check():
                ext = []
                print (f"{w}[{c}+{w}] Insert Stop To Stop Insert Extensions")
                print (f"{w}[{c}+{w}] If You Stop The Last Scan Specific Ext Scanner Doesn't Work Until Finish Scan It Or Delete This File : {paths_tool[1]}")
                while True:
                    ask2 = input(f'{w}{g}Extensions >> {w}')
                    if ask2.lower() == 'stop':
                        if not voice == 1:SpeakDone("لقد تم حفظ صيغ الملفات جاري فحصهم")
                        else:print (f'{w}[{b}+{w}] Extenstions Are Saved Scanner Will Work Now On Them')
                        break
                    else:
                        ext.append(ask2)
                        print (f"{w}[{c}+{w}] Added")
                check_files(ext)
        elif ask == '3':
            if check():scan_paths(input(f"{c}PATH >> "))
        elif ask == '4':
            if check():get_new()
        elif ask == '5':exit()
if __name__ == "__main__":
    while True:
       check()
       start_up()
       maps_files()
       main()
