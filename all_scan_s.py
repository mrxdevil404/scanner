from socket import socket , AF_INET , SOCK_STREAM , gethostbyname , gaierror
from os import walk , getenv , getcwd , getlogin , system , remove
from os.path import isfile , isdir , getsize , basename , abspath
from random import _urandom
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
def start_up():
    name = basename(__file__).split('.')[0] + '.exe'
    pathN = getcwd() + f'//{name}'
    if not isfile(f'C:\\\\Users\\\\{getlogin()}\\\\AppData\\\\Roaming\\\\Microsoft\\\\Windows\\\\Start Menu\\\\Programs\\\\Startup\\\\{name}'):copy(pathN,f'C:\\\\Users\\\\{getlogin()}\\\\AppData\\\\Roaming\\\\Microsoft\\\\Windows\\\\Start Menu\\\\Programs\\\\Startup')
def SpeakDone(num):
    language = "ar"
    myobj = gTTS(text=num, lang=language, slow=False)
    myobj.save("welcome.mp3")
    system("start welcome.mp3")
    sleep(5)
    remove("welcome.mp3")
def results():
    if isfile("results_scan.txt") and getsize("results_scan.txt") != 0:
        SpeakDone("مرحبا لقد تم الانتهاء من الفحص ويوجد بعض البرامج الضاره يرجي الاطلاع علي ملف النتائج لحذفهم")
    else:
        SpeakDone("مرحبا لقد تم الانتهاء من الفحص ولا يوجد اي برامج ضاره")
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
    if kwargs == 'All':
     path_d = [f'C:\\Users\\{getlogin()}\\Desktop' , getenv('AppData') , "C:\\Windows\\temp"]
    else:
     path_d = [f'C:\\\\Users\\\\{getlogin()}\\\\AppData\\\\Roaming\\\\Microsoft\\\\Windows\\\\Start Menu\\\\Programs\\\\Startup' , f"C:\\Users\\{getlogin()}\\Downloads" , f'C:\\Users\\{getlogin()}\\Desktop' , getenv('AppData')]
    for i in range(65,91):
        if isdir(f'{chr(i)}:\\') and chr(i) != 'C':
            path_ = chr(i) + ':\\\\'
            path_d.append(path_)
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
def check_files(*kwargs):
    ext = []
    if kwargs:
        for e in kwargs:
            for ee in e:
                ext.append(ee)
    if not isfile(getenv("AppData") + '//scan_files'):
        fws = open(getenv("AppData") + '//scan_files' , 'w')
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
    with open(getenv("AppData") + '//scan_files' , 'r')as ff:
        ff_l = ff.readlines()
        x = []
        for pathff in ff_l:
            pathff = pathff.rstrip()
            if isfile(r"{}".format(pathff)):
                upload_pe(pathff)
                x.append(pathff)
                f2 = open(getenv("AppData") + '//scan_files' , 'w')
                for o in ff_l:
                    if o.rstrip() != pathff:
                       if o.rstrip() not in x:
                          f2.write(o)
                f2.close()
                print (f"{w}[{b}+{w}] SUCCESS SCAN {pathff.split('/')[-1]}")
    ff.close()
    sleep(10)
    try:
        remove(getenv("AppData") + '//scan_files')
    except:
        print (f'{w}[{g}!{w}] Delete {getenv("AppData") + "//scan_files"} To Scanner Work')
        with open("scanners_notes" , 'w')as ffr:
            ffr.write(f'[!] Delete {getenv("AppData") + "//scan_files"} To Scanner Work\n')
            SpeakDone("قم بالاطلاع علي ملف الملاحظات للنتائج")
    SpeakDone("لقد تم الانتهاء من فحص كل ملفات الجهاز")
    results()
def maps_files():
    if not isfile(getenv("AppData") + '//maps_files'):
        f_map = open(getenv("AppData") + '//maps_files' , 'w')
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
   if not isfile(getenv("AppData") + '//maps_files'):exit(f"[{w}{r}!{w}] {getenv('AppData') + '//maps_files'} Was Deleted Reinstall The Tool Or Run Function maps_files")
   else:
    f_new = open("files_new" , 'w')
    new = []
    f = open(getenv("AppData") + '//maps_files' , 'r')
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
    f_w = open(getenv("AppData") + '//maps_files' , 'a')
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
    SpeakDone('تم فحص الملفات والبرامج الجديدة')
    results()
    print (f"{w}[{c}+{w}] Success Scan New Files {numb}")
def check():
    data = _urandom(65000)
    s = socket(AF_INET,SOCK_STREAM)
    try:
        ip = gethostbyname('www.google.com')
        s.connect((ip,80))
        s.sendto(data,(ip,80))
        s.close()
        check_files()
        get_new()
    except gaierror:
        sleep(1)
        check()
if __name__ == "__main__":
    start_up()
    maps_files()
    while True:
        check()
