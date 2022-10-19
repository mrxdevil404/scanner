from subprocess import Popen , PIPE
from os.path import isfile
from os import remove , listdir , chdir , getcwd
from shutil import rmtree , move
pwd = getcwd()
name = 'scanner.py'
convert_exe = Popen(f'pyinstaller --onefile --icon=favicon.ico {name}',shell=True,stdout=PIPE).communicate()[0]
if isfile(name.split(".")[0] + ".spec"):
    remove(name.split(".")[0] + ".spec")
chdir("dist")
move(listdir()[0] , "..")
chdir(pwd)
rmtree("build")
rmtree("dist")