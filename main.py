#!/usr/bin/python3 
#author: (MR X)

import os, sys, time, random, requests
import json, itertools, re, instaloader
from googlesearch import search
import duckduckgo_search as ddgo
from faker import Faker
from mailtm import Email
import wikipedia as wiki
from bs4 import BeautifulSoup
from bs4 import BeautifulSoup as bs
#> ------ [ Colours ] ------ <#
white = "\033[0m"
rad = "\033[1;31m"
green = "\033[1;32m"
white = "\033[1;37m"
blue = "\033[1;34m"
#> ------ [ Tokens/APIKeys ] ------ <#
configration = json.load(open("data/config.json"))
#> ------ [ Gen-Wordlist ] ------ <#
def createWordList():
	logo()
	chrs = input(" [+] Input Characters for Passlist : ")
	try:
		min_length = int(input(" [+] Input Minimum Password length : "))
	except ValueError:
		min_length = 4
	try:
		max_length = int(input(" [+] Input Maximum Password length : "))
	except ValueError:
		max_length = 6
	outputX = input(" [+] PassList Save as : ")
	output = open(outputX, 'w')
	print(" ------------------------------------------------------")
	print(f"    {green}{chrs}{white}")
	print(" ------------------------------------------------------")
	time.sleep(2)
	for n in range(min_length, max_length + 1):
		for xs in itertools.product(chrs, repeat=n):
			chars = ''.join(xs)
			output.write("%s\n" % chars)
			print(chars)
	lines_Pass = len((open(outputX,"r").read()).splitlines())
	output.close()
	print(" ------------------------------------------------------")
	print(f" [{green}+{white}] PassList Save As : {outputX}")
	print(f" [{green}+{white}] Total Passwords : {str(lines_Pass)}")
	print(f" [{green}+{white}] Length - Minimum / Maximum : {str(min_length)} / {str(max_length)}")
	print(" ------------------------------------------------------")
	input("")
	time.sleep(0.5)
	main()
#> ------ [ Install-Kalinethunter ] ------ <#
def kali_nethunter():
	logo()
	print(f"[{green}+{white}] Installing Kali Net Hunter Please - Wait")
	print(" ------------------------------------------------------")
	os.system("""termux-setup-storage
pkg install wget -y
wget -O install-nethunter-termux https://offs.ec/2MceZWr
chmod +x install-nethunter-termux
bash install-nethunter-termux""")
	input("")
	time.sleep(0.5)
	main()
#> ------ [ IP-Information ] ------ <#
def ip_info():
	logo()
	user_ip = input(" [+] Input Target IP Address : ")
	urlY = (f"http://ip-api.com/json/{user_ip}?lang=en")
	print(" ------------------------------------------------------")
	print(f"    target: {green}{user_ip}{white}")
	print(" ------------------------------------------------------")
	sess = requests.Session()
	data = sess.get(urlY).text
	data = json.loads(data)
	for key,values in data.items():
		print(f" [{green}+{white}] {str(key).capitalize()} : {str(values).capitalize()}")
	print(" ------------------------------------------------------")
	input("")
	time.sleep(1)
	main()
#> ------ [ Query Search ] ------ <#
def query_search():
	number = 1
	logo()
	query = input(f'[{green}+{white}] Input Keyword && Query : ').strip().split('--')
	print(" ------------------------------------------------------")
	for words in query: #\n
		results = search(words,num_results=20,sleep_interval=5,advanced=True)
		print(f"[{green}*{white}] Google Search Result [{words}]: ")
		for result in results:
			print(f" [{green}*{white}] Title {green}{number}{white} : {result.title} ")
			print(f" [{green}*{white}] URL : {result.url}")
			print(f" [{green}*{white}] Description : {result.description}\n")
			number +=1
		summary = wiki.summary(words)
		page = wiki.page(words)
		print(f'[{green}+{white}] Wikipedia : ')
		print(" ------------------------------------------------------")
		print(f'\t\t{summary}')
		print(f' [{green}*{white}] Title : {page.title}')
		print(f' [{green}*{white}] URL : {page.url}')
		print(f' [{green}*{white}] Description : {page.content}')
		duckgo_search = ddgo.DDGS()
		results = duckgo_search.text(words)
		print(" ------------------------------------------------------")
		print(f"[{green}*{white}] DuckDuckGo Search Result [{words}]: ")
		for result in results:
			title0 = (result['title']).split('-')[0]
			try:title1 = (result['title']).split('-')[1]
			except IndexError:title1 = 'None'
			url = result['href']
			content = result['body']
			print(f' [{green}*{white}] Title : {title1} [ {green}{title0}{white} ]')
			print(f' [{green}*{white}] URL : {url}')
			print(f' [{green}*{white}] Description : {content}')
#> ------ [ Query Search ] ------ <#
def mailTm_listener(message):
	print(f"[{green}+{white}] Subject: " + message['subject'])
	print(f"[{green}+{white}] Content: " + message['text'] if message['text'] else message['html'])
def mailTM():
	logo()
	username = input(f"[{green}+{white}] Input Username [Random] : ")
	password = input(f"[{green}+{white}] Input Password [Random] : ")
	domain = input(f"[{green}+{white}] Input Domain [exelica.com] : ")
	mail = Email()
	if username in ['',' ']:username=None
	if password in ['',' ']:password=None
	if domain in ['',' ']:domain=None
	mail.register(username=username,password=password,domain=domain)
	print(f"\n[{green}+{white}] Email Adress: " + str(mail.address))
	print(f"[{green}+{white}] Waiting for new emails...")
	print(" ------------------------------------------------------")
	mail.start(mailTm_listener)
#> ------ [ Json Keys/Values Printer ] ------ <#
def print_json_keys_values(json_data):
	for key, value in json_data.items():
		if isinstance(value, dict):
			print(f'[{green}+{white}] {key} : ')
			print_json_keys_values(value)
		else:
			print(f'[{green}+{white}] {key} : {value}')
#> ------ [ FB Information Gathering ] ------ <#
def fbinfoga():
	logo()
	app_token = configration['facebook_token'].strip()
	uid = input(f"[{green}->{white}] Input fb uid : ")
	try:
		data = requests.get(f"https://graph.facebook.com/{uid}?metadata=1&access_token={app_token}").json()
	except Exception as e:
		print(f"\n {rad}Error : {e} {white}")
	print(" ------------------------------------------------------")
	print_json_keys_values(data)
	print(" ------------------------------------------------------")
	input(f"")
	main()
#> ------ [ IG Information Gathering ] ------ <#
def iginfoga():
	logo()
	L = instaloader.Instaloader()
	username = input(f" [{green}+{white}]Input Instagram Username : ")
	profile = instaloader.Profile.from_username(L.context, username)
	print(" ------------------------------------------------------")
	for attribute in sorted(profile.__dict__.keys()):
		value = getattr(profile, attribute)
		if attribute == '_node':
			print_json_keys_values(value)
		else:
			print(f"{white}{attribute}: {value}")
	print(" ------------------------------------------------------")
	input(f"")
	main()
#> ------ [ FB Token Generator ] ------ <#
def generate_token():
	logo()
	cookie = input(f'[{green}->{white}] Input Cookie : ')
	session = requests.Session()
	try:
		url = 'https://www.facebook.com/adsmanager/manage/campaigns'
		req = session.get(url,cookies={'cookie':cookie})
		set = re.search('act=(.*?)&nav_source',str(req.content)).group(1)
		nek = '%s?act=%s&nav_source=no_referrer'%(url,set)
		roq = session.get(nek,cookies={'cookie':cookie})
		token = re.search('accessToken="(.*?)"',str(roq.content)).group(1)
		print(" ------------------------------------------------------")
		print(f"[{green}+{white}] EAAB Token : {green}{token}{white}")
		req_info_token(cookie,token)
	except Exception as e:
		print(f'{e}')
	try:
		url = 'https://business.facebook.com/business_locations'
		req = session.get(url,cookies={'cookie':cookie})
		token = re.search('(\["EAAG\w+)', req.text).group(1).replace('["','')
		print(" ------------------------------------------------------")
		print(f"[{green}+{white}] EAAG Token : {green}{token}{white}")
		req_info_token(cookie,token)
	except Exception as e:
		print(f'{e}')
	try:
		url = 'https://www.facebook.com/events_manager2/overview'
		req = session.get(url,cookies={'cookie':cookie})
		token = re.search('{"accessToken":"(EAAd\w+)',req.text).group(1)
		print(" ------------------------------------------------------")
		print(f"[{green}+{white}] EAAD Token : {green}{token}{white}")
		req_info_token(cookie,token)
	except Exception as e:
		print(f'{e}')
	print(" ------------------------------------------------------")
	input(f"")
	main()
#> ------ [ PAK SIM INFO ] ------ <#
def paksiminfo():
	logo()
	number = input(f' [{green}->{white}] Input Mobile Number (03x...x) : ')
	url = "https://simdatabaseonline.com.pk/search.php"
	params = {
		'type':'mobile',
		'search':number
	}
	response = requests.get(url,params=params)
	try:
		soup = BeautifulSoup(response.text, 'html.parser')
		print("\n ------------------------------------------------------")
		for row in soup.find_all('tr'):
			data = {cell.get('data-label'): cell.text.strip() for cell in row.find_all('td')}
			if len(response.text) != 0:
				print_json_keys_values(data)
			else:
				print(f" [{rad}->{white}] No Data Found In Database")
		print(" ------------------------------------------------------")
	except Exception as e:
		print(f"{e}")
#> ------ [ FB Token Permissions ] ------ <#
def req_info_token(cookie,token):
	session = requests.Session()
	try:
		url	= 'https://developers.facebook.com/tools/debug/accesstoken/?access_token=%s&version=v15.0'%(token)
		req = BeautifulSoup(session.get(url,cookies={'cookie':cookie}).content,'html.parser')
		crf = req.find('a',href='/docs/reference/login/#permissions').text
		print(f"[{green}+{white}] Permissions : {green}{crf}{white}")
	except Exception as e:
		print(f"{e}")
#> ------ [ revshells  ] ------ <#
def revshells():
	logo()
	os.system("cd data/malware/reverse-shell-generator ; python3 -m http.server")
#> ------ [ Logo ] ------ <#
def logo():
    os.system('clear')
    print(f"""{white}   [{rad} Version 0.0.1 {white}]
___________.__    .__           .______________             
\__    ___/|  |__ |__|______  __| _/\_   _____/__.__. ____  
  |    |   |  |  \|  \_  __ \/ __ |  |    __ <   |  |/ __ \ 
  |    |   |   Y  \  ||  | \/ /_/ |  |        \___  \  ___/ 
  |____|   |___|  /__||__|  \____ | /_______  / ____|\___  >
                \/               \/         \/\/         \/ """)
    print(f" #> ---------------< [ {green}Third Eye{white} ] >---------------- <# ")
    print(f"{green} No Technology thats connected to internet is Unhackable{white}")
    print(" ------------------------------------------------------")
#> ------ [ Main ] ------ <#
def main():
    logo()
    print("")
    print(f" #> ---------------< [ {green}Main Menu{white} ] >---------------- <# ")
    print(f" [{green}01{white}] Wordlist generator ")
    print(f" [{green}02{white}] Install Kali NetHunter (rootless)")
    print(f" [{green}03{white}] IP Address Information")
    print(f" [{green}04{white}] Search Query [google,wikipedia,duckduckgo]")
    print(f" [{green}05{white}] TempMail Server")
    print(f" [{green}06{white}] FB Account Information Gathering")
    print(f" [{green}07{white}] IG Account Information Gathering")
    print(f" [{green}08{white}] FB Account Cookie-To-Token")
    print(f" [{green}09{white}] PAK SIM Number Information Gathering")
    print(f" [{green}10{white}] Reverse Shell Generator (GUI)")
    # print(f" [{green}11{white}] ")
    # print(f" [{green}12{white}] ")
    # print(f" [{green}13{white}] ")
    # print(f" [{green}14{white}] ")
    # print(f" [{green}15{white}] ")
    mninp = input(f"[{green}->{white}] Input an option : ")
    if mninp in ['01','1']:
        createWordList()
    elif mninp in ['02','2']:
        kali_nethunter()
    elif mninp in ['03','3']:
        ip_info()
    elif mninp in ['04','4']:
        query_search()
    elif mninp in ['05','5']:
        mailTM()
    elif mninp in ['06','6']:
        fbinfoga()
    elif mninp in ['07','7']:
        iginfoga()
    elif mninp in ['08','8']:
        generate_token()
    elif mninp in ['09','9']:
        paksiminfo()
    elif mninp in ['10']:
        revshells()
	else:
		time.sleep(1)
		main()
if __name__=="__main__":
	main()