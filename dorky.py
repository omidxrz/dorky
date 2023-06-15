#!/usr/bin/python3
import requests
import sys
import urllib.parse


def URLEncode(string):
    return urllib.parse.quote_plus(string)

def google(domain):
    print("\n---- Google Dork ----")
    Base = "https://www.google.com/search?q="
    print(Base + URLEncode(f"site:{domain} inurl:&"))
    print(Base + URLEncode(f"site:{domain} inurl:cmd | inurl:exec= | inurl:query= | inurl:code= | inurl:do= | inurl:run= | inurl:read= | inurl:ping= inurl:&"))
    print(Base + URLEncode(f"site:{domain} inurl:apidocs | inurl:api-docs | inurl:swagger | inurl:api-explorer"))
    print(Base + URLEncode(f"site:{domain} inurl:email= | inurl:phone= | inurl:password= | inurl:secret= inurl:&"))
    print(Base + URLEncode(f"site:{domain} inurl:config | inurl:env | inurl:setting | inurl:backup | inurl:admin | inurl:php"))
    print(Base + URLEncode(f"site:{domain} inurl:http | inurl:url= | inurl:path= | inurl:dest= | inurl:html= | inurl:data= | inurl:domain= | inurl:page= inurl:&"))
    print(Base + URLEncode(f"site:{domain} inurl:url= | inurl:return= | inurl:next= | inurl:redir= inurl:http"))
    print(Base + URLEncode(f"site:{domain} ext:log | ext:txt | ext:conf | ext:cnf | ext:ini | ext:env | ext:sh | ext:bak | ext:backup | ext:swp | ext:old | ext:~ | ext:git | ext:svn | ext:htpasswd | ext:htaccess | ext:xml"))
    print(Base + URLEncode(f"site:{domain} ext:php | ext:aspx | ext:asp | ext:jsp | ext:html | ext:htm"))
    print(Base + URLEncode(f"site:{domain} inurl:(unsubscribe|register|feedback|signup|join|contact|profile|user|comment|api|developer|affiliate|upload|mobile|upgrade|password)"))
    print(Base + URLEncode(f"site:{domain} ext:xml | ext:conf | ext:reg | ext:cfg | ext:inf | ext:txt | ext:ini"))
    print(Base + URLEncode(f"site:{domain} ext:( php | asp | aspx | jsp )"))
    print(Base + URLEncode(f"site:{domain} ext:sql | ext:dbf | ext:mdb | ext:log"))
    print(Base + URLEncode(f"site:{domain} ext:bkf | ext:bkp | ext:bak | ext:old | ext:backup"))
    print(Base + URLEncode(f"site:{domain} inurl:login | inurl:auth | inurl:Login | inurl:signin | intitle:signin"))
    print(Base + URLEncode(f"site:{domain} ext:doc | ext:docx | ext:odt | ext:pdf | ext:rtf | ext:sxw | ext:psw | ext:ppt | ext:pptx | ext:pps | ext:csv"))
    print(Base + URLEncode(f"site:{domain} ext:action | ext:stauts | ext:do"))
    print(Base + URLEncode(f"site:{domain} inurl:login | inurl:auth | inurl:Login | inurl:signin | intitle:signin"))
    print(Base + URLEncode(f"site:{domain} intext:\"Warning: mysql_num_rows()\""))
    print(Base + URLEncode(f"site:{domain} intitle:\"Welcome to Nginx\""))
    print(Base + URLEncode(f"site:http://ideone.com | site:http://codebeautify.org | site:http://codeshare.io | site:http://codepen.io | site:http://repl.it | site:http://justpaste.it | site:http://pastebin.com | site:http://jsfiddle.net | site:http://trello.com \"{domain}\" "))
    print(Base + URLEncode(f"site:openbugbounty.org inurl:reports intext:\"{domain}\""))
    print(Base + URLEncode(f"site:http://dropbox.com/s \"{domain}\""))
    print(Base + URLEncode(f"site:http://docs.google.com inurl:\"/d/\" \"{domain}\""))



def bing(domain):
    print("\n---- Bing Dork ----")
    Base = "https://www.bing.com/search?q="
    print(Base + URLEncode(f"site:{domain}"))



def yandex(domain):
    print("\n---- Yandex Dork ----")
    Base = "https://yandex.com/search/?text="
    print(Base + URLEncode(f"site:{domain}"))


def duckduckgo(domain):
    print("\n---- DuckDuckGo Dork ----")
    Base = "https://duckduckgo.com/?q="
    print(Base + URLEncode(f"site:{domain}"))


if __name__=='__main__':
    try:
        domain = sys.argv[1]
        google(domain)
        bing(domain)
        yandex(domain)
        duckduckgo(domain)


    except Exception as err:
        print(f"[-] Error: {err}")
