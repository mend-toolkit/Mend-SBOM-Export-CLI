from enum import Enum
import os

class aliases(Enum): # List of aliases for params
    apikey = ("--apiKey","--api-key","--orgToken")
    userkey = ("--user-key","--userKey")
    projectkey = ("--project","--projectToken")
    productkey = ("--productToken","--product")
    url = ("--url","--mendUrl")
    output = ("--out","--dir")
    sbom = ("--sbom","--input")
    lic = ("--licensetext", "--lictext")
    exclude = ("--exclude", "-exclude")
    threads = ("--threads", "-threads")
    type = ("--type", "-type")

    @classmethod
    def get_aliases_str(cls, key):
        res = list()
        for elem_ in cls.__dict__[key].value:
            res.append(elem_)
            if elem_ != elem_.lower():
                res.append(elem_.lower())
        return res


class varenvs(Enum): # Lit of Env.variables
    wsuserkey = ("WS_USERKEY", "MEND_USERKEY")
    wsapikey = ("MEND_APIKEY","WS_APIKEY","WS_TOKEN")
    wsurl = ("WS_WSS_URL","MEND_WSS_URL","WS_URL","MEND_URL")
    wsscope = ("WS_SCOPE","MEND_SCOPE")
    wsproduct = ("WS_PRODUCTTOKEN", "MEND_PRODUCTTOKEN")
    wsproject = ("WS_PROJECTTOKEN", "MEND_PROJECTTOKEN")
    wsexclude = ("WS_EXCLUDETOKEN", "MEND_EXCLUDETOKEN")

    @classmethod
    def get_env(cls, key):
        res = ""
        for el_ in cls.__dict__[key].value:
            res = os.environ.get(el_)
            if res:
                break
        return res
