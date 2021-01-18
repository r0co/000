import os
import re
import urllib
import argparse
import requests
from lib.core import data
from xml.etree import ElementTree as et


def init():
    """
    >>> init()
    >>> len(data.Absolute_path) > 0
    >>> len(data.Targets) > 0
    >>> len(data.Payloads) > 0
    >>> len(data.CmdLineOptions) > 0
    """
    initArgs()
    setPath()
    loadTarget()
    loadPayload()


def initArgs():
    usage = "python3 000.py [options]"
    parser = argparse.ArgumentParser(usage=usage)

    major_options = parser.add_argument_group("Major")

    major_options.add_argument("--url", "-u", dest="url", default=None, required=False,
                               help="Target URL (e.g. \"http://127.0.0.1\")")
    major_options.add_argument("--url-file", "-uf", dest="url_file", default=None, required=False,
                               help="Load url from a file (e.g. \"urls.txt\")")
    major_options.add_argument("--payload-folder", "-pf", dest="payload_folder", default="./payload",
                               help="The folder where the payload is stored (default ./payload)")

    others_options = parser.add_argument_group("Others")
    others_options.add_argument("--proxy", dest="proxy", default=None, required=False,
                                help="Use a proxy to connect to the target URL.(e.g. \"http://127.0.0.1:80\",HTTP/SOCKS4/5 is supported.)")
    others_options.add_argument("--threads", "-t", dest="threads", type=int, default=1, required=False,
                                help="Max number of concurrent HTTP(s) requests (default 1)")
    others_options.add_argument("--log-folder", "-lf", dest="log", default="./log", required=False,
                                help="The folder where the log will be stored (default \"./log\")")
    others_options.add_argument("--timeout", dest="timeout", default=5, type=int, required=False,
                                help="How many seconds to wait for the server to send data before giving up.")
    others_options.add_argument("--allow-redirects", "-ar", dest="allow_redirects", action="store_true",
                                help="Enable/disable GET/OPTIONS/POST/PUT/PATCH/DELETE/HEAD redirection.")
    args = parser.parse_args()
    data.CmdLineOptions = args.__dict__


def loadPayload():
    for xml in os.listdir(data.CmdLineOptions['payload_folder']):
        if xml[-4:] == ".xml":
            path = "{folder}/{xml}".format(folder=data.Absolute_path+data.CmdLineOptions['payload_folder'], xml=xml)
            xml2dict(path)


def loadTarget():
    """
    Load url from cmdline or file that stored urls
    """
    if data.CmdLineOptions['url'] is None and data.CmdLineOptions['url_file'] is None:
        exit("[!] You must give me a target at least.")

    if data.CmdLineOptions['url'] is not None:
        data.Targets.append(data.CmdLineOptions['url'])
    if data.CmdLineOptions['url_file'] is not None:
        file_path = data.Absolute_path + os.sep + data.CmdLineOptions['url_file']
        try:
            urls_dirty = [line.replace('\n', '') for line in open(file_path, "r").readlines()]
        except OSError as e:
            exit("[!] Can not load url file.\n{}".format(e))
        urls = []
        for url in urls_dirty:
            if url[-1] == '/':
                # Delete '/' at the end of url
                url = url[:-1]
            if url[:4] != "http":
                # e.g. 127.0.0.1 => http://127.0.0.1
                url = "http://{}".format(url)
            urls.append(url)
        data.Targets.extend(urls)


def xml2dict(xml_file):
    """
    >>> xml2dict("test.xml")
    >>> len(data.Payloads) > 0
    """
    doc = et.parse(xml_file)
    root = doc.getroot()

    for payload in root.findall("payload"):
        weapon = {"Header": {}}
        for child in payload:
            # Parse "Header" tag
            if child.tag == "Header":
                for header in child:
                    weapon["Header"][header.tag] = header.text
            # Parse others
            elif child.text:
                weapon[child.tag] = child.text
        data.Payloads.append(weapon)


def setPath():
    """
    >>> setPath()
    >>> len(data.Absolute_path) > 0
    """
    data.Absolute_path = os.getcwd()


def payload2dict(strings):
    """
    >>> a = payload2dict("cmd=whoami&pass=123")
    >>> a
    {"cmd":"whoami","pass"="123"}
    """
    res = {}
    pattern = r"(.*)=(.*)"
    payload_list = strings.split('&')
    for key_value in payload_list:
        for (key, value) in re.findall(pattern, key_value):
            res[key] = value
    return res


def checkVuln(url, payload):
    get_payload = urllib.request.quote(payload['GET'], safe='/?&=')
    # print(url + get_payload + "      ")
    if "POST" not in payload.keys():
        args_get = {
            "headers": payload["Header"],
            "proxies": {
                "http": data.CmdLineOptions["proxy"],
            },
            "timeout": data.CmdLineOptions["timeout"],
            "allow_redirects": data.CmdLineOptions["allow_redirects"],
        }
        resp = requests.get("{url}{get}".format(url=url, get=get_payload),
                            **args_get)
        resp = getAllResp(resp)
    else:
        args_post = {
            "headers": payload["Header"],
            "proxies": {
                "http": data.CmdLineOptions["proxy"],
            },
            "timeout": data.CmdLineOptions["timeout"],
            "data": payload2dict(payload["POST"]),
            "allow_redirects": data.CmdLineOptions["allow_redirects"],
        }
        resp = requests.post("{url}{get}".format(url=url, get=get_payload),
                             **args_post)
        resp = getAllResp(resp)
    if payload["Vuln_Condition"] in resp:
        return True
    else:
        return False


def showProcessBar(current, total):
    max_length = 50
    finished_length = int(current / total * max_length)
    if current != total:
        print("\r[{finished}>{unfinished}] {percent:.2f}%".format(finished='=' * finished_length,
                                                                  unfinished=' ' * (max_length - finished_length),
                                                                  percent=current / total * 100), end='')
    else:
        print("\r[{finished}{unfinished}] {percent:.2f}%".format(finished='=' * finished_length,
                                                                 unfinished=' ' * (max_length - finished_length),
                                                                 percent=current / total * 100), end='')


def getAllResp(response):
    message = ""
    for key, value in response.headers.items():
        message += "{k}: {v}\n".format(k=key, v=value)
    message += response.text
    return message
