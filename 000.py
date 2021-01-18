import os
import time
from lib.core import data
from urllib.parse import urlsplit
from lib.core.functions import init, checkVuln, showProcessBar
from concurrent.futures import ThreadPoolExecutor, as_completed


class r0co:
    def __init__(self):
        self.datetime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        init()
        self.log_path = "{folder}/{datetime}.log".format(folder=data.CmdLineOptions['log'],
                                                         datetime=self.datetime.replace(' ', '_').replace(':', '-'))
        try:
            self.log = open(self.log_path, "w")
            self.log.write("[!] Only successful operations are recorded\n")
        except OSError as e:
            exit("[!] Failed to open {}: {}".format(self.log_path, e))
        self.showCurrentConfig()

    def start(self, url, payload):
        if checkVuln(url, payload):
            self.recorder(url, payload)
            target = "{url}{get}".format(url=url, get=urlsplit(payload['GET']).path)
            return target
        else:
            return None

    def recorder(self, url, payload):
        front = "{boundary}{datetime}{boundary}\n".format(boundary="=" * 15, datetime=self.datetime)
        log = "URL: " + url + urlsplit(payload['GET']).path + '\n'
        for key in payload.keys():
            if key == "Header":
                log += "|Header:\n"
                for item in payload["Header"].keys():
                    log += "|\t{key}:{value}\n".format(key=item, value=payload["Header"][item])
            elif key == "Vuln_Condition":
                continue
            else:
                log += "|{key}:\n|\t{value}\n".format(key=key, value=payload[key])
        log = front + log
        self.log.write(log)

    def showCurrentConfig(self):
        message = "[*] Current config:\n"
        message += "==> Url: {}\n".format(data.CmdLineOptions['url'])
        message += "==> Log: {}\n".format(self.log_path)
        message += "==> Proxy: {}\n".format(data.CmdLineOptions['proxy'])
        message += "==> Threads: {}\n".format(data.CmdLineOptions['threads'])
        message += "==> Timeout: {}\n".format(data.CmdLineOptions['timeout'])
        message += "==> Url-File: {}\n".format(data.Absolute_path + os.sep + data.CmdLineOptions['url_file'])
        message += "==> Payload Folder: {}\n".format(data.CmdLineOptions['payload_folder'])
        message += "==> Allow Redirects: {}".format(data.CmdLineOptions['allow_redirects'])
        print(message)
        if input("[*] Is the current configuration correct? [y/n]: ").lower() != 'y':
            exit()
        else:
            print("[*] OK.Scanner will be start soon.")

    def __del__(self):
        try:
            self.log.close()
        except AttributeError:
            pass


if __name__ == '__main__':
    scanner = r0co()
    r0co = ThreadPoolExecutor(max_workers=data.CmdLineOptions['threads'])
    task_list = []
    for url in data.Targets:
        for payload in data.Payloads:
            args = [url, payload]
            task_list.append(r0co.submit(scanner.start, *args))
    total_task = len(task_list)
    finished_count = 0
    for finished in as_completed(task_list):
        res = finished.result()
        if res:
            print("\r[+] {} is vulnerable.".format(res))
        finished_count += 1
        showProcessBar(finished_count, total_task)
