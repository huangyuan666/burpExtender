# -*-coding:utf-8 -*-
# !/usr/bin/env python
# author:ske

from burp import IBurpExtender
from burp import IHttpListener
from burp import IHttpRequestResponse
from burp import IResponseInfo
from burp import IRequestInfo
from burp import IHttpService

import re

print "check jsonp\n author:ske"

class BurpExtender(IBurpExtender, IHttpListener):

    def registerExtenderCallbacks(self, callbacks):

        self._callbacks = callbacks

        # 用于获取IExtensionHelpers对象，扩展可以使用该对象执行许多有用的任务。返回：包含许多帮助器方法的对象，用于构建和分析HTTP请求等任务。
        self._helpers = callbacks.getHelpers()

        # 用于设置当前扩展的显示名称，该名称将显示在Extender工具的用户界面中。参数：name - 扩展名。。
        self._callbacks.setExtensionName("find JSON callback")

        # 用于注册侦听器，该侦听器将通知任何Burp工具发出的请求和响应。扩展可以通过注册HTTP侦听器来执行自定义分析或修改这些消息。参数：listener- 实现IHttpListener接口的扩展创建的对象 。
        callbacks.registerHttpListener(self)

    def get_request_url(self, reqHeaders):
        link = reqHeaders[0].split(' ')[1]
        host = reqHeaders[1].split(' ')[1]
        return 'http[s]://{}{}'.format(host, link)

    def save(self, content):
        print content
        with open(r'H:\2. py\py_self\py3\project\burpExtend\jsonp.txt', 'at') as f:
            f.writelines(content+'\n\n')

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        '''
        :param toolFlag:            一个标志，指示发出请求的Burp工具。Burp工具标志在IBurpExtenderCallbacks界面中定义
        :param messageIsRequest:    标记是否为请求或响应调用方法。
        :param messageInfo:         要处理的请求/响应的详细信息。扩展可以调用此对象上的setter方法来更新当前消息，从而修改Burp的行为。
        :return:
        '''

        print '-' * 50
        # Proxy和Repeater触发插件
        if toolFlag == 64 or toolFlag == 16 or toolFlag == 8 or toolFlag == 4:

            # 处理响应内容
            if not messageIsRequest:
                # 获取响应包的数据
                response = messageInfo.getResponse()  # getResponse方法用于检索请求消息。返回：响应消息。
                analyzedResponse = self._helpers.analyzeResponse(
                    response)  # analyzeResponse方法可用于分析HTTP响应，并获取有关它的各种关键详细信息。返回：IResponseInfo可以查询的对象以获取有关响应的详细信息。
                resHeaders = analyzedResponse.getHeaders()  # getHeaders方法用于获取响应中包含的HTTP标头。返回：响应中包含的HTTP标头。
                resBodys = response[
                           analyzedResponse.getBodyOffset():].tostring()  # getBodyOffset方法用于获取消息正文开始的响应中的偏移量。返回：消息正文开始的响应中的偏移量。response[analyzedResponse.getBodyOffset():]获取正文内容
                resStatusCode = analyzedResponse.getStatusCode()  # getStatusCode获取响应中包含的HTTP状态代码。返回：响应中包含的HTTP状态代码。

                # 获取请求包的数据
                request = messageInfo.getRequest()
                analyzedRequest = self._helpers.analyzeRequest(
                    request)  # analyzeRequest用于分析HTTP请求，并获取有关它的各种关键详细信息。生成的IRequestInfo对象
                reqHeaders = analyzedRequest.getHeaders()  # 用于获取请求中包含的HTTP头。返回：请求中包含的HTTP标头。
                reqBodys = request[analyzedRequest.getBodyOffset():].tostring()  # 获取消息正文开始的请求中的偏移量。返回：消息正文开始的请求中的偏移量。
                reqUrl = self.get_request_url(reqHeaders)

                # 获取服务信息
                httpService = messageInfo.getHttpService()
                port = httpService.getPort()
                host = httpService.getHost()
                protocol = httpService.getProtocol()
                #print '{}://{}:{}'.format(protocol, host, port)
                # 第一种情况：url中带有callback,且返回的是json数据。
                expressionA = r'.*(callback).*'
                expressionB = r'.*(text/html|application/json|application/javascript).*'
                expressionC = r'.*(text/html|application/javascript).*'

                for _reqHeader in reqHeaders:
                    if _reqHeader.startswith("Host"):
                        reqhost = _reqHeader
                        break

                # Content-Type： WEB 服务器告诉浏览器自己响应的对象的类型。例如：Content-Type：application/xml
                ishtml = 0
                for resHeader in resHeaders:
                    if resHeader.startswith("Content-Type:") and re.match(expressionC, resHeader):
                        ishtml = 1

                    if resHeader.startswith("Content-Type:") and re.match(expressionB, resHeader):
                        if re.match(expressionA, reqHeaders[0]):
                            content = '[+] -> {}\n[Headers] -> {}'.format(reqUrl, reqHeaders)
                            self.save(content)
                            break

                # 第二种情况：url中没有带callback,但是通过添加callback参数后，便返回了带方法名的json数据。
                if not re.match(expressionA, reqHeaders[0]):
                    againReqHeaders = reqHeaders
                    if '?' in againReqHeaders[0]:
                        againReqHeaders[0] = againReqHeaders[0].replace('?', '?callback=BuiBui&')
                    else:
                        againReqHeaders[0] = againReqHeaders[0][:-9] + '?callback=BuiBui'

                    againReq = self._helpers.buildHttpMessage(againReqHeaders, reqBodys)
                    ishttps = False
                    if protocol == 'https':
                        ishttps = True

                    if resStatusCode == 200 and ishtml == 1:
                        againRes = self._callbacks.makeHttpRequest(host, port, ishttps, againReq)

                        # 新的请求请求包
                        analyzedreq = self._helpers.analyzeResponse(againRes)
                        # againReqHeaders = analyzedreq.getHeaders()
                        againReqBodys = againRes[analyzedreq.getBodyOffset():].tostring()
                        againReqUrl = self.get_request_url(againReqHeaders)

                        # 新的请求响应包
                        analyzedrep = self._helpers.analyzeResponse(againRes)
                        againResHeaders = analyzedrep.getHeaders()
                        againResBodys = againRes[analyzedrep.getBodyOffset():].tostring()

                        if 'BuiBui' in againResBodys:
                            for againResHeader in againResHeaders:
                                if againResHeader.startswith("Content-Type:") and re.match(expressionB, againResHeader):
                                    content = '[+] -> {}\n[Headers] -> {}'.format(againReqUrl, againReqHeaders)
                                    self.save(content)
                                    break
