# -*-coding:utf-8 -*-
# !/usr/bin/env python
# author:ske
# 对get参数和post参数检测，如果参数值是一个链接，那么就会尝试检测url跳转：↓
# --------------------------------------------------------------------------------------------------------
# 1、直接跳转
# http://baidu.com
# 2、利用@绕过URL限制
# http://login.aaa.com@baidu.com
# 3、利用  问号,#号,反斜杠和正斜杠,一个反斜杠一个点  绕过限制
# http://baidu.com?www.login.aaa.com
# http://baidu.com#login.aaa.com
# http://baidu.com/login.aaa.com
# http://baidu.com\\login.aaa.com
# http://baidu.com\login.aaa.com
# http://baidu.com\.login.aaa.com
# --------------------------------------------------------------------------------------------------------
# --------------------------------------------------------------------------------------------------------
# 1、直接跳转
# baidu.com
# 2、利用@绕过URL限制
# login.aaa.com@baidu.com
# 3、利用  问号,#号,反斜杠和正斜杠,一个反斜杠一个点  绕过限制
# baidu.com?www.login.aaa.com
# baidu.com#login.aaa.com
# baidu.com/login.aaa.com
# baidu.com\\login.aaa.com
# baidu.com\login.aaa.com
# baidu.com\.login.aaa.com
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
import urllib

print "check url Jump\n author:ske"

# 漏洞存储路径
saveFile = r'H:\2. py\py_self\py3\project\burpExtend\urlJump.txt'


# url跳转网址
toUrl = 'baidu.com'
# 利用[问号,#号,反斜杠和正斜杠,一个反斜杠一个点]绕过限制
bypassChars = ['?', '#', '/', '\\\\', '\\', '\\.']
# 调试开关
isDebug = 1
# 插件名字
ExtensionName = r'Url Jump'

class BurpExtender(IBurpExtender, IHttpListener):

    def registerExtenderCallbacks(self, callbacks):

        self._callbacks = callbacks

        # 用于获取IExtensionHelpers对象，扩展可以使用该对象执行许多有用的任务。返回：包含许多帮助器方法的对象，用于构建和分析HTTP请求等任务。
        self._helpers = callbacks.getHelpers()

        # 用于设置当前扩展的显示名称，该名称将显示在Extender工具的用户界面中。参数：name - 扩展名。。
        self._callbacks.setExtensionName(ExtensionName)

        # 用于注册侦听器，该侦听器将通知任何Burp工具发出的请求和响应。扩展可以通过注册HTTP侦听器来执行自定义分析或修改这些消息。参数：listener- 实现IHttpListener接口的扩展创建的对象 。
        callbacks.registerHttpListener(self)

        self.bypassChars = bypassChars
        self.toUrl = toUrl

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

    # url解析
    def url_parse(self, url):
        urlParse = urlparse(url)
        if isDebug:
            print urlParse
        scheme, netloc, path, params, query = urlParse.scheme, urlParse.netloc, urlParse.path, urlParse.params, urlParse.query
        return scheme, netloc, path, params, query

    # 检查是否存在url跳转
    def check_url_jump(self, request, protocol, host, port, ishttps, parameterName, parameterValueUrl,
                           parameterType):
        thread_id = threading.current_thread().ident
        if isDebug:
            print '[' + str(thread_id) + ']' + parameterValueUrl + '\n'
        # 构造参数
        newParameter = self._helpers.buildParameter(parameterName, parameterValueUrl, parameterType)
        # 更新参数，并发送请求
        newRequest = self._helpers.updateParameter(request, newParameter)
        newAnalyzedRequest, newReqHeaders, newReqBodys, newReqMethod, newReqParameters = self.get_request_info(
            newRequest)

        # 新的响应
        newResponse = self._callbacks.makeHttpRequest(host, port, ishttps, newRequest)
        newResHeaders, newResBodys, newResStatusCode = self.get_response_info(newResponse)
        if 300 < newResStatusCode < 400:
            newReqUrl = self.get_request_url(protocol, newReqHeaders)
            print '[{}] -> [{}] {}\n[Bodys] -> {}\n'.format(thread_id, newResStatusCode, newReqUrl, newReqBodys)
            content = '{} -> [{}] {}\n[Headers] -> {}\n[Bodys] -> {}'.format('[url Jump]', newResStatusCode, newReqUrl, newReqHeaders,
                                                                           newReqBodys)
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

                # 存放构造的每个url跳转链接
                newParameterValueList = []

                for parameter in reqParameters:
                    # 筛选出get参数和post参数.      0是get参数，1是post参数，2是cookies参数
                    if parameter.getType() != 2:
                        parameterName, parameterValue, parameterType = self.get_parameter_Name_Value_Type(parameter)
                        scheme, netloc, path, params, query = self.url_parse(urllib.unquote(parameterValue))

                        # ?url=http://login.aaa.com
                        if scheme:
                            # 直接跳转
                            newParameterValueList.append([parameterName, '{}://{}'.format(scheme, self.toUrl), parameterType])  # http://baidu.com

                            # 利用@绕过URL限制
                            newParameterValueList.append([parameterName,'{}://{}@{}'.format(scheme, netloc, self.toUrl), parameterType])  # http://login.aaa.com@baidu.com

                            # 利用[问号,#号,反斜杠和正斜杠,一个反斜杠一个点]绕过限制
                            # http://baidu.com?www.login.aaa.com  http://baidu.com#login.aaa.com  http://baidu.com/login.aaa.com
                            # http://baidu.com\\login.aaa.com  http://baidu.com\login.aaa.com  http://baidu.com\.login.aaa.com
                            for bypassChar in self.bypassChars:
                                newParameterValueList.append([parameterName, '{}://{}{}{}'.format(scheme, self.toUrl, bypassChar, netloc), parameterType])

                        # ?url=login.aaa.com/id=1&new=2
                        elif path and '.' in path:
                            domain = path.split('/')[0]

                            newParameterValueList.append([parameterName, '{}://{}'.format(protocol, self.toUrl), parameterType])
                            newParameterValueList.append([parameterName, '{}://{}@{}'.format(protocol, domain, self.toUrl), parameterType])
                            for bypassChar in self.bypassChars:
                                newParameterValueList.append([parameterName, '{}://{}{}{}'.format(protocol, self.toUrl, bypassChar, domain), parameterType])

                            newParameterValueList.append([parameterName, '{}'.format(self.toUrl), parameterType])
                            newParameterValueList.append([parameterName, '{}@{}'.format(domain, self.toUrl), parameterType])
                            for bypassChar in self.bypassChars:
                                newParameterValueList.append([parameterName, '{}{}{}'.format(self.toUrl, bypassChar, domain), parameterType])

                        # 参数里不存在网址
                        else:
                            break

                        # 存放url跳转的多线程
                        url_threads = []
                        for newParameters in newParameterValueList:
                            parameterName, parameterValueUrl, parameterType = newParameters
                            t = threading.Thread(target=self.check_url_jump, args=(
                            request, protocol, host, port, ishttps, parameterName, parameterValueUrl, parameterType))
                            url_threads.append(t)
                            t.start()
                        for t in url_threads:
                            t.join()






