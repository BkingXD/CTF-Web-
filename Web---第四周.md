# Web---第四周

## 1、刷题

Bugku CTF web25-33，写WP

## 2.观看视频二，回答下列问题：

1.目前owasp的十大web安全漏洞是哪些？这些漏洞排名是按照漏洞的严重程度排序的还是按照漏洞的常见程度排序的？（2分） 

1、Injection(注入漏洞) 2、Broken Authentication(身份认证失败) 3、Sensitive Data Exposure(敏感信息泄漏) 4、XML External Entities(XXE) 5、Broken Access Control(访问控制中断) 6、Security Misconfiguration(安全配置错误) 7、Cross-Site Scripting(XSS，跨站脚本) 8、Insecure Deserialization(不安全的反序列化) 9、Using Components with Known Vulnerabilities(使用已知漏洞组件) 10、Insufficient Logging & Monitoring(日志和监控不足)

按漏洞的严重程度排序

2.请翻译一下credential stuffing（1分） 

凭证填充；撞库；

3.为什么说不充分的日志记录(insufficient logging)也算owasp十大漏洞的一种？他的危害性如何（2分） 

因为当黑客侵入你的系统，而你的日志中没有留下或者留下不充分的黑客进入的记录，你就不能及时知道黑客的侵入，所以也就不能及时做出防御等举措，从而产生危害。它的危害非常大

4.请翻阅一下owasp testing guide，以及owasp testing guide check-list，视频说怎么结合这两个文档来学习渗透测试？ 结合你平时渗透过程中的经验，谈谈你的感想。（3分） 

owasp testing guide教你用不同方式去测试一个web；owasp testing guide check-list是一个表格，包含了所以当你在渗透时需要测试的东西。根据owasp testing guide check-list里一项测试，然后在owasp testing guide文档里搜索有关这项测试更详细的资料，包括教你怎么操作。

虽然没有渗透经验，但我认为这个owasp提供了测试的规范和方法，使渗透测试更加系统化和全面化，不会忘记或忽略某项测试，更有利于渗透测试

5.you are only as good as you notes   you are only as good as things you can refer to结合这两句话谈谈你的感想。（2分）

要多写笔记，多参考学习别人的好的东西