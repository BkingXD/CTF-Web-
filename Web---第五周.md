# Web---第五周

## 1、观看视频三，回答下列问题

1.http报文的结构是什么？（1分） 

```
http报文由报文首部与报文主体构成，两者中间隔着crlf。
```

2.什么是crlf？在http报文的哪个位置。（1分） 

```
crlf是空行，CR(回车)+LF(换行)的意思，它在http报文的首部与主体之间，将其分割开。
```

3.解释下这几个头的含义（5分）：

```
Host：处理http请求的服务器是是谁
Accept：告诉web服务器，能被客户端接受的MIME(多用途互联网邮件扩展类型)
Cookie：存在客户端上的数据，发送给服务器，用来验证客户端身份，从而返回相对应的信息
Referer：告诉服务器，客户端从哪个页面链接过来的
Authorization：基础认证，包含客户端的username和password，服务器用来验证客户端的身份的认证
```

4.cookie具有哪些特点，不同的域名和子域名对cookie有怎样的权限？Cookie的Secure和 HTTPOnly这两个flag分别有什么作用？请结合xss攻击来进行说明（3分） 

```
cookie是服务器发送给客户端的键值对(key-value)数据，并保存在客户端，每一个cookie对应唯一内容。
(1)为域名添加一个cookie，这个cookie可以被任何子域名读取
(2)为子域名添加一个cookie，这个cookie只能被自己和自己的子域名读取
(3)一个子域名(test.example.com)设置一个cookie能为了它的子域名(foo.test.example.com)和父域名(example.com)，但不能为了同级域名(test2.example.com)
Secure：cookie只能用于https协议
HTTPOnly：cookie不能被Javascript(document.cookie)读取到。因为XSS攻击是编写恶意HTML代码，而使用HTTPOnly，cookie就不会被恶意的Javascript代码窃取到
```

5.简述本视频提到的xss绕过web防火墙的方案（5分）

```
对于HTML，浏览器解析语句和防火墙(filter)解析语句有差异，间接说明存在漏洞，例如<script/xss，一些不好的filter不会把它当成script标签，因而没有过滤掉这个语句，但浏览器会把它当html执行，导致XSS攻击，这个方案就是构造不被防火墙过滤的标签。
<script>标签，HTML5规范规定浏览器会在结尾对它进行自动闭合，否则会出现语法错误；但如果是在url中的xss，那就不行了，因为自动闭合中的'/'会变成路径分隔符。
某个标签闭角符号不存在，会与下一个标签的闭角符合自动闭合匹配，而且大多数浏览器会认为在一个标签里设置一个开放标签是有效的；其中一种是用封装协议来封装script标签，配合一组尖括号，实现绕过。
```

6.内容嗅探是什么？主要有哪些类型？请分别举例，主要用途是什么？在什么情况下可以利用这些漏洞？。为什么facebook等网站需要使用不同的域名来存储图片？（5分） 

```
内容嗅探：浏览器在显示响应回来的请求文件或网页时，不知道该文件或网页的具体类型(Content-Type)，（就是你发送的数据里没有Content-Type），浏览器就会启动内容嗅探机制，对内容进行解析匹配，然后执行相应的解析显示。

MIME嗅探：浏览器会先自动探测未知格式的请求文件类型；
浏览器还会自动检测请求文件的内容，如果包含html标记，它就会解析执行，IE6或7因为没有对响应图片或文件指定适当的MIME类型，如果图片或文件包含html就能执行，这样就可以通过存储形式实现XSS攻击。
编码嗅探：浏览器会先自动探测未知格式文件的编码类型；
不指定编码类型，浏览器就会进行编码嗅探，控制浏览器的文本解码方法，就能修改其解析机制，侧面了解浏览器的过滤方式。WAF通常会过滤掉尖括号等危险字符，利用UTF-7等编码，就可以绕过，如果你不指定编码类型，在编码嗅探的过程中也可能会绕过。

网站需要上传图片，如果图片中写入HTML的内容，且触发了MIME嗅探，受害者把它当作一般图片，那么攻击者可以写入任意相关代码来实现想要的攻击，所以facebook等网站使用不同的域名来存储图片，为了防止XSS等攻击
```

7.同源策略是什么？限制是什么？浏览器在遇到哪两种情况的时候会用到同源策略？如何放松SOP限制？放松SOP限制会对浏览器插件安全造成怎样的破坏？ 

```
同源策略是一种限制跨域资源访问的约定，防止web交互的不安全行为。
限制就是源匹配，协议(http&https)相同，端口相同，域名相同(上下级域名都不行)。
1、不同域之间通过XML的HTTP请求(AJAX请求)交互 2、iframe和windows属性的跨域访问
设置不同域之间的document.domain脚本；post messages进行跨窗口通信；使用CORS(cross-origin resource sharing)跨源资源共享，可加在http的请求头中
我们向浏览器插件发送信息，而其存在的SOP绕过漏洞已经破坏了浏览器沙箱，会导致XSS攻击，形成不同页面的信息获取
```

8.csrf是什么？如何设计规避csrf？视频中提到的错误的csrf配置方法是什么？ 

```
csrf(跨站请求伪造)，攻击者挟持受害者去访问攻击者控制的的网站，然后以受害者的身份执行提交数据等恶意操作。
使用Token来规避csrf。
仅附带动态的csrf验证形式，在每一个表单中包含进csrf Token，每次提交在服务端生成一个新的Token，后端生成csrf.js这个文件，每个页面加载该文件添加csrf Token这个参数；这样配置会把csrf Token存储在JS文件中，把csrf Token的生成机制泄露了，然后会被攻击者利用。
```

附加题：5、6两点主要利用的是由于服务端和客户端对同一信息的处理方式不同造成的漏洞，你还能举出相似的例子么？（1分）

```
不知道
```

## 2、刷题，写WP，学知识点

WP放博客了。

因为以前没写WP的习惯，所以重新做了一遍一部分BUU的做过的题目，写了WP

