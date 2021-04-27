# web25

hint：[SQL约束攻击](https://www.anquanke.com/post/id/85230)（先去学习一下）

```
1、不管sql查询还是插入，都会略去空格（前提：空格后面没有字符）
2、插入数据时，先查询该username在数据库中是否存在，不存在，则插入
3、插入数据时，会删去高出限制的字符
```

先随便注册一个账号，然后登陆试试，回显“不是管理员还想看flag？！”，去注册一个用户名为`admin`的账号，发现已存在，于是根据SQL约束攻击的原理，注册一个用户为`admin(空格*n)1`的账号，输入`admin`和自己注册的密码，拿到flag。

原理：此处注册账号相当于往数据库插入一条数据，所以`admin(空格*n)1`会被查询数据库中是否存在，如果不存在，则插入数据，但是因为每条数据的长度有限，它会自动删去超出长度的字符，于是就会存在两条`admin`数据，输入`admin`和自己注册的密码，就会返回第一个数据记录，也就是原始的数据记录。这样就成功做到了以原始用户身份登录

# web26

”are you from google?“，显然这是要改referer，BP抓包，请求头里改`Referer:http://www.google.com`，或者用hackbar这个插件，flag就直接出来了

# web27

提示md5 collision，打开页面，显示”please input a“，随便尝试一下GET传入`a`的值，回显为”false!!!“，根据提示，试了一下`?a=QNKCDZO`，显示为”false!!!“，在再试了一下`?a=240610708`，就拿到了flag（很是迷惑）。

于是上网搜了一下，发现好像缺失了源码，那就分析以下源码吧

```php
$md51 = md5('QNKCDZO');
$a = @$_GET['a'];
$md52 = @md5($a);
if(isset($a)){
    if ($a != 'QNKCDZO' && $md51 == $md52) {
        echo "nctf{*****************}";
    } else {
        echo "false!!!";
    }
}//显然，用了"=="，md5函数漏洞，只要a的md5加密后的值为0E开头就行
else{
    echo "please input a";
}
```

# web28

提示为“请从本地访问”，这太简单了，就是伪造IP嘛，直接用hackbar插件添加`X-Forwarded-For:127.0.0.1`，轻松拿到flag

# web29

简简单单代码审计，

```php
<?php
highlight_file('flag.php');
$_GET['id'] = urldecode($_GET['id']);//得到的数据进行url解码
$flag = 'flag{xxxxxxxxxxxxxxxxxx}';
if (isset($_GET['uname']) and isset($_POST['passwd'])) {
    if ($_GET['uname'] == $_POST['passwd'])
        print 'passwd can not be uname.';
    else if (sha1($_GET['uname']) === sha1($_POST['passwd'])&($_GET['id']=='margin'))
        die('Flag: '.$flag);
//回显flag的条件，uname和passwd不能相等，但它们的sha1值要相等，因为用了"==="，不能用0E绕过，用数组
    else
        print 'sorry!';
}
?>
```

构造`payload：GET:?id=margin&uname[]=1 POST:passwd[]=2`

# web30

题目描述：“txt？？？？”，打开又是代码审计，

```php
<?php
extract($_GET);
if (!empty($ac))//如果$ac存在且非空非零，empty()返回false
{
$f = trim(file_get_contents($fn));//$fn为一个文件名，$f为将这个文件读入一个字符串并去除首尾空白字符
if ($ac === $f)
{
echo "<p>This is flag:" ." $flag</p>";
}
else
{
echo "<p>sorry!</p>";
}
}
?>
```

通过分析代码，可以得出，应该需要寻找`$fn`的值，题目又提示了txt，用dirsearch扫一下目录，发现没有想要的txt文件，后来想到`file_get_contents()`这个函数，可将参数设为`php://input`，同时用POST传数据，此时POST的数据可被视为文件内容，于是BP抓包，构造`payload：GET:?ac=123&fn=php://input POST:123`。

但我感觉这个提示应该是有用的，我一开始的想法是没错的，后来看到了别的师傅的另一种解，目录下应该是有个`flag.txt`，直接访问可得里面内容为`bugku`，于是可以构造`payload：?ac=bugku&fn=flag.txt`，但是我迷惑这个文件名的由来，难道真的只有大胆猜测得出？

# web31

打开网页，显示如下![image-20210420215147492](C:\Users\shuoke\AppData\Roaming\Typora\typora-user-images\image-20210420215147492.png)

"No such file or directory"，说明文件或路径不对，暗示需要寻找到其它文件和路径，于是拿dirsearch扫描，发现存在`/robots.txt`，访问该文件，回显为

```
User-agent: *
Disallow: /resusl.php
```

发现它不允许访问`/resusl.php`，访问一下，出现`Warning:你不是管理员你的IP已经被记录到日志了`

```
By bugkuctf.
if ($_GET[x]==$password) 此处省略1w字
```

IP被ban，以为要改XFF头伪造IP(但是后来发现这里不用改)，而这里的password可以爆破得到，但其实题目的描述“好像需要管理员”，还有“Warning:你不是管理员”，已经提示你`x=admin`，用hackbar传参，就能拿到flag

# web32

一道普通的文件上传，“My name is margin,give me a image file not a php”，不能上传php文件，写一句话木马的文件，将后缀改为`.jpg`，发现上传成功，并且给了路径，但此时并不能蚁剑直连。

BP抓包，尝试将后缀改回`.php`，发现不行，并不是客户端验证。

直接上传php文件抓包，改后缀不能上传成功，回显为“You was catched! :)”，对比之下，发现请求数据的`Content-Type`有区别，这个参数应该改为`image/jpeg`，再尝试一些后缀名的绕过，例如`.php1`，`.php2`等，但发现还是不行，实在没什么思路，去看了WP，请求头部中的`Content-Type`竟然也要改，大小写绕过`muLTIpart/form-data`，然后后缀改为`.php4`，成功上传，蚁剑直连，在根目录下找到flag，拿到源码分析一下刚才操作的原理

```php
<?php
function global_filter(){
	$type =  $_SERVER["CONTENT_TYPE"];
	if (strpos($type,"multipart/form-data") !== False){
	//这是为什么请求头中的Content-Type需要大小写绕过
		$file_ext =  substr($_FILES["file"]["name"], strrpos($_FILES["file"]["name"], '.')+1);
        $file_ext = strtolower($file_ext);//截取后缀名并小写
		if (stripos($file_ext,"php") !== False){//过滤php后缀名
			die("Invalid File<br />");
		}
	}
}
?>

<?php
global_filter();
if ((stripos($_FILES["file"]["type"],'image')!== False) && ($_FILES["file"]["size"] < 10*1024*1024)){//判断Content-Type中是否有image和文件大小
	if ($_FILES["file"]["error"] == 0){
		$file_ext =  substr($_FILES["file"]["name"], strrpos($_FILES["file"]["name"], '.')+1);
        $file_ext = strtolower($file_ext);//截取后缀名并小写
        $allowexts = array('jpg','gif','jpeg','bmp','php4');//php4在白名单中，这是为什么能用php4作为后缀
        if(!in_array($file_ext,$allowexts)){//判断在不在白名单
            die("give me a image file not a php");
        }
		$_FILES["file"]["name"]="bugku".date('dHis')."_".rand(1000,9999).".".$file_ext;
	    if (file_exists("upload/" . $_FILES["file"]["name"])){
	    	echo $_FILES["file"]["name"] . " already exists. <br />";
	    }
	    else{
	    	if (!file_exists('./upload/')){
	    		mkdir ("./upload/");
                system("chmod 777 /var/www/html/upload");
	    	}
	    	move_uploaded_file($_FILES["file"]["tmp_name"],"upload/" . $_FILES["file"]["name"]);
                echo "Upload Success<br>";
                $filepath = "upload/" . $_FILES["file"]["name"];
	      	echo "Stored in: " ."<a href='" . $filepath . "' target='_blank'>" . $filepath . "<br />";
	    }
	}
}
else{
	if($_FILES["file"]["size"] > 0){
		echo "You was catched! :) <br />";
	}
}
```

# web33

描述为“fR4aHWwuFCYYVydFRxMqHhhCKBseH1dbFygrRxIWJ1UYFhotFjA=”，下载附件，是一段php源码，如下

```php
<?php
function encrypt($data,$key)
{
    $key = md5('ISCC');//密钥
    $x = 0;
    $len = strlen($data);//明文长度
    $klen = strlen($key);
    for ($i=0; $i < $len; $i++) { 
        if ($x == $klen)
        {
            $x = 0;
        }
        $char .= $key[$x];//在密钥中取$len个值
        $x+=1;
    }
    for ($i=0; $i < $len; $i++) {
        $str .= chr((ord($data[$i]) + ord($char[$i])) % 128);
    }
    return base64_encode($str);
}
?>
```

这个属于一个对称加密(单密钥加密)，写一个逆向解密的脚本(实在是不太会写，要去好好学习一下)

```php
<?php
function decrypt($data,$key)
{
    $data = 'fR4aHWwuFCYYVydFRxMqHhhCKBseH1dbFygrRxIWJ1UYFhotFjA=';//密文
    $data = base64_decode($data);
    $key = md5('ISCC');
    $x = 0;
    $len = strlen($data);
    $klen = strlen($key);
    for ($i=0; $i <$len; $i++){
        if ($x == $klen)
        {
            $x = 0;
        }
        $char .= $key[$x];
        $x++;
    }
    for ($i=0; $i < $len; $i++){
        if (ord($data[$i]) < ord($char[$i]))
        {
            $str .= chr((ord($data[$i]) + 128) - ord($char[$i]));
        }
        else
        {
            $str .= chr(ord($data[$i]) - ord($char[$i]));
        }
    }
    return $str;
}
?>
```

