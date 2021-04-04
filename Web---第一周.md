# Web---第一周

## 1、ctfshow萌新web1-15

学到了一些PHP代码的函数绕过。

1、进制转换

(1)二进制：0b1111101000

(2)十六进制：0x38e

2、字节操作

(1)两次取反：~~1000

(2)异或：200^800

(3)按位与：992|8

3、运算符

(1)加减乘除：200*5  10/0.01  200-80  200+800

(2)负负：--1000

4、绕过函数

intval(mixed $value)会从$value的起始位置取数字碰到非数字就结束。例如，`intval('100a123')=100 intval('a123')=0`

## 2、github上学习信息泄露

有关备份文件的知识

1、常见的网站源码备份文件后缀：tar，tar.gz，zip，rar

常见的网站源码备份文件名：web，website，backup，back，www，wwwroot，temp

2、vim缓存<!--vim是一个文本编辑器-->：vim中的swp是隐藏文件，这个文件是一个临时交换文件，用来备份缓冲区中的内容。`.swp`是隐藏文件，因此最前面有`.` ，即`.index.php.swp`，注意index前面的点。`vim -r` 可以查看当前目录下所有的swp文件。`vim -r filename`可以恢复文件，这样上次意外退出没有保存的修改，就会覆盖文件。

3、`.DS_Store `是 Mac OS 保存文件夹的自定义属性的隐藏文件。通过`.DS_Store`可以知道这个目录里面所有文件的清单。

4、git泄露：使用GitHack工具，命令`python GitHack.py (url)/.git`，重建还原工程源代码

git命令：`git log`查看版本  `git reset` 切换版本  `git diff `比较文件的不同`git clone` 拷贝一个git仓库

`stash`：用于临时保存和回复修改    `git stash list`: 所有保存的记录列表

`git stash pop`: 恢复之前缓存的工作目录，将缓存堆栈中的对应stash删除，并将对应修改应用到当前的工作目录下

Git本地库中的索引Index就是一个二进制文件,是暂存区，用`git checkout-index`命令将从索引(暂存区)中列出的所有文件复制到工作目录

## 3、红明谷的比赛的收获

虽然红明谷的比赛没有做出来题目，但是看了别的师傅的WP，收获了一些东西。

1、write_shell

本道题过滤了";"和"php"，所以写一个完整的php代码不行，所以这里要用php的短标签绕过";"(以前不知道，现在学到了)

2、happysql

首先学到了一些sql的一些绕过，`=`用`in`或者`regexp`进行绕过,空格用`/**/`绕过，`or`可以用`||`替换，绕过`information_schema`，用`mysql.innodb_table_stats`，还有就是要去学习一下布尔盲注的脚本怎么写了

