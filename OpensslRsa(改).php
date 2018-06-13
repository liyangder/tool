<?php
class OpensslRSA{


    private $private_key;
    private $public_key;

    private $pi_key;
    private $pu_key;

    //判断公钥和私钥是否可用
    public function __construct()
    {

//        $this->pi_key =  openssl_pkey_get_private($this->private_key);//这个函数可用来判断私钥是否是可用的，可用返回资源id Resource id
//        $this->pu_key = openssl_pkey_get_public($this->public_key);//这个函数可用来判断公钥是否是可用的

    }


    /**
     * 生成公私钥
     */
    public function create_key()
    {
        $resource = openssl_pkey_new(['private_key_bits' => 1024]);
        openssl_pkey_export($resource, $this->private_key);
        $detail = openssl_pkey_get_details($resource);
        $this->public_key = $detail['key'];


        return ['pub' => $this->public_key,'pri' => $this->private_key];

    }



    //私钥加密

    public function PrivateEncrypt($data){
        $crypto = '';
        foreach (str_split($data, 117) as $chunk) {
            openssl_private_encrypt($chunk, $encryptData, $this->pi_key);
            $crypto .= $encryptData;
        }
        $encrypted = $this->urlsafe_b64encode($crypto);//加密后的内容通常含有特殊字符，需要编码转换下，在网络间通过url传输时要注意base64编码是否是url安全的
        return $encrypted;
    }
    //加密码时把特殊符号替换成URL可以带的内容
    function urlsafe_b64encode($string) {
        $data = base64_encode($string);
        $data = str_replace(array('+','/','='),array('-','_',''),$data);
        return $data;
    }

    //解密码时把转换后的符号替换特殊符号
    function urlsafe_b64decode($string) {
        $data = str_replace(array('-','_'),array('+','/'),$string);
        $mod4 = strlen($data) % 4;
        if ($mod4) {
            $data .= substr('====', $mod4);
        }
        return base64_decode($data);
    }

    //私钥加密的内容通过公钥可用解密出来
    public function PublicDecrypt($encrypted){
        $crypto = '';
        foreach (str_split($this->urlsafe_b64decode($encrypted), 128) as $chunk) {
            openssl_public_decrypt($chunk, $decryptData, $this->pu_key);
            $crypto .= $decryptData;
        }
        //openssl_public_decrypt($encrypted,$decrypted,$this->pu_key);//私钥加密的内容通过公钥可用解密出来
        return $crypto;
    }

    //公钥加密
    public function PublicEncrypt($data,$pub_key){
        //openssl_public_encrypt($data,$encrypted,$this->pu_key);//公钥加密
        $this->public_key = $pub_key;
        $this->pu_key = openssl_pkey_get_public($this->public_key);

        $crypto = '';
//        echo $data.'<hr>';
//        $data  = hex2bin($data);

        foreach (str_split($data, 117) as $chunk) {
            $chunk=bin2hex($chunk);
            $chunk=hex2bin(str_pad($chunk,256,0,STR_PAD_LEFT));
            openssl_public_encrypt($chunk, $encryptData, $this->pu_key,OPENSSL_NO_PADDING);

            $crypto .= $encryptData;

        }
//        $encrypted = $this->urlsafe_b64encode($crypto);
        $encrypted = bin2hex($crypto);
        return $encrypted;
    }

    //私钥解密
    public function PrivateDecrypt($encrypted,$parivate_key)
    {
        $this->private_key = $parivate_key;
        $this->pi_key =  openssl_pkey_get_private($this->private_key);

        $crypto = '';
        //转换为2进制;
//        foreach (str_split($this->urlsafe_b64decode($encrypted), 128) as $chunk) {
        foreach (str_split(hex2bin($encrypted), 128) as $chunk) {
            openssl_private_decrypt($chunk, $decryptData, $this->pi_key,OPENSSL_NO_PADDING);

            $decryptData=bin2hex($decryptData);


            $decryptData = preg_replace('/^0+/','',$decryptData);

            if (strlen($decryptData)%2==1){
                $decryptData = hex2bin('0'.$decryptData);
            }else{
                $decryptData = hex2bin($decryptData);
            }

            $crypto .= $decryptData;
        }

        return $crypto;
//        return base64_encode($crypto);
    }


}