<?php

class  OpensslRSA{
        //echo $private_key 私钥;
       public $private_key = '-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQC+L7ENzBHxKOqjuFHPFKlAt40BatVZhUAHw/G05XshpTGqm9Rv
8wG0EAbFbdo9PuB8DiXdPQLyIfaqkTgpsPjJ1Ow7WKxmYbqZN5IW/GN+TyFWP+MB
2W6IBLPWBDvAl2NJlmU8j3LCPJW1dH4zP1OitkxZMyUuUYYfPuOtO9RJ2wIDAQAB
AoGAUFCbmJQBT7JTxGfmRGkZQLdC2MJg7rkS3TSmMhpm8UJtwvqjr9MTeRL7iQxn
CU4wRrNC0jcds1sca9N/wDt4FCkCala+bg7mwQuPpg5QhXelfFr88ibRnP8y8LmZ
7PPNqx9c4jivhMzJrzNh3luqg6awjsig2w3+EW1/Ubb30AECQQDshTvyc5mpDgiO
4g8q1ztszszL9eCp+IjlUaN51vC3Nj1eXpjbtdSZ0JVKrDdhKcd3rEZVYzMQN/lI
pyq85e/bAkEAzdmN6TF3Y1h3LouumCy6+61ChTFrl/yjw13CGApmAQHhEVyANHr7
NjoxP06eimzn7KHff/eYxd1Emf1SYA8uAQJBAN1ibFUpLRgXAZ20LNw9r+rNutXi
ZJLUBlcXTjv6G0ByLYkKZGuqy7/ZhBPsFL4GnCUBBKhh/ObebaA6kH9VfmcCQGfg
0WxMOiM4EWy7sG+6ouE+ncL5HYKlSz7boYbgOHlpqVpJg6j4Jq1G0HNSCU9xhdg0
F8VL/RxcfLH41AkFoAECQQCR8NDB3BgHqyJfarKKMWQ3qrXHaLfBKExMrpQ8MDzs
MlSBzFOnucufo110lSgjdRlgr8smtU2hx9gXFIqxvfWF
-----END RSA PRIVATE KEY-----';
       //公钥
        public $public_key = '-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC+L7ENzBHxKOqjuFHPFKlAt40B
atVZhUAHw/G05XshpTGqm9Rv8wG0EAbFbdo9PuB8DiXdPQLyIfaqkTgpsPjJ1Ow7
WKxmYbqZN5IW/GN+TyFWP+MB2W6IBLPWBDvAl2NJlmU8j3LCPJW1dH4zP1OitkxZ
MyUuUYYfPuOtO9RJ2wIDAQAB
-----END PUBLIC KEY-----';

        public $pi_key;
        public $pu_key;

        //判断公钥和私钥是否可用
        public function __construct()
        {
            $this->pi_key =  openssl_pkey_get_private($this->private_key);//这个函数可用来判断私钥是否是可用的，可用返回资源id Resource id
            $this->pu_key = openssl_pkey_get_public($this->public_key);//这个函数可用来判断公钥是否是可用的

        }

        //私钥加密
        /*public function PrivateEncrypt($data){
            openssl_private_encrypt($data,$encrypted,$this->pi_key);
            $encrypted = $this->urlsafe_b64encode($encrypted);//加密后的内容通常含有特殊字符，需要编码转换下，在网络间通过url传输时要注意base64编码是否是url安全的
            return $encrypted;
        }*/

        public function PrivateEncrypt($data){
           // openssl_private_encrypt($data,$encrypted,$this->pi_key);
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
           // $encrypted = $this->urlsafe_b64decode($encrypted);
            $crypto = '';
            foreach (str_split($this->urlsafe_b64decode($encrypted), 128) as $chunk) {
                openssl_public_decrypt($chunk, $decryptData, $this->pu_key);
                $crypto .= $decryptData;
            }
            //openssl_public_decrypt($encrypted,$decrypted,$this->pu_key);//私钥加密的内容通过公钥可用解密出来
            return $crypto;
        }

        //公钥加密
        public function PublicEncrypt($data){
            //openssl_public_encrypt($data,$encrypted,$this->pu_key);//公钥加密
            $crypto = '';
            foreach (str_split($data, 117) as $chunk) {
                openssl_public_encrypt($chunk, $encryptData, $this->pu_key);
                $crypto .= $encryptData;
            }
            $encrypted = $this->urlsafe_b64encode($crypto);
            return $encrypted;
        }

        //私钥解密
        public function PrivateDecrypt($encrypted)
        {
            $crypto = '';
            foreach (str_split($this->urlsafe_b64decode($encrypted), 128) as $chunk) {
                openssl_private_decrypt($chunk, $decryptData, $this->pi_key);
                $crypto .= $decryptData;
            }
            //$encrypted = $this->urlsafe_b64decode($encrypted);
            //openssl_private_decrypt($encrypted,$decrypted,$this->pi_key);
            return $crypto;
        }


}