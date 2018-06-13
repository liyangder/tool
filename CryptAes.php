<?php
class CryptAES
{
    protected $cipher = MCRYPT_RIJNDAEL_128;
    protected $mode = MCRYPT_MODE_ECB;
    protected $pad_method = NULL;
    protected $secret_key = '';
    protected $iv = '';

    public function set_cipher($cipher)
    {
        $this->cipher = $cipher;
    }

    public function set_mode($mode)
    {
        $this->mode = $mode;
    }

    public function set_iv($iv)
    {
        $this->iv = $iv;
    }

    public function set_key($key)
    {
        $this->secret_key = $key;
    }

    public function require_pkcs5()
    {
        $this->pad_method = 'pkcs5';
    }

    protected function pad_or_unpad($str, $ext)
    {
        if ( is_null($this->pad_method) )
        {
            return $str;
        }
        else
        {
            $func_name = __CLASS__ . '::' . $this->pad_method . '_' . $ext . 'pad';
            if ( is_callable($func_name) )
            {
                $size = mcrypt_get_block_size($this->cipher, $this->mode);
                return call_user_func($func_name, $str, $size);
            }
        }
        return $str;
    }

    protected function pad($str)
    {
        return $this->pad_or_unpad($str, '');
    }

    protected function unpad($str)
    {
        return $this->pad_or_unpad($str, 'un');
    }

    public function encrypt($str)
    {
        $str = $this->pad($str);
        $td = mcrypt_module_open($this->cipher, '', $this->mode, '');

        if ( empty($this->iv) )
        {
            $iv = @mcrypt_create_iv(mcrypt_enc_get_iv_size($td), MCRYPT_RAND);
        }
        else
        {
            $iv = $this->iv;
        }

        mcrypt_generic_init($td, $this->secret_key, $iv);
        $cyper_text = mcrypt_generic($td, $str);
//        $rt=base64_encode($cyper_text);
        $rt = bin2hex($cyper_text);

//        $rt = preg_replace('/b31098667cca4250ceea3681a6959b17$/','',$rt);//保持兼容


        mcrypt_generic_deinit($td);
        mcrypt_module_close($td);

        return $rt;
    }

    public function ec($str)
    {
        $str = $this->pad($str);
        $td = mcrypt_module_open($this->cipher, '', $this->mode, '');

        if ( empty($this->iv) )
        {
            $iv = @mcrypt_create_iv(mcrypt_enc_get_iv_size($td), MCRYPT_RAND);
        }
        else
        {
            $iv = $this->iv;
        }

        mcrypt_generic_init($td, $this->secret_key, $iv);
        $cyper_text = mcrypt_generic($td, $str);
        $rt=base64_encode($cyper_text);
//        $rt = bin2hex($cyper_text);

//        $rt = preg_replace('/b31098667cca4250ceea3681a6959b17$/','',$rt);//保持兼容


        mcrypt_generic_deinit($td);
        mcrypt_module_close($td);

        return $rt;

    }

    public function decrypt($str){
//        $str .='b31098667cca4250ceea3681a6959b17';//ios 兼容
        $td = mcrypt_module_open($this->cipher, '', $this->mode, '');

        if ( empty($this->iv) )
        {
            $iv = @mcrypt_create_iv(mcrypt_enc_get_iv_size($td), MCRYPT_RAND);
        }
        else
        {
            $iv = $this->iv;
        }

        mcrypt_generic_init($td, $this->secret_key, $iv);
        $decrypted_text = mdecrypt_generic($td, self::hex2bin($str));
//        $decrypted_text = mdecrypt_generic($td, base64_decode($str));

        $rt = $decrypted_text;
        mcrypt_generic_deinit($td);
        mcrypt_module_close($td);

        return $this->unpad($rt);
    }

    public static function hex2bin($hexdata) {
        $bindata = '';
        $length = strlen($hexdata);
        for ($i=0; $i < $length; $i += 2)
        {
            $bindata .= chr(hexdec(substr($hexdata, $i, 2)));
        }
        return $bindata;
    }

    public static function pkcs5_pad($text, $blocksize)
    {
        $pad = $blocksize - (strlen($text) % $blocksize);
        return $text . str_repeat(chr($pad), $pad);
    }

    public static function pkcs5_unpad($text)
    {
        $pad = ord($text{strlen($text) - 1});
        if ($pad > strlen($text)) return false;
        if (strspn($text, chr($pad), strlen($text) - $pad) != $pad) return false;
        return substr($text, 0, -1 * $pad);
    }
}


//$keyStr = '0000000000123456';//数据保险箱密码填10个零;
////原文前后拼上kisslock;
//$plainText = 'kisslockMIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAMDxx1/AtQUo/FEJ/zGv5yHyLd+26HHd0N9qTbFuWj04JY/YnytG68b8U4LE1HKPHAIr5XGCCbadmMDHpOzl2hGN6KfKz/yZ1/ultGYXGY5a4GVW3OawdwBnvy4CuN7HRCCcPtQ2JZrunxVp2xHWwAUIcM2SXtAbocKLWleJwNIdAgMBAAECgYEAg1HLzcr+KaXsnUd9jhbX7E3FlTcLW7yKFhVnDbU66+HUBuR76NubS9KfECjhI5tth7jSr/++lrEKr2LySF5knU9Wye+2CC1cCsrKt3XWiizmwzKh4DlOsa1FQ3RKbbOwn6AqWHn7pCRayAsqf2sx2VqwgTZqbeWZTQyLDhiIeeECQQD6Ym3p6QgTJCQt899OyNoioqNf7fKaeGP0D4uymwr519NyDy07StYSvvvHOZ19RSJXzEDvIiXWG8ByifLQ+ZgZAkEAxUWPaG9lOdXSsBvWN2v1reKVRsE04w2l6oj/teogycy5nATYWll8TB/ZgUhNmBIob6zR+WQjVGvlhCqa9dFapQJBAM23EyFMsbKwTf1nUcB0KyyrvVkysdGSOmUqZJeA5PqzBWm/6GS/rrTGLyzXPHrQ00+ZZHxU7QtFz88LYfGqL/kCQACaHb3r2Rs8E9CFxTmWEsHdFyeIH2kx+Xelw2ICvObgwRBA04gzDbYNwtQqLFJye70bgeiI7bKsQZ8Nojtt0CECQHyufQDa5UVwNZL8l7XpejEJ8Rd9YRgs9Tft5O3l0wS9u5WXWQ/1aPioQbUs75/3Lr1XiHCNNakHzg9sykIgwzE=kisslock';
//

//
////
//$keyStr='123456';
//$plainText='12345678abcdefgh';
//$aes =  new CryptAES();
//$aes->set_key($keyStr);
//$encText = $aes->encrypt($plainText);
//// $encText = '479126C98F19DC04EC20427E77462E89';
//$decString = $aes->decrypt($encText);
//
//echo $encText,"<hr>",$decString;
//
//die;

