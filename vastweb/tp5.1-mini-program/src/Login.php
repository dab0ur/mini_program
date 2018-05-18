<?php
/**
 * Created by PhpStorm.
 * User: lenovo
 * Date: 2018/5/18
 * Time: 10:20
 */
use think\Mini_program;
use thin\Db;
use think\facade\Config;
use think\facade\Request;
//数据库
/*
DROP TABLE IF EXISTS `mini_sessions`;
CREATE TABLE `mini_sessions` (
`id` int(11) NOT NULL AUTO_INCREMENT,
  `skey` varchar(255) NOT NULL,
  `session_key` varchar(255) NOT NULL,
  `user_info` varchar(255) NOT NULL,
  `create_time` int(11) NOT NULL,
  `last_visit_time` int(11) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
*/


class Login
{
    /**
     * @var object 对象实例
     */
    protected static $instance;


    //默认配置
    protected $config = [
        'AppId' => '',//小程序id
        'AppSecret' => '',//小程序密钥
        'WxLoginExpires' => 7200,// 微信登录态有效期
        'timeout' => 3000,// 网络请求超时时长（单位：毫秒）
        'info' => 'sessions', // 存储用户信息的表
    ];

    //初始化配置
    public function __construct()
    {
        //可设置配置项 auth, 此配置项为数组。
        if ($Mini_program = Config::get('Mini_program')) {
            $this->config = array_merge($this->config, $Mini_program);
        }

    }

    /**
     * 初始化
     * @access public
     * @param array $options 参数
     * @return \think\Request
     */
    public static function instance($options = [])
    {
        if (is_null(self::$instance)) {
            self::$instance = new static($options);
        }
        return self::$instance;
    }

    /**
     * 用户登录接口
     * @param {string} $code        wx.login 颁发的 code
     * @param {string} $encryptData 加密过的用户信息
     * @param {string} $iv          解密用户信息的向量
     * @return {array} { loginState, data }
     */
    public function login($code, $encryptedData, $iv)
    {
        // 1. 获取 session key
        $sessionKey = self::getSessionKey($code);

        // 2. 生成 3rd key (skey)
        $skey = sha1($sessionKey . mt_rand());

        /**
         * 3. 解密数据
         * 由于官方的解密方法不兼容 PHP 7.1+ 的版本
         * 这里弃用微信官方的解密方法
         * 采用推荐的 openssl_decrypt 方法（支持 >= 5.3.0 的 PHP）
         * @see http://php.net/manual/zh/function.openssl-decrypt.php
         */
        $decryptData = \openssl_decrypt(
            base64_decode($encryptData),
            'AES-128-CBC',
            base64_decode($sessionKey),
            OPENSSL_RAW_DATA,
            base64_decode($iv)
        );
        $userinfo = json_decode($decryptData);

        // 4. 储存到数据库中
        $data = [
            'skey' => $skey,
            'session_key' => $sessionKey,
            'user_info' => $user_info,
            'open_id' => $userinfo->openId,
            'create_time' => time(),
            'last_visit_time' => time(),
        ];
        $result = Db::name($this->config['info'])->where(['open_id' => $userinfo->openId])->find();
        if (!$result)
        {
            $res = Db::name($this->config['info'])->insertGetId($data);
            if ($res)
            {
                return json([
                    'loginState' => 1,
                    'data' => $data
                ]);
            }else{
                return json([
                    'loginState' => 0,
                    'data' => []
                ]);
            }
        }else{
            unset($data['create_time']);
            $res = Db::name($this->config['info'])->where(['open_id' => $userinfo->openId])->update($data);
            if ($res)
            {
                return json([
                    'loginState' => 1,
                    'data' => $data
                ]);
            }else{
                return json([
                    'loginState' => 0,
                    'data' => []
                ]);
            }
        }
    }


    //验证登录
    public function checkLogin($skey) {
        $userinfo = Db::name($this->config['info'])->where(['skey' => $skey])->find();
        if ($userinfo === NULL) {
            return json([
                'loginState' => 0,
                'userinfo' => []
            ]);
        }

        $wxLoginExpires = $this->config['WxLoginExpires'];
        $timeDifference = time() - strtotime($userinfo->last_visit_time);

        if ($timeDifference > $wxLoginExpires) {
            return json([
                'loginState' => 0,
                'userinfo' => []
            ]);
        } else {
            return json([
                'loginState' => 1,
                'userinfo' => json_decode($userinfo->user_info, true)
            ]);
        }
    }
    /**
     * 通过 code 换取 session key
     * @param {string} $code
     */
    public function getSessionKey ($code) {
            $appId = $this->config['AppId'];
            $appSecret = $this->config['AppSecret'];
            list($session_key, $openid) = array_values(self::getSessionKeyDirectly($this->config['AppId'], $this->config['AppSecret'], $code));
            return $session_key;
    }

    /**
     * 直接请求微信获取 session key
     * @param {string} $appId  小程序的 appId
     * @param {string} $appSecret 小程序的 appSecret
     * @param {string} $code
     * @return {array} { $session_key, $openid }
     */
    private function getSessionKeyDirectly ($appId, $appSecret, $code) {
        $requestParams = [
            'appid' => $appId,
            'secret' => $appSecret,
            'js_code' => $code,
            'grant_type' => 'authorization_code'
        ];

        list($status, $body) = array_values(self::send([
            'url' => 'https://api.weixin.qq.com/sns/jscode2session?' . http_build_query($requestParams),
            'timeout' => 3000,
            'method'  => 'GET'
        ]));

        if ($status !== 200 || !$body || isset($body['errcode'])) {
            return 0;
        }

        return $body;
    }

    public static function send($options) {
        $ch = curl_init();

        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $options['method']);
        curl_setopt($ch, CURLOPT_URL, $options['url']);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, FALSE);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, TRUE);

        if (isset($options['headers'])) {
            curl_setopt($ch, CURLOPT_HTTPHEADER, $options['headers']);
        }

        if (isset($options['timeout'])) {
            curl_setopt($ch, CURLOPT_TIMEOUT_MS, $options['timeout']);
        }

        if (isset($options['data'])) {
            curl_setopt($ch, CURLOPT_POSTFIELDS, $options['data']);
        }

        $result = curl_exec($ch);
        $status = curl_getinfo($ch, CURLINFO_HTTP_CODE);

        $body = json_decode($result, TRUE);
        if ($body === NULL) {
            $body = $result;
        }

        curl_close($ch);
        return compact('status', 'body');
    }

}