<?php
/* ******************************************** */
/*   Copyright: ZWEISCHNEIDER DIGITALSCHMIEDE   */
/*         http://www.zweischneider.de          */
/* ******************************************** */

const LOG_ENABLED = false; // true enables logging of incoming requests
const LOG_MAX_FILESIZE = 1024; // in KB
const LOG_MAX_FILES = 7;

/* ##################################################################################################### */
/* dont change anything below this line                                                                  */
/* ##################################################################################################### */

date_default_timezone_set('UTC');

class CrowdpingChecker {
    protected $_scriptInitTime = null;

    protected $_classVersion = '0.2'; // please update default useragent to match version
    protected $_secretKey = '%cryptethash%';
    protected $_urlApi = 'https://api.crowdping.net/1.0/load_times';

    protected $_log = array();
    protected $_logEnabled = false; // true enables logging
    protected $_logMaxFilesize = 1024; // in KB
    protected $_logMaxFiles = 7; // number of log files to keep

    protected $urlToCheck = null;
    protected $securityHash = null;
    protected $apiHash = null;

    private $_curlDefaultOptions = array(
        //CURLOPT_USERAGENT => 'Mozilla/5.0 (Windows NT 6.1; rv:31.0) Gecko/20100101 Firefox/31.0',
        CURLOPT_USERAGENT => 'crowdping/0.2',
        CURLOPT_CONNECTTIMEOUT => 3,
        CURLOPT_TIMEOUT => 60, // set this to X hours (in seconds) so we dont timeout on big files
        CURLOPT_IPRESOLVE => CURL_IPRESOLVE_WHATEVER, // change to CURL_IPRESOLVE_V4 or CURL_IPRESOLVE_V6 to resolve specific IP version addresses
    );

    /**
     * Class constructor
     *
     * @param array $settings Class specifiv settings
     */
    public function __construct(array $settings = array()) {
        $this->_scriptInitTime = time();

        foreach ($settings as $prop => $val) {
            if (property_exists($this, $prop)) {
                $this->{$prop} = $val;
            }
        }
    }

    /**
     * Class deconstructor
     */
    public function __destruct() {
        if ($this->_logEnabled === true) {
            $logFile = __FILE__ . '.log';
            $fp = @fopen($logFile, 'a');

            if ($fp !== false && @flock($fp, LOCK_EX)) {
                array_unshift($this->_log, date('c', $this->_scriptInitTime));
                $this->_log[] = '###############################################################';
                $logContent = implode(PHP_EOL, $this->_log) . PHP_EOL;

                if (@filesize($logFile) > $this->_logMaxFilesize * 1024) {
                    // rotate log files
                    for ($i = $this->_logMaxFiles; $i > 0; --$i) {
                        $rotateFile = $logFile . '.' . $i;
                        if (is_file($rotateFile)) {
                            if ($i === $this->_logMaxFiles) {
                                @unlink($rotateFile);
                            }
                            else {
                                @rename($rotateFile, $logFile . '.' . ($i + 1));
                            }
                        }
                    }

                    if (is_file($logFile)) {
                        @rename($logFile, $logFile . '.1');
                    }

                    @flock($fp, LOCK_UN);
                    @fclose($fp);
                    @file_put_contents($logFile, $logContent, FILE_APPEND | LOCK_EX);
                }
                else {
                    @fwrite($fp, $logContent);
                    @flock($fp, LOCK_UN);
                    @fclose($fp);
                }
            }
        }
    }

    /**
     * Merges two arrays.
     *
     * @param array $to Array to be merged to.
     * @param array $from Array to be merged from.
     * @return array The merged array.
     */
    public static function arrayMerge(array $to, array $from) {
        $args = func_get_args();
        $res = array_shift($args);

        while (!empty($args)) {
            $next = array_shift($args);

            foreach ($next as $k => $v) {
                if (is_integer($k)) {
                    isset($res[$k]) ? $res[] = $v : $res[$k] = $v;
                } elseif (is_array($v) && isset($res[$k]) && is_array($res[$k])) {
                    $res[$k] = self::arrayMerge($res[$k], $v);
                } else {
                    $res[$k] = $v;
                }
            }
        }

        return $res;
    }

    /**
     * Load url with curl
     *
     * @param string $url The url to load
     * @param array $curlOptions Curl specific options. Overrides default $this->_curlDefaultOptions
     *
     * @return array Assoc array with
     * <ul>
        <li>res: Content of the url if CURLOPT_RETURNTRANSFER=1 or false, otherwise true/false</li>
        <li>chErr: The error number or 0 (zero) if no error occurred.</li>
        <li>chInfo: Returns an associative array with the following elements (which correspond to opt): "url" "content_type" "http_code" "header_size" "request_size" "filetime" "ssl_verify_result" "redirect_count" "total_time" "namelookup_time" "connect_time" "pretransfer_time" "size_upload" "size_download" "speed_download" "speed_upload" "download_content_length" "upload_content_length" "starttransfer_time" "redirect_time"</li>
      </ul>
     */
    public function doCURL($url, $curlOptions = array()) {
        $curlOptions = self::arrayMerge($curlOptions, $this->_curlDefaultOptions);

        $ch = curl_init($url);
        curl_setopt_array($ch, $curlOptions);

        $res = curl_exec($ch);
        $chErr = curl_errno($ch);
        $chInfo = curl_getinfo($ch);
        curl_close($ch);

        return array(
            'res' => $res,
            'chErr' => $chErr,
            'chInfo' => $chInfo,
        );
    }

    /**
     * Set specific header and exit if requested
     *
     * @param int $code HTTP code to send
     * @param string $txt If empty, it will look correct message for each known http error code
     * @param bool $terminate Terminate application if not false, defaults to true
     */
    public function renderError($code, $txt = '', $terminate = true) {
        $httpCodes = array(
            100 => 'Continue',
            101 => 'Switching Protocols',
            102 => 'Processing',
            118 => 'Connection timed out',
            200 => 'OK',
            201 => 'Created',
            202 => 'Accepted',
            203 => 'Non-Authoritative',
            204 => 'No Content',
            205 => 'Reset Content',
            206 => 'Partial Content',
            207 => 'Multi-Status',
            210 => 'Content Different',
            300 => 'Multiple Choices',
            301 => 'Moved Permanently',
            302 => 'Found',
            303 => 'See Other',
            304 => 'Not Modified',
            305 => 'Use Proxy',
            307 => 'Temporary Redirect',
            310 => 'Too many Redirect',
            400 => 'Bad Request',
            401 => 'Unauthorized',
            402 => 'Payment Required',
            403 => 'Forbidden',
            404 => 'Not Found',
            405 => 'Method Not Allowed',
            406 => 'Not Acceptable',
            407 => 'Proxy Authentication Required',
            408 => 'Request Time-out',
            409 => 'Conflict',
            410 => 'Gone',
            411 => 'Length Required',
            412 => 'Precondition Failed',
            413 => 'Request Entity Too Large',
            414 => 'Request-URI Too Long',
            415 => 'Unsupported Media Type',
            416 => 'Requested range unsatisfiable',
            417 => 'Expectation failed',
            418 => 'I’m a teapot',
            422 => 'Unprocessable entity',
            423 => 'Locked',
            424 => 'Method failure',
            425 => 'Unordered Collection',
            426 => 'Upgrade Required',
            449 => 'Retry With',
            450 => 'Blocked by Windows Parental Controls',
            500 => 'Internal Server Error',
            501 => 'Not Implemented',
            502 => 'Bad Gateway ou Proxy Error',
            503 => 'Service Unavailable',
            504 => 'Gateway Time-out',
            505 => 'HTTP Version not supported',
            507 => 'Insufficient storage',
            509 => 'Bandwidth Limit Exceeded',
        );

        if (empty($txt) && isset($httpCodes[$code])) { $txt = $httpCodes[$code]; }
        header((isset($_SERVER['SERVER_PROTOCOL']) ? $_SERVER['SERVER_PROTOCOL'] : 'HTTP/1.0') . " {$code} " . $txt);

        $this->log('[renderError] ' . $code . ' - ' . $txt);

        if ($terminate) {
            exit(0);
        }
    }

    /**
     * Add messages to log ; accepts mixed params
     */
    public function log(/* poly */) {
        $args = func_get_args();
        if (empty($args)) { return; }

        foreach ($args as $arg) {
            $this->_log[] = (is_string($arg) || is_numeric($arg)) ? $arg : trim(print_r($arg, true));
        }
    }

    /**
     * Print out current log entries
     */
    public function printLog() {
        var_dump($this->_log);
    }

    /**
     * Validate security hash with secret key
     *
     * @return bool
     */
    protected function validateSecurityHash() {
        for ($i = time(); $i >= (time() - 15); $i--) {
            if ($this->securityHash == md5($i . $this->_secretKey)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Are we allowed to check the specified url?
     *
     * @return bool
     */
    protected function urlCheckable() {
        $checkable = false;
        $urlParts = parse_url($this->urlToCheck);

        if ($urlParts == false || !array_key_exists('host', $urlParts)) {
            $this->log('ERROR: Invalid url');
        }
        else {
            $stateFile = __FILE__ . '.state';
            $fp = @fopen($stateFile, 'a+');

            if ($fp !== false && @flock($fp, LOCK_EX)) {
                $stateData = @unserialize(@file_get_contents($stateFile));
                if ($stateData === false) {
                    // unserialize failed => create default array
                    $stateData = array(
                        'times' => array(
                            $urlParts['host'] => 0,
                        ),
                    );
                }

                if (is_array($stateData)) {
                    if (time() - $stateData['times'][$urlParts['host']] > 30) { // min seconds between next request to host
                        $checkable = true;
                        $stateData['times'][$urlParts['host']] = time();
                        @file_put_contents($stateFile, serialize($stateData)); // save new state
                    }
                    else {
                        $this->log('WARNING: min time between requests not passed');
                    }
                }

                @flock($fp, LOCK_UN);
                @fclose($fp);
            }
        }

        return $checkable;
    }

    /**
     * Check if specified url is reachable and check some stuff
     *
     * @return array Assoc array
     */
    protected function checkUrl() {
        $return = array();
        $start = microtime(true);

        $curlOptions = array(
            CURLOPT_FRESH_CONNECT => true,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CONNECTTIMEOUT => 30,
            CURLOPT_TIMEOUT => 30,
            CURLOPT_SSL_VERIFYPEER => false,
        );

        // GET CONTENT OF WEBSITE
        $curl = $this->doCURL($this->urlToCheck, $curlOptions);

        $content = $curl['res'];
        $return['http_code'] = $curl['chInfo']['http_code'];

        // LOAD ALL SOURCES FROM WEBSITE
        preg_match_all('/src=(["\']?)([^\1]+?)\1/m', $content, $result, PREG_PATTERN_ORDER);
        $result = $result[2];
        preg_match_all('/background(-image)??\s*?:.*?url\(["|\']??(.+)["|\']??\)/', $content, $result2, PREG_PATTERN_ORDER);

        foreach ($result2[2] AS $val) {
            $result[] = $val;
        }
        $headers = array(
            'Cache-Control: no-cache',
        );

        do {
            $init_array = array();
            $mh = curl_multi_init();
            $count = 0;
            foreach ($result as $key => $src) {
                if (strpos($src, '//') === false) {
                    $url = $this->urlToCheck . $src;
                } else {
                    $url = $src;
                }

                if (strpos($url, '//') == 0) {
                    $url = 'http:' . $url;
                }

                $init_array[$key] = curl_init();
                curl_setopt($init_array[$key], CURLOPT_URL, $url);
                curl_setopt($init_array[$key], CURLOPT_FRESH_CONNECT, true);
                curl_setopt($init_array[$key], CURLOPT_RETURNTRANSFER, true);
                curl_setopt($init_array[$key], CURLOPT_HTTPHEADER, $headers);
                curl_setopt($init_array[$key], CURLOPT_CONNECTTIMEOUT, 30);
                curl_setopt($init_array[$key], CURLOPT_TIMEOUT, 30);
                curl_multi_add_handle($mh, $init_array[$key]);
                unset($result[$key]);
                $count++;

                if ($count > 9) {
                    break;
                }
            }

            $running = null;
            do {
                curl_multi_exec($mh, $running);
            } while ($running > 0);

            foreach ($init_array AS $key => $val) {
                curl_multi_remove_handle($mh, $init_array[$key]);
            }
            curl_multi_close($mh);
        } while (count($result) > 0);

        $total = microtime(true) - $start;
        $return['complete_loading_time'] = $total;

        return $return;
    }

    /**
     * Send data to crowdping api
     *
     * @param array $data
     */
    protected function pushToApi(array $data) {
        $return = array();
        $return['hash'] = $this->apiHash;
        $return['version'] = $this->_classVersion;

        $return = self::arrayMerge($return, $data);

        $headerArray = array('Content-Type: application/json');

        $curlOptions = array(
            CURLOPT_POST => 1,
            CURLOPT_HEADER => 0,
            CURLOPT_FRESH_CONNECT => true,
            CURLOPT_NOSIGNAL => 1,
            CURLOPT_CONNECTTIMEOUT => 1,
            CURLOPT_TIMEOUT => 1,
            CURLOPT_HTTPHEADER => $headerArray,
            CURLOPT_POSTFIELDS => json_encode($return),
        );

        // SEND NOTIFICATION TO CROWDPING
        $curl = $this->doCURL($this->_urlApi, $curlOptions);
    }

    /**
     * Do the fancy stuff :P
     *
     * @param string $urlToCheck
     * @param string $securityHash
     * @param string $apiHash
     *
     * @return bool
     */
    public function check($urlToCheck, $securityHash, $apiHash) {
        $this->urlToCheck = $urlToCheck;
        $this->securityHash = $securityHash;
        $this->apiHash = $apiHash;

        $this->log('urlToCheck:', $urlToCheck);
        $this->log('securityHash:', $securityHash);
        $this->log('apiHash:', $apiHash);

        if (!$this->validateSecurityHash()) {
            $this->log('ERROR: Security check failed');
            //$this->renderError(401);
        }

        if (!$this->urlCheckable()) {
            $this->log('ERROR: Url checkable not passed');
            $this->renderError(503);
        }

        $check = $this->checkUrl();
        if (!empty($check)) {
            $this->pushToApi($check);

            echo 'crowdping_script';
            return true;
        }
        else {
            $this->renderError(500);
        }
    }
}

$settings = array(
    '_logEnabled' => LOG_ENABLED,
    '_logMaxFilesize' => LOG_MAX_FILESIZE,
    '_logMaxFiles' => LOG_MAX_FILES,
);
$checker = new CrowdpingChecker($settings);

if (isset($_REQUEST['url'], $_REQUEST['security'], $_REQUEST['hash'])) {
    if ($checker->check($_REQUEST['url'], $_REQUEST['security'], $_REQUEST['hash'])) {
        exit(0); // done
    }
}

// as default we render an error
$checker->renderError(400);
