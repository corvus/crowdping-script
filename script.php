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

$log = array();
$log[] = date('c');

if (!empty($_REQUEST['url']) && !empty($_REQUEST['security'])) {
    $log[] = 'INFO: $_REQUEST';
    $log[] = trim(print_r($_REQUEST, true));

    $check = false;
    for ($i=time(); $i>=(time()-15); $i--) {
        if ($_REQUEST['security'] == md5($i.'%cryptethash%')) {
            $check = true;
            break;
        }
    }

    if (!$check) {
        $log[] = 'ERROR: Security check failed';
        header((isset($_SERVER["SERVER_PROTOCOL"]) ? $_SERVER["SERVER_PROTOCOL"] : 'HTTP/1.0') . ' 404 Not Found');
    } else {
        $doCheck = false;
        $urlParts = parse_url($_REQUEST['url']);

        if ($urlParts == false || !array_key_exists('host', $urlParts)) {
            $log[] = 'ERROR: Invalid url';
        } else {
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
                        $doCheck = true;
                        $stateData['times'][$urlParts['host']] = time();
                        @file_put_contents($stateFile, serialize($stateData)); // save new state
                    } else {
                        header((isset($_SERVER["SERVER_PROTOCOL"]) ? $_SERVER["SERVER_PROTOCOL"] : 'HTTP/1.0') . ' 503 Service Unavailable');
                        $log[] = 'WARNING: min time between requests not passed';
                    }
                }

                @flock($fp, LOCK_UN);
                @fclose($fp);
            }
        }

        if ($doCheck) {
            // GET CONTENT OF WEBSITE
            $total = 0;
            $start = microtime(true);
            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, $_REQUEST['url']);
            curl_setopt($ch, CURLOPT_FRESH_CONNECT, true);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 30);
            curl_setopt($ch, CURLOPT_TIMEOUT, 30);
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
            $content = curl_exec($ch);
            $getInfo = curl_getinfo($ch);
            curl_close($ch);

            $return['http_code'] = $getInfo['http_code'];

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
                        $url = $_REQUEST['url'] . $src;
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

            // SEND NOTIFICATION TO CROWDPING
            $return['hash'] = $_REQUEST['hash'];
            $return['version'] = '0.2';
            $ch = curl_init();
            curl_setopt($ch, CURLOPT_POST, 1);
            curl_setopt($ch, CURLOPT_HEADER, 0);
            curl_setopt($ch, CURLOPT_URL, 'https://api.crowdping.net/1.0/load_times');
            curl_setopt($ch, CURLOPT_FRESH_CONNECT, true);
            curl_setopt($ch, CURLOPT_NOSIGNAL, 1);
            curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 1);
            curl_setopt($ch, CURLOPT_TIMEOUT, 1);
            $headerArray = array('Content-Type: application/json');
            curl_setopt($ch, CURLOPT_HTTPHEADER, $headerArray);
            curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($return));
            curl_exec($ch);
            curl_close($ch);

            $log[] = 'INFO: success';

            echo 'crowdping_script';
        }
    }
} else {
    header((isset($_SERVER["SERVER_PROTOCOL"]) ? $_SERVER["SERVER_PROTOCOL"] : 'HTTP/1.0') . ' 404 Not Found');
}

if (LOG_ENABLED === true && count($log) > 1) {
    $logFile = __FILE__ . '.log';
    $fp = @fopen($logFile, 'a');

    if ($fp !== false && @flock($fp, LOCK_EX)) {
        $log[] = '###############################################################';
        $logContent = implode(PHP_EOL, $log) . PHP_EOL;

        if (@filesize($logFile) > LOG_MAX_FILESIZE * 1024) {
            // rotate log files
            for ($i = LOG_MAX_FILES; $i > 0; --$i) {
                $rotateFile = $logFile . '.' . $i;
                if (is_file($rotateFile)) {
                    if ($i === LOG_MAX_FILES) {
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
