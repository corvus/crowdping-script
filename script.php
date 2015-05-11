<?php

/* ******************************************** */
/*   Copyright: ZWEISCHNEIDER DIGITALSCHMIEDE   */
/*         http://www.zweischneider.de          */
/* ******************************************** */

if(!empty($_REQUEST['url']) && !empty($_REQUEST['security'])) {
    date_default_timezone_set('UTC');

    $check = false;
    for($i=time(); $i>=(time()-15); $i--) {
        if($_REQUEST['security'] == md5($i.'%cryptethash%')) {
            $check = true;
            break;
        }
    }

    if(!$check) {
        header('HTTP/1.0 404 Not Found');
        die;
    }

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

    echo 'crowdping_script';
} else {
    header('HTTP/1.0 404 Not Found');
    die;
}
