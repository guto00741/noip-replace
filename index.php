<?php
if (!isset($_SERVER['PHP_AUTH_USER'])) {
    header('WWW-Authenticate: Basic realm="My Realm"');
    header('HTTP/1.0 401 Unauthorized');
    echo 'badauth'.PHP_EOL;
    exit;
}

require __DIR__ . '/vendor/autoload.php';

$user_name =  $_SERVER['PHP_AUTH_USER'];

// Alguns routers cortam a senha,
// pois possui um limite de 24 chars
// nesse caso vc pode travar uma senha aqui
$api_key =  $_SERVER['PHP_AUTH_PW'];

$key     = new Cloudflare\API\Auth\APIKey($user_name, $api_key);
$adapter = new Cloudflare\API\Adapter\Guzzle($key);

$zones = new Cloudflare\API\Endpoints\Zones($adapter);
$dns = new Cloudflare\API\Endpoints\DNS($adapter);

$subdomain = strtolower(trim($_GET['hostname']));
$newIP = strtolower(trim($_GET['myip']));

$subParts = explode('.',$subdomain);

if(count($subParts) >=3 ){
    $sub_part = $subParts[0];
    unset($subParts[0]);
    $domain = implode('.',$subParts);
}else{
    echo 'nohost'.PHP_EOL;
    exit;
}

$zone = $zones->listZones($domain);

if($zone->result_info->count){
    $zone_id = $zone->result[0]->id;
}else{
    echo 'nohost'.PHP_EOL;
    exit;
}

$dns_entry = $dns->listRecords($zone_id,'A',$sub_part.'.'.$domain);

if($dns_entry->result_info->count){
    $dns_record = $dns_entry->result[0];
}else{
    echo 'nohost'.PHP_EOL;
    exit;
}

if($dns_record->content == $newIP){
    echo 'nochg '.$newIP.PHP_EOL;
    exit;
}else{
    $dns->updateRecordDetails($zone_id,$dns_record->id,['name'=>$dns_record->name,'type'=>$dns_record->type,'content'=>$newIP,'ttl'=>$dns_record->ttl]);
    echo "good ".$newIP.PHP_EOL;
    exit;
}