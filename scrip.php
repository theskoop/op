<?php
while(true){
start:
$wait = 0;
//for($u=0;$u<3;$u++){
$upis = ["pythor@airtel"];
$u=0;
$mail = random(5);
$ip = 14.98.'.'.mt_rand(10,255).'.'.mt_rand(10,255);
$dom = "oosln.com";
$email = $mail."@".$dom;
$gad = uuid();
$did = random(10);
//sendotp
$reg1 = sendotp($email,$gad,$did);

echo $iid = json_decode($reg1)->installationId;
if(empty($iid)){goto start;}
echo "\n";

//getotp
getmail:
$getMail = http("https://www.1secmail.com/api/v1/?action=getMessages&login=$mail&domain=$dom",[]);
$getMail = json_decode($getMail,1);
if($wait>=10){goto start;}
if(empty($getMail)){sleep(2);$wait+=2;goto getmail;}

foreach($getMail as $m){
    $id = $m['id'];
    $u2 = "https://www.1secmail.com/api/v1/?action=readMessage&domain=$dom&login=$mail&id=$id";
    $msg = json_decode(http($u2,[]),1)['htmlBody'];
    $otp = substr($msg,0,4);
}

//verify
$reg2 = verify($iid,$otp);

$s = json_decode($reg2,1);
echo $status = $s['message'];//VERIFIED_SUCCESS_MSG
$uid = $s['userId'];
$token = $s['token'];
echo "\n";


for($i=1;$i<=3;$i++){
if($i==1){ $t2=time()-86400*2;}
if($i==2){ $t2=time()-86400*1;}
if($i==3){ $t2=time();}
$t1=$t2-620;
echo task($token,$uid,$t1);
echo "\n";
echo task2($token,$uid,$t2);
echo "\n\n";
//}
sleep(2);
}

echo "Rs ". $rew = json_decode(reward($token,$uid))->wallet->walletMoney;

echo "\n\n";
$upi = "pythor@airtel";
echo redeem($upi,$token,$uid);

echo "\n\n";
file_put_contents("data.txt","$mail|$uid|$token\n",FILE_APPEND);

}
function sendotp($email,$gad,$did){
    global $ip;
$u = 'https://api.kooapp.com/registration-v2';
$h = ["Host: api.kooapp.com","version: android 0.98.8","migration_ver: 2","user_id: ","primarylanguage: hi","defaultlanguage: ","feedlanguages: ","app_version_code: 293","shield_id: d15185ecd064453f9ce34697c212cd4b","content-type: application/json; charset=UTF-8","user-agent: okhttp/4.9.3"];
$d = '{"accessorId":null,"appVersion":"0.98.8","authCheckType":1,"autoLoginProfile":null,"captchaKey":"","communicationEnablePreferences":{"whatsappCommunicationEnabled":true},"correlationId":null,"countryCode":91,"deviceId":"'.$did.'","deviceModel":"Redmi Note 5 Pro","deviceOs":"ANDROID","emailType":0,"feedLanguages":null,"googleAdId":"'.$gad.'","identifier":"'.$email.'","imei":"","lang":"hi","manufacturer":"Xiaomi","osVersion":"O_MR1","otpVersion":1,"password":null,"phone":"","userAcquisitionPlatform":"google-play","primaryLanguage":"hi","pushToken":null,"registerType":1,"source":null,"statusMinus1":0,"userId":null,"userToken":null,"utmParams":"utm_source=google-play&utm_medium=organic","versionCode":"293"}';
$res = http($u,$h,'POST',$d);
return $res;
}


function verify($iid,$otp){
$u = 'https://api.kooapp.com/registration-v2/verify';
$h = ["Host: api.kooapp.com","version: android 0.98.8","migration_ver: 2","user_id: ","primarylanguage: hi","defaultlanguage: ","feedlanguages: ","app_version_code: 293","shield_id: d15185ecd064453f9ce34697c212cd4b","content-type: application/json; charset=UTF-8","user-agent: okhttp/4.9.3"];
$d = '{"countryCode":91,"otp":"'.$otp.'","phone":"","registerType":1,"source":"","userId":"","userRegistrationId":'.$iid.'}';
$res = http($u,$h,'POST',$d);
return $res;
}


function task($token,$uid,$ts){
    global $ip;
$u = "https://api.kooapp.com/rewards";
$d = '{"type":0,"initiationTs":'.$ts.',"completedValues":{"timespentInMin":0}}';
$h = ['Host: api.kooapp.com','authorization: Bearer '.$token.'','version: android 0.98.8','app_version_code: 293','migration_ver: 2','user_id: '.$uid.'','primarylanguage: hi','feedlanguages: hi','shield_id: d15185ecd064453f9ce34697c212cd4b','content-type: application/json; charset=UTF-8','user-agent: okhttp/4.9.3'];
$res = http($u,$h,'POST',$d);
return $res;
}


function task2($token,$uid,$ts){
    global $ip;
$u = "https://api.kooapp.com/rewards";
$d = '{"type":1,"initiationTs":'.$ts.',"completedValues":{"timespentInMin":10}}';
$h = ['Host: api.kooapp.com','authorization: Bearer '.$token.'','version: android 0.98.8','app_version_code: 293','migration_ver: 2','user_id: '.$uid.'','primarylanguage: hi','feedlanguages: hi','shield_id: d15185ecd064453f9ce34697c212cd4b','content-type: application/json; charset=UTF-8','user-agent: okhttp/4.9.3'];
$res = http($u,$h,'POST',$d);
return $res;
}

function task3($token,$uid,$ts){
    global $ip;
$u = "https://api.kooapp.com/rewards";
$d = '{"type":1,"initiationTs":'.$ts.',"completedValues":{"timespentInMin":20}}';
$h = ['Host: api.kooapp.com','authorization: Bearer '.$token.'','version: android 0.98.8','app_version_code: 293','migration_ver: 2','user_id: '.$uid.'','primarylanguage: hi','feedlanguages: hi','shield_id: d15185ecd064453f9ce34697c212cd4b','content-type: application/json; charset=UTF-8','user-agent: okhttp/4.9.3'];
$res = http($u,$h,'POST',$d);
return $res;
}


function reward($token,$uid){
    global $ip;
$u = "https://api.kooapp.com/rewards";
$h = ['Host: api.kooapp.com','authorization: Bearer '.$token.'','version: android 0.98.8','app_version_code: 293','migration_ver: 2','user_id: '.$uid.'','primarylanguage: hi','feedlanguages: hi','shield_id: d15185ecd064453f9ce34697c212cd4b','content-type: application/json; charset=UTF-8','user-agent: okhttp/4.9.3'];
$res = http($u,$h);
return $res;
}


function valid($upi){
    global $ip;
$u = "https://api.kooapp.com/rewards/payments/validate";
$d = '{"vpa":"'.$upi.'}';
$h = ['Host: api.kooapp.com','authorization: Bearer '.$token.'','version: android 0.98.8','app_version_code: 293','migration_ver: 2','user_id: '.$uid.'','primarylanguage: hi','feedlanguages: hi','shield_id: d15185ecd064453f9ce34697c212cd4b','content-type: application/json; charset=UTF-8','user-agent: okhttp/4.9.3'];
$res = http($u,$h,'POST',$d);
return $res;
}

function redeem($upi,$token,$uid){
    global $ip;
$u = "https://api.kooapp.com/rewards/redeem";
$d = '{"vpa":"'.$upi.'","coins":0}';
$h = ['Host: api.kooapp.com','authorization: Bearer '.$token.'','version: android 0.98.8','app_version_code: 293','migration_ver: 2','user_id: '.$uid.'','primarylanguage: hi','feedlanguages: hi','shield_id: d15185ecd064453f9ce34697c212cd4b','content-type: application/json; charset=UTF-8','user-agent: okhttp/4.9.3'];
$res = http($u,$h,'POST',$d);
return $res;
}







function uuid() {
    $data = PHP_MAJOR_VERSION < 7 ? openssl_random_pseudo_bytes(16) : random_bytes(16);
    $data[6] = chr(ord($data[6]) & 0x0f | 0x40);    // Set version to 0100
    $data[8] = chr(ord($data[8]) & 0x3f | 0x80);    // Set bits 6-7 to 10
    return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
}

function random($length=16){
    $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    $charactersLength = strlen($characters);
    $randomString = '';
    for ($i = 0; $i < $length; $i++) {
        $randomString .= $characters[rand(0, $charactersLength - 1)];
    }
    return $randomString;
}

function http($url,$head,$method="GET",$data="",$h=0){
$ch = curl_init($url);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
if($method!="GET"){
curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
}
curl_setopt($ch, CURLOPT_HTTPHEADER, $head);
if($h===1){
curl_setopt($ch, CURLOPT_HEADER, 1);
}
$result = curl_exec($ch);
if (curl_errno($ch)) {
    echo 'Error:' . curl_error($ch);
}
curl_close($ch);
return $result;
}
