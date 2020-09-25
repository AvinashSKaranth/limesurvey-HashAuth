# limesurvey-SSOAuth

```php
<?php
$APP_URL="https://example.com";
$secretKey="WW4TdZgQkerUav43AQPeRrxcdDWx4y95"; // <= Your Secret Key
$data["username"] = "admin";
$data["email"]    = "admin@example.com";
$data["name"]     = "admin";
$data["time"]     = round(microtime(true) * 1000);
$hash		      = hash_hmac('sha256',json_encode($data,JSON_NUMERIC_CHECK),$secretKey);
$url = $APP_URL."/index.php/admin/authentication/sa/login?authMethod=SSOAuth&username=".$data["username"]."&email=".$data["email"]."&name=".$data["name"]."&time=".$data["time"]."&loginlang=default&action=login&width=1434&login_submit=login&hash=".$hash;
header('Location: '.$url);
?>
```
