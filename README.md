# limesurvey-SSOAuth

This is a simple Unidirectional SSO using secret_key and hash_hmac to create a secure SSO without requiring any token generation or complicated request logic. This works with a simple get request with some data (params) and hashed value for authentication 

```php
<?php
$LIMESURVEY_APP_URL="https://example.com";
$secretKey="WW4TdZgQkerUav43AQPeRrxcdDWx4y95"; // <= Your Secret Key saved in the plugin
$data["username"] = "admin";
$data["email"]    = "admin@example.com";
$data["name"]     = "admin";
$data["time"]     = round(microtime(true) * 1000);
$hash             = hash_hmac('sha256',json_encode($data,JSON_NUMERIC_CHECK),$secretKey);
$url = $LIMESURVEY_APP_URL."/index.php/admin/authentication/sa/login?authMethod=SSOAuth&username=".$data["username"]."&email=".$data["email"]."&name=".$data["name"]."&time=".$data["time"]."&hash=".$hash."&loginlang=default&action=login&login_submit=login";
header('Location: '.$url);
?>
```
