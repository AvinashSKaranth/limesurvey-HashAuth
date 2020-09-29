<?php
class HashAuth extends AuthPluginBase {

    protected $storage = 'DbStorage';
    static protected $description = 'Hash Auth';
    static protected $name = 'HashAuth';
	
    protected $settings = array(
			'secret_key' => array(
            'type' => 'string',
            'label' => 'Secret Key (32 digit Key)',
            'default' => 'WW4TdZgQkerUav43AQPeRrxcdDWx4y95',
        ),
            'logoffurl' => array(
            'type' => 'string',
            'label' => 'Redirecting url after LogOff',
            'default' => 'https://my.example.com/Account/Logoff',
		),
            'is_default' => array(
            'type' => 'checkbox',
            'label' => 'Check to make default authentication method (this disable Default LimeSurvey authentification by database)',
            'default' => false,
        ),
            'autocreateuser' => array(
            'type' => 'checkbox',
            'label' => 'Automatically create user if not exists',
            'default' => true,
        ),
            'permission_create_survey' => array(
            'type' => 'checkbox',
            'label' => 'Permission create survey',
            'default' => true,
        )
    );

    /*public function __construct(\LimeSurvey\PluginManager\PluginManager $manager, $id) {
        parent::__construct($manager, $id);

        $this->subscribe('beforeLogin');
        $this->subscribe('newUserSession');
		$this->subscribe('afterLogout');
    }*/
	 public function init(){
        /**
         * Here you should handle subscribing to the events your plugin will handle
         */
        $this->subscribe('getGlobalBasePermissions');
        $this->subscribe('beforeLogin');
        $this->subscribe('newUserSession');
		$this->subscribe('afterLogout');
		$this->subscribe('remoteControlLogin');
    }
	/**
     * Add AuthLDAP Permission to global Permission
     * @return void
     */
    public function getGlobalBasePermissions()
    {
        $this->getEvent()->append('globalBasePermissions', array(
            'auth_hash' => array(
                'create' => false,
                'update' => false,
                'delete' => false,
                'import' => false,
                'export' => false,
                'title' => gT("Hash Auth SSO"),
                'description' => gT("Use Hashed SSO authentication"),
                'img' => 'usergroup'
            ),
        ));
    }
	
    public function beforeLogin() {
		// Do nothing if this user is not HashAuth type
		$request = $this->api->getRequest();		
		$authMethod = $request->getParam('authMethod');
		if ($authMethod != 'HashAuth') 
		{
			return;
		}
		
		$data["username"] = $request->getParam('username');
		$data["email"] = $request->getParam('email');
		$data["name"] = $request->getParam('name');
		$data["time"] = $request->getParam('time');
		$json = $request->getParam('json');
		$hash = $request->getParam('hash');
		$secret_key = $this->get('secret_key',null,null,$this->settings['secret_key']['default']);
		$chash=hash_hmac('sha256',json_encode($data,JSON_NUMERIC_CHECK),$secret_key);
		if ($hash==$chash&&abs($data["time"]-round(microtime(true) * 1000))<60*5*1000)
		{		
			// If is set "autocreateuser" option then create the new user
            if($this->get('autocreateuser',null,null,$this->settings['autocreateuser']['default']))
            {
                $this->setUsername($data["username"]);
				$this->displayName = $data["name"];
				$this->mail = $data["email"];
                $this->setAuthPlugin(); // This plugin handles authentication, halt further execution of auth plugins
            }else if($this->get('is_default',null,null,$this->settings['is_default']['default']))
            {
                throw new CHttpException(401,'Wrong credentials for LimeSurvey administration: "' . $data["username"] . '".');
            }
		}else{
			throw new CHttpException(401,'Invalid Hash: " ' .$hash. '".');
		}
    }

    public function newUserSession() {
		// Do nothing if this user is not HashAuth type
		$identity = $this->getEvent()->get('identity');
        if ($identity->plugin != 'HashAuth') {
            return;
        }
		
        $sUser = $this->getUserName();
        $oUser = $this->api->getUserByName($sUser);

        if (is_null($oUser)) {
            // Create new user
            $oUser = new User;
            $oUser->users_name = $sUser;
            $oUser->password = hash('sha256', createPassword());
            $oUser->full_name = $this->displayName;
            $oUser->parent_id = 1;
            $oUser->email = $this->mail;

            if ($oUser->save()) {
                if ($this->get('permission_create_survey', null, null, false)) {
                    $data = array(
                        'entity_id' => 0,
                        'entity' => 'global',
                        'uid' => $oUser->uid,
                        'permission' => 'surveys',
                        'create_p' => 1,
                        'read_p' => 0,
                        'update_p' => 0,
                        'delete_p' => 0,
                        'import_p' => 0,
                        'export_p' => 0
                    );

                    $permission = new Permission;
                    foreach ($data as $k => $v)
                        $permission->$k = $v;
                    $permission->save();
                }


                $this->setAuthSuccess($oUser);
                return;
            } else {
                $this->setAuthFailure(self::ERROR_USERNAME_INVALID);
                return;
            }

            return;
        } else { // The user alredy exists
            $this->setAuthSuccess($oUser);
        }
    }

	public function afterLogout()
    {
		$logoffurl = $this->get('logoffurl');
		
		if (!empty($logoffurl))
		{
			// Logout HashAuth
			header("Location: " . $logoffurl);
			die();
		}
    }
}
?>
