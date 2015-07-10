<?php
App::uses('CakeLog', 'Log');
App::uses('BaseAuthenticate', 'Controller/Component/Auth');

class LdapAuthenticate extends BaseAuthenticate {

    /**
     * The name of the model that represents users which will be authenticated.
     * Defaults to 'User'.
     */
 
    function __construct(ComponentCollection $collection, $settings = array()) {
        if (empty($settings)) {
            $settings = $this->settings;
        }
        $model = Configure::read('LDAP.LdapAuth.Model');
        $model = (isset($model) ? $model : $settings['userModel']);

        $this->groupType = Configure::read('LDAP.groupType');
        $this->groupType = (isset($settings['GroupType'])) 
            ? $settings['GroupType'] : $this->groupType;
        //lets find all of our users groups
        if(!isset($this->groupType) || empty($this->groupType) ){
            $this->groupType = 'group';
        }
        $this->userModel = $model;
        $this->model = ClassRegistry::init($model);
        parent::__construct($collection, $settings);
	}   //  LdapAuthenticate :: __construct()
/**
 * Authenticate a user based on the request information.
 *
 * @param CakeRequest $request Request to get authentication information from.
 * @param CakeResponse $response A response object that can have headers added.
 * @return mixed Either false on failure, or an array of user data on success.
 */
    public function authenticate(CakeRequest $request, CakeResponse $response) {

        list($plugin, $model) = pluginSplit($this->userModel);

        $fields = $this->settings['fields'];
        if (empty($request->data[$model])) {
            return false;
        }
        if (
            empty($request->data[$model][$fields['username']]) ||
            empty($request->data[$model][$fields['password']])
        ) {
            return false;
        }
	$dn = $this->_getDn($this->model->primaryKey, 
            $request->data[$model][$fields['username']]);
        if (! $dn)  {
            return  false;
        }
        return $this->_findLdapUser(
            $dn, $request->data[$model][$fields['password']]
        );
    }   //  LdapAuthenticate :: authenticate()

    /**
     * Get a user based on information in the request.  
     * Used by cookie-less auth for stateless clients.
     *
     * @param CakeRequest $request Request object.
     * @return mixed Either false or an array of user information
     */
    public function getUser(CakeRequest $request) {
        $username = env('PHP_AUTH_USER');
        $pass = env('PHP_AUTH_PW');

        if (empty($username) || empty($pass)) {
            return false;
        }
        $dn = $this->_getDn($this->model->primaryKey, $username);
        return $this->_findLdapUser($dn, $pass);
    }   //  LdapAuthenticate :: getUser()

    function _findLdapUser($dn, $password)  {
        if (! $authResult =  $this->model->auth([
            'dn'        =>  $dn,
            'password'  =>  $password
        ])) {
            return  false;
        }
        $user =  $this->model->find('first', [
            'scope'     =>  'base',
            'targetDn'  =>  $dn
        ]);
        $user[$this->model->alias]['bindDN'] = $dn;
        $user[$this->model->alias]['bindPasswd'] = $password;
        $groups = $this->getGroups($user[$this->model->alias]);
        return $user[$this->model->alias];
    }   //  LdapAuthenticate :: _findLdapUser()

    function _getDn( $attr, $query) {
        if (! $userObj = $this->model->find('first', [
            'conditions'    =>  [
                $attr   =>  $query
            ],
            'scope'         =>  'sub'
        ])) {
            return  null;   //  No such account
        }
        return ($userObj[$this->model->alias]['dn']);
    }   //  LdapAuthenticate :: _getDn()

    function getGroups($user = null)    {
        if (strtolower($this->groupType) == 'group')    {
            $groups = $this->model->find('all',[
                'conditions'    =>  [
                    'AND'   =>  [
                        'objectclass'   =>  'group',
                        'member'        =>  $user['dn']
                    ]
                ],
                'scope'         =>  'sub'
            ]);
        } elseif (strtolower($this->groupType) == 'groupofuniquenames') {
            $groups = $this->model->find('all', [
                'conditions'    =>  [
                    'AND'   =>  [
                        'objectclass'   =>  'groupofuniquenames',
                        'uniquemember'  =>  $user['dn']
                    ]
                ],
                'scope' =>  'sub'
            ]);
        } elseif (strtolower($this->groupType) == 'posixgroup') {
            $pk = $this->model->primaryKey;
            $groups = $this->model->find('all', [
                'conditions'    =>  [
                    'AND'   =>  [
                        'objectclass'   =>  'posixgroup',
                        'memberuid'     =>  $user[$pk]
                    ]
                ],
                'scope' =>  'sub'
            ]);
        }
	if (!isset($groups)  || empty($groups)) {
            return  false;
        }
	$groupIdentifer = Configure::read('LDAP.Group.Identifier');
	$groupIdentifer = (empty($groupIdentifer)) ? 'cn' : $groupIdentifer;
        foreach ($groups as $group) {
            $gid = $group[$this->model->alias][$groupIdentifer];
            if (isset($gid)) {
		$mygroup[$gid] = $group[$this->model->alias]['dn'];
            }
	}
	//  todo loop through groupos to see if any are nested groups 
    //  that need to be expanded!
	return $mygroup;
    }   //  LdapAuthenticate :: getGroups()
}   //  class LdapAuthenticate extends BaseAuthenticate
