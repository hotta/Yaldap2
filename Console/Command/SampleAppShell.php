<?php
//  app/Plugin/Yaldap2/Console/Command/SampleAppShell.php
Class   SampleAppShell  extends AppShell    {

    public  $uses = array('Yaldap2.Yaldap2_User',
                          'Yaldap2.Yaldap2_Aduser');
    const   USERID = 'user1';

    public  function    startup(){} //  remove startup message

    public  function    main() {
        $this->out( "cake SampleApp [arg]\n"
                .   "   arg is one of the list below:\n" 
                .   "   args ............ Show argument list\n"
                .   "   ldap_read ....... Model->read()\n"
                .   "   ldap_findby ..... Model->findByXXX()\n"
                .   "   ldap_findfirst .. Model->find('first')\n"
                .   "   ldap_findall .... Model->find('all')\n"
                .   "   ldap_query ...... Model->query(sql)\n"
                .   "   ldap_auth ....... Model->find('first', password)\n"
                .   "   ad_read ....... Model->read()\n"
                .   "   ad_findby ..... Model->findByXXX()\n"
                .   "   ad_findfirst .. Model->find('first')\n"
                .   "   ad_findall .... Model->find('all')\n"
                .   "   ad_query ...... Model->query(sql)\n"
                .   "   ad_auth ....... Model->find('first', password)\n");
    }

    public  function    ldap_read() {
        $this->out('$this->Yaldap2_User->read()');
        $this->out(print_r($this->Yaldap2_User->read(
            array('displayName', 'homeDirectory'), self::USERID), true));
    }

    public  function    ldap_findby() {
        $this->out('$this->Yaldap2_User->findBy()');
        $this->out(print_r($this->Yaldap2_User->findByUid(self::USERID),true));
    }

    public  function    ldap_findfirst() {
        $this->out('$this->Yaldap2_User->find(\'first\')');
        $query = array(
            'conditions'    =>  array('uid' =>  self::USERID),
            'fields'        =>  array('displayName', 'loginShell'));
        $this->out(print_r($this->Yaldap2_User->find('first', $query), true));
    }

    public  function    ldap_findall() {
        $this->out('$this->Yaldap2_User->find(\'all\')');
        $query = array(
            'conditions'    =>  array('loginShell' =>  '/bin/bash'),
            'fields'        =>  array('uid', 'homeDirectory', 'mail'),
            'limit'         =>  array(3));
        $this->out(print_r($this->Yaldap2_User->find('all', $query), true));
    }

    public  function    ldap_query() {
        $this->out('$this->Yaldap2_User->query()');
        $query = array(
            'basedn'        =>  'ou=Groups,dc=example,dc=com',
            'conditions'    =>  array('cn' =>  'group2'),
            'callbacks'     =>  false);
        $this->out(print_r($this->Yaldap2_User->query('search', $query), true));
    }

    public  function    ldap_auth() {
        $argc = count($this->args);
        if ($argc != 2) {
            $this->out("cake SampleApp ldap_auth uid password");
            exit;
        }
        $uid = $this->args[0];
        $password = $this->args[1];
        $this->out('$this->Yaldap2_User->auth()');
        $user = $this->Yaldap2_User->auth($uid, $password);
        if ($user)  {
            $this->out("Successfully authenticated.");
        } else  {
            $this->out("Authentication failed");
        }
    }

    public  function    ad_read() {
        $this->out('$this->ad->read()');
        $this->out(print_r($this->Yaldap2_Aduser->read(
            array('sn', 'GivenName'), self::USERID), true));
    }

    public  function    ad_findby() {
        $this->out('$this->ad->findBy()');
        $this->out(print_r($this->Yaldap2_Aduser->findBysAMAccountName(self::USERID),true));
    }

    public  function    ad_findfirst() {
        $this->out('$this->ad->find(\'first\')');
        $query = array(
            'conditions'    =>  array('sAMAccountName' =>  self::USERID),
            'fields'        =>  array(
                'sn', 'displayName', 'givenName', 'homeDirectory'));
        $this->out(print_r($this->Yaldap2_Aduser->find('first', $query), true));
    }

    public  function    ad_findall() {
        $this->out('$this->ad->find(\'all\')');
        $query = array(
            'conditions'    =>  array('mail' =>  '*@example.com'),
            'fields'        =>  array(
                'sn', 'displayName', 'GivenName', 'homeDirectory'),
        //  Some fields may not be specified as a filter
        //  'conditions'=>  array('physicalDeliveryOfficeName' => 'siebold'),
        //  'fields'    =>  array('sAMAccountName', 'sn', 'GivenName'),
            'limit'     =>  array(3));
        $this->out(print_r($this->Yaldap2_Aduser->find('all', $query), true));
    }

    public  function    ad_query() {
        $this->out('$this->ad->query()');
        $query = array(
            'basedn'        =>  'ou=04Computers,dc=example,dc=com',
            'conditions'    =>  array('cn' =>  '41CW3W1'),
            'callbacks'     =>  false);
        $this->out(print_r($this->Yaldap2_Aduser->query('search', $query), true));
    }

    public  function    ad_auth() {
        $argc = count($this->args);
        if ($argc != 2) {
            $this->out("cake SampleApp ad_auth uid password");
            exit;
        }
        $uid = $this->args[0];
        $password = $this->args[1];
        $this->out('$this->Yaldap2_Aduser->auth()');
        $user = $this->Yaldap2_Aduser->auth($uid, $password);
        if ($user)  {
            $this->out("Successfully authenticated.");
        } else  {
            $this->out("Authentication failed");
        }
    }

    public function args()  {
        $argc = count($this->args);
        $this->out(print_r($this->args, true));
    }
}   //  Class   SampleAppShell  extends AppShell 
