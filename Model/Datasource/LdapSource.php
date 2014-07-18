<?php
/**
 * Yer another LDAP Datasource for CakePHP 'Yaldap2'
 * This code is derived from www.analogrithems.com below.
 * Tested on CakePHP 2.5.2
 * Added findBy*() / findAll() and several minor improvements.
 *
 * ------------------------------------------------------------------------------------
 *
 * Connect to LDAPv3 style datasource with full CRUD support.
 * Still needs HABTM support
 * 
 * Discussion at http://www.analogrithems.com/rant/2012/01/03/cakephp-2-0-ldapauth/
 * Tested with OpenLDAP, Netscape Style LDAP {iPlanet, Fedora, RedhatDS} Active Directory.
 * Supports TLS, multiple ldap servers (Failover not, mirroring), Scheme Detection
 *
 * PHP Version 5
 *
 * CakePHP(tm) : Rapid Development Framework (http://cakephp.org)
 * Copyright 2005-2011, Cake Software Foundation, Inc. (http://cakefoundation.org)
 *
 * Licensed under The MIT License
 * Redistributions of files must retain the above copyright notice.
 *
 * @copyright	 Copyright 2005-2010, Cake Software Foundation, Inc. (http://cakefoundation.org)
 * @link		  http://cakephp.org CakePHP(tm) Project
 * @package	   datasources
 * @subpackage	datasources.models.datasources
 * @since		 CakePHP Datasources v 0.3
 * @license	   MIT License (http://www.opensource.org/licenses/mit-license.php)
 */

/**
 * Ldap Datasource
 *
 * @package datasources
 * @subpackage datasources.models.datasources
 */
App::uses('CakeSession', 'Model/Datasource');

class LdapSource extends DataSource {

const   LDAP_ENTRY_LIMIT = 1000;    //  To avoid exhausting memory

/**
 * Datasource description
 *
 * @var string
 */
    public $description = "Ldap Data Source";

/**
 * Cache Sources
 *
 * @var boolean
 */
    public $cacheSources = true;

/**
 * Schema Results
 *
 * @var boolean
 */
    public $SchemaResults = false;

/**
 * Database
 *
 * @var mixed
 */
    public $_connection = false;

/**
 * Number of Rows Returned
 *
 * @var integer
 */
    public $numRows = 0;

/**
 * String to hold how many rows were affected by the last LDAP operation.
 *
 * @var string
 */
    public $affected = null;

/**
 * Model
 *
 * @var mixed
 */
    public $model;

/**
 * Operational Attributes
 *
 * @var mixed
 */
    public $OperationalAttributes;

/**
 * Schema DN
 *
 * @var string
 */
    public $SchemaDN;

/**
 * Schema Attributes
 *
 * @var string
 */
    public $SchemaAtributes;

/**
 * Schema Filter
 *
 * @var string
 */
    public $SchemaFilter = '(objectClass=subschema)';

/**
 * Result for formal queries
 *
 * @var mixed
 */
    protected $_result = false;

/**
 * Base driver configuration. Will be merged with user settings.
 *
 * @var  array
 */
    protected $_baseConfig = array(
        //  mandatory from here
        'type'      => 'OpenLDAP',          //  '(OpenLDAP|ActiveDirectory)'
        'datasource'=> 'Yaldap2.LdapSource',
        'host'      => 'ldap://localhost',  //  OpenLDAP 2.x or greater
        'basedn'    => 'dc=example,dc=com',
        'login'     => 'cn=Manager,dc=example,dc=com',  //  admin user id
        'password'  => 'password-string',               //  admin user pw
        'userdn'    => 'ou=Users,dc=example,dc=com',
        'database'  =>  '',         //  needed for parent::listSources()
        //  mandatory to here
        'port'      => 389,
        'groupdn'   => 'ou=Groups,dc=example,dc=com',
        'tls'       => false,
        'version'   => 3,
        'filter'    => '(objectclass=*)',
        'attrs'     => array(),     //  array
        'attrsonly' => 0,           //  1.attr type only 0.attr type and value
        'sizelimit' => 0,           //  number of entries to get 0.unlimited
        'timelimit' => 0,           //  max time to retrieve 0.unlimited
        'deref'     => LDAP_DEREF_NEVER,//  how to treat alias
    );

/**
 * MultiMaster Use
 *
 * @var integer
 */
    protected $_multiMasterUse = 0;

/**
 * Query Time
 *
 * @var integer
 */
    protected $_queriesTime = 0;

/**
 * Query cnt
 *
 * @var integer
 */
    public $_queriesCnt = 0;

/**
 * Query Logging
 *
 * @var array
 */
    public $_queriesLog = array();

/**
 * Query Log Max
 *
 * @var array
 */
    public $_queriesLogMax = 200;

/**
 * query cache
 *
 * @var array
 */
    private $_queryCache = array();

/**
 * Print full query debug info?
 *
 * @var bool
 */
    public $fullDebug = false;

/**
 * Time the last query took
 *
 * @var int
 */
    public $took = null;

/**
 * Result set of the last query
 *
 * @var array
 */
    private $_resultSet = array();

/**
 * numeric index represents the current position of $this->_resultSet
 *
 * @var array
 */
    private $_index = -1;

/**
 * boolean value represents whether $this->_resultSet is available.
 *
 * @var array
 */
    private $_available = false;

/**
 * Constructor
 *
 * @param array $config Configuration 
 */
    public function __construct($config = null) {

        $this->fullDebug = Configure::read('debug') > 1;
        parent::__construct($config);
        $link =  $this->connect();

        // People Have been asking for this forever.
        if (isset($config['type']) && !empty($config['type'])) {
            switch($config['type']){
            case 'OpenLDAP':
                $this->setOpenLDAPEnv();
                break;
            case 'ActiveDirectory':
                $this->setActiveDirectoryEnv();
                break;
            case 'Netscape':
            default:
                $this->setNetscapeEnv();
                break;
            }
        }

        $this->setSchemaPath();
        return $link;
    }   //  LdapSource :: __construct()

    /**
    * Destructor
    *
    * Closes connection to the server
    *
    * @return void
    */
    public function __destruct() {
        $this->close();
        parent::__destruct();
    }   //  LdapSource :: __destruct()

/**
 * auth($dn, $passwd)
 * Test if the dn/passwd combo is valid
 * This may actually belong in the component code, will look into that
 *
 * @param string bindDN to connect as
 * @param string password for the bindDN
 * @param boolean 
*/
    public function auth( $dn, $passwd ){
        $this->connect($dn, $passwd);
        if ($this->connected){
            return true;
        } else {
            $error = $this->lastError();
            if (isset($this->model))    {
                CakeSession::destroy('Auth.' . $this->model->alias);
            }
            return false;
        }
    }   //  LdapSource :: auth()

/**
 * Translates between PHP boolean values and Database (faked) boolean values
 *
 * @param mixed $data Value to be translated
 * @param bool $quote Whether or not the field should be cast to a string.
 * @return string|bool Converted boolean value
 */
    public function boolean($data, $quote = false) {
        if ($quote) {
            return !empty($data) ? '1' : '0';
        }
        return !empty($data);
    }   //  LdapSource :: boolean()

/**
 * Returns the count of records
 *
 * @param model $model
 * @param string $func Lowercase name of SQL function, i.e. 'count' or 'max'
 * @param array $params Function parameters (any values must be quoted manually)
 * @return string	   entry count
 * @access public
 */
    public function calculate(&$model, $func, $params = array()) {
        $params = (array)$params;

        switch (strtolower($func)) {
        case 'count':
            if(empty($params) && $model->id){
                //quick search to make sure it exsits
                $queryData['targetDn'] = $model->id;
                $queryData['conditions'] = 'objectClass=*';
                $queryData['scope'] = 'base';
                $query = $this->read($model, $queryData);
            }
            return $this->numRows;
            break; 
        case 'max':
        case 'min':
            break;
        }
    }   //  LdapSource :: calculate()

/**
 * Disconnects database, kills the connection and says the connection is closed,
 * and if DEBUG is turned on, the log for this object is shown.
 *
 */
    public function close() {
        if ($this->fullDebug ) {
            $this->showLog();
        }
        $this->disconnect();
    }   //  LdapSource :: close()

    /**
    * create the actual connection to the ldap server
    * This function supports failover, so if your config['host'] is an array
    * it will try the first one, if it fails, jumps to the next and attempts 
    * to connect and so on.  If will also check try to setup any special 
    * connection options needed like referal chasing and tls support
    *
    * @param string the users dn to bind with
    * @param string the password for the previously state bindDN
    * @return boolean the status of the connection
    */
    public function connect($bindDN = null, $passwd = null) {
        $config = am($this->_baseConfig, $this->config);
        $this->connected = false;
        $hasFailover = false;
        if(isset($config['host']) && is_array($config['host']) ) {
            $config['host'] = $config['host'][$this->_multiMasterUse];
            if(count($this->config['host']) > (1 + $this->_multiMasterUse) ) {
                $hasFailOver = true;
            }
        }
        $bindDN =  (empty($bindDN)) ? $config['login'] : $bindDN;
        $bindPasswd = (empty($passwd)) ? $config['password'] : $passwd;
        if (!function_exists('ldap_connect')) {
            $this->log("LDAP not configured on this server.",'error');
            die("LDAP not configured on this server. The PHP-LDAP extension is probably missing!");
        }
        $this->_connection = @ldap_connect($config['host']);
        if (!$this->_connection) {
            // Try Next Server Listed
            if ($hasFailover) {
                $this->log('Trying Next LDAP Server in list:'
                . $this->config['host'][$this->_multiMasterUse], 'error');
                $this->_multiMasterUse++;
                $this->connect($bindDN, $passwd);
                if ($this->connected) {
                    return $this->connected;
                }
            }
        }

        // Set our protocol version usually version 3
        ldap_set_option($this->_connection, LDAP_OPT_PROTOCOL_VERSION, 
            $config['version']);
//      ldap_set_option(NULL, LDAP_OPT_DEBUG_LEVEL, 7); 

        if ($config['tls']) {
            if (!ldap_start_tls($this->_connection)) {
                $this->log("ldap_start_tls failed : " . 
                    ldap_err2str(ldap_errno($this->_connection)), 'error');
                throw new ConfigureException("Ldap_start_tls failed");
            }
        }
        //  So little known fact, if /your php-ldap lib is built against 
        //  openldap like pretty much every linux distro out their 
        //  like redhat, suse etc. The connect doesn't acutally happen 
        //  when you call ldap_connect it happens when you call ldap_bind.
        //  So if you are using failover then you have to test here also.
        $bind_result = @ldap_bind($this->_connection, $bindDN, $bindPasswd);
        if (!$bind_result) {
            if(ldap_errno($this->_connection) == 49){
                $this->log("Auth failed for '$bindDN'!",'error');
            }else{
                $this->log('Trying Next LDAP Server in list:'
                    . $this->config['host'][$this->_multiMasterUse], 'error');
                $this->_multiMasterUse++;
                $this->connect($bindDN, $passwd);
                if($this->connected){
                    return $this->connected;
                }
            }

        } else {
            $this->connected = true;
        }
        return $this->connected;
    }   //  LdapSource :: connect()

/**
 * Convert Active Directory timestamps to unix ones
 * 
 * @param integer $ad_timestamp Active directory timestamp
 * @return integer Unix timestamp
 */
    public static function convertTimestamp_ADToUnix($ad_timestamp) {
        $epoch_diff = 11644473600; 
            // difference 1601<>1970 in seconds. see reference URL
        $date_timestamp = $ad_timestamp * 0.0000001;
        $unix_timestamp = $date_timestamp - $epoch_diff;
        return $unix_timestamp;
    }   // LdapSource :: convertTimestamp_ADToUnix

/**
 * The "C" in CRUD
 *
 * @param Model $model
 * @param array $fields containing the field names
 * @param array $values containing the fields' values
 * @return true on success, false on error
 */
    public function create(Model $model, $fields = null, $values = null ) {
        $basedn = $this->config['basedn'];
        $key = $model->primaryKey;
        $table = $model->useTable;
        $fieldsData = array();
        $id = null;
        $objectclasses = null;

        if ($fields == null) {
            unset($fields, $values);
            $fields = array_keys($model->data);
            $values = array_values($model->data);
        }

        $count = count($fields);

        for ($i = 0; $i < $count; $i++) {
            if ($fields[$i] == $key) {
                $id = $values[$i];
            } elseif ($fields[$i] == 'cn') {
                $cn = $values[$i];
            }
            $fieldsData[$fields[$i]] = $values[$i];
        }

        // Lets make our DN, this is made from the useTable & basedn 
        // + primary key. Logically this corelate to LDAP

        if (isset($table) && preg_match('/=/', $table)) {
            $table = $table.', ';
        } else {
            $table = '';
        }
        if (isset($key) && !empty($key)) {
            $key = "$key=$id, ";
        } else {
            // Almost everything has a cn, this is a good fall back.
            $key = "cn=$cn, "; 
        }
        $dn = $key.$table.$basedn;

        $res = @ ldap_add( $this->_connection, $dn, $fieldsData );
        // Add the entry
        if ( $res ) {
            $model->setInsertID($id);
            $model->id = $id;
            return true;
        }
        $this->log("Failed to add ldap entry: dn:$dn\nData:" 
            . print_r($fieldsData,true) . "\n"
            . ldap_error($this->_connection),'error');
        $model->onError();
        return false;
    }   //  LdapSource :: create()

/**
 * debugs the current connection to check the settings.
 *
 */
    public function debugLDAPConnection(){
        $opts = array('LDAP_OPT_DEREF', 'LDAP_OPT_SIZELIMIT', 
            'LDAP_OPT_TIMELIMIT','LDAP_OPT_NETWORK_TIMEOUT',
            'LDAP_OPT_PROTOCOL_VERSION','LDAP_OPT_ERROR_NUMBER',
            'LDAP_OPT_REFERRALS','LDAP_OPT_RESTART','LDAP_OPT_HOST_NAME',
            'LDAP_OPT_ERROR_STRING','LDAP_OPT_MATCHED_DN',
            'LDAP_OPT_SERVER_CONTROLS','LDAP_OPT_CLIENT_CONTROLS');
        foreach ($opts as $opt) {
            $ve = '';
            ldap_get_option($this->_connection,constant($opt), $ve);
            $this->log("Option={$opt}, Value=".print_r($ve,1),'debug');
        }
    }   //  LdapSource :: debugLDAPConnection()

    public function defaultNSAttributes(){
        $fields = '* '.$this->OperationalAttributes;
        return(explode(' ', $fields));
    }   //  LdapSource :: defaultNSAttributes()

    public function describe($model) {
        $schemas = $this->__getLDAPschema();
        $attrs = $schemas['attributetypes'];
        ksort($attrs);
        return $attrs;
    }   //  LdapSource :: describe()

/**
 * The "D" in CRUD
 */
    public function delete(Model $model, $conditions = null)   {

        $recursive = false; //  if we want to recursively delete or not

        if(preg_match('/dn/i', $model->primaryKey)){
            $dn = $model->id;
        } else {
            // Find the user we will update as we need their dn
            if( $model->defaultObjectClass ) {
                $options['conditions'] = sprintf( '(&(objectclass=%s)(%s=%s))', 
                    $model->defaultObjectClass, $model->primaryKey, $model->id );
            } else {
                $options['conditions'] = 
                    sprintf( '%s=%s', $model->primaryKey, $model->id );
            }
            $options['targetDn'] = $model->useTable;
            $options['scope'] = 'sub';

            $entry = $this->read( $model, $options, $model->recursive );
            $dn = $entry[0][$model->name]['dn'];
        }

        if( $dn ) {
            if( $recursive === true ) {
                // Recursively delete LDAP entries
                if( $this->__deleteRecursively( $dn ) ) {
                    return true;
                }
            } else {
                // Single entry delete
                if( @ldap_delete( $this->_connection, $dn ) ) {
                    return true;
                }
            }
        }

        $model->onError();
        $errMsg = ldap_error($this->_connection);
        $this->log("Failed Trying to delete: $dn \nLdap Erro:$errMsg",'ldap.error');
        return false;
    }   //  LdapSource :: delete()

/**
 * disconnect  close connection and release any remaining results in the buffer
 *
 */
    public function disconnect() {
        @ldap_free_result($this->results);
        @ldap_unbind($this->_connection);
        $this->connected = false;
        return $this->connected;
    }   //  LdapSource :: disconnect()

/**
 * Check whether the LDAP extension is installed/loaded
 *
 * @return boolean
 */
    public function enabled() {
        return function_exists('ldap_connect');
    }   //  LdapSource :: enabled()

/**
 * Queries the LDAP database with given params, and obtains some metadata 
 * about the result(rows affected, timing, any errors, number of rows 
 * in resultset). The query is also logged.
 * If Configure::read('debug') is set, the log is shown all the time, 
 * else it is only shown on errors.
 *
 * ### Options
 *
 * - log - Whether or not the query should be logged to the memory log.
 *
 * @param string $query LDAP operation
 * @param array $options The options for executing the query.
 * @param array $params values to be bound to the query.
 * @return mixed Resource or object representing the result set, 
 *  or false on failure
 */
    public function execute($query, $options = array(), $params = array()) {
        $options += array('log' => $this->fullDebug);

        $t = microtime(true);
        $this->_result = $this->_executeQuery($query, $params);
        return $this->_result;
    }   //  LdapSource :: execute()

/**
 * Returns an array of all result rows for a given LDAP query.
 *
 * ### Options
 *
 * - `cache` - Returns the cached version of the query, if exists and 
 *      stores the result in cache. This is a non-persistent cache, 
 *      and only lasts for a single request. This option defaults to true. 
 *      If you are directly calling this method, you can disable caching
 *      by setting $options to `false`
 *
 * @param array $query LDAP query
 *  $query = [
 *      'conditions' => string, //  '(attr=pattern)'
 *      'targetDn' => string,   //  ou=Users,... etc
 *      'type' => string,       //  search|????
 *      'scope' => string,      //  base|one|sub
 *      'fields' => array       //  attrs to be retrieved
 *      'limit' => number       //  number of rows to be returned
 * ... ];
 * @param array|bool $params Either parameters to be bound as values 
 *  for the LDAP operation, or a boolean to control query caching.
 * @param array|string $options additional options for the query.
 * @return bool|array Array of resultset rows, or false if no rows matched
 */
    public function fetchAll($query, $params = array(), $options = array()) {
        if (is_string($options)) {
            $options = array('modelName' => $options);
        }
        if (is_bool($params)) {
            $options['cache'] = $params;
            $params = array();
        }
        $options += array('cache' => true);
        $cache = $options['cache'];
        $conditions = $query['conditions'];
//      if ($cache && ($cached = $this->getQueryCache($query, $params)) !== false) 
        if ($cache
        && empty($params)
        && isset($this->_queryCache[$conditions]))   {
            $this->log(__FUNCTION__. '() : Cache used', 'debug');
            return $this->_queryCache[$conditions];
        }
        $result = $this->execute($query, array(), $params);
        
        if ($result) {
            $e = ldap_get_entries($this->_connection, $result);
            if ($cache) {
                $this->_queryCache[$conditions] = $e;
            }
            return $e;
        }
        return false;
    }   //  LdapSource :: fetchAll()

//Here are the functions that try to do model associations
    public function generateAssociationQuery(& $model, & $linkModel, $type, 
        $association = null, $assocData = array (),
        & $queryData, $external = false, & $resultSet) {

        $this->__scrubQueryData($queryData);

        switch ($type) {
        case 'hasOne' :
            $id = $resultSet[$model->name][$model->primaryKey];
            $queryData['conditions'] = trim($assocData['foreignKey']) . '=' . trim($id);
            $queryData['targetDn'] = $linkModel->useTable;
            $queryData['type'] = 'search';
            $queryData['limit'] = 1;
            return $queryData;

        case 'belongsTo' :
            $id = $resultSet[$model->name][$assocData['foreignKey']];
            $queryData['conditions'] = trim($linkModel->primaryKey).'='.trim($id);
            $queryData['targetDn'] = $linkModel->useTable;
            $queryData['type'] = 'search';
            $queryData['limit'] = 1;
            return $queryData;

        case 'hasMany' :
            $id = $resultSet[$model->name][$model->primaryKey];
            $queryData['conditions'] = trim($assocData['foreignKey']) . '=' . trim($id);
            $queryData['targetDn'] = $linkModel->useTable;
            $queryData['type'] = 'search';
            $queryData['limit'] = $assocData['limit'];
            return $queryData;

        case 'hasAndBelongsToMany' :
            return null;
        }
        return null;
    }   //  LdapSource :: generateAssociationQuery()

/**
 * Get the query log as an array.
 *
 * @param boolean $sorted Get the queries sorted by time taken, 
 *      defaults to false.
 * @param boolean $clear If True the existing log will cleared.
 * @return array Array of queries run as an array
 */
    public function getLog($sorted = false, $clear = true) {
        if ($sorted) {
            $log = sortByKey($this->_queriesLog, 'took', 'desc', SORT_NUMERIC);
        } else {
            $log = $this->_queriesLog;
        }
        if ($clear) {
            $this->_queriesLog = array();
        }
        return array('log' => $log, 'count' => $this->_queriesCnt, 
            'time' => $this->_queriesTime);
    }   //  LdapSource :: getLog()

/*
 *  Case insensitive in_array()
 *
 */
    public function in_arrayi( $needle, $haystack ) {
        $found = false;
        foreach( $haystack as $attr => $value ) {
            if( strtolower( $attr ) == strtolower( $needle ) ) {
                $found = true;
            } elseif( strtolower( $value ) == strtolower( $needle ) ) {
                $found = true;
            }
        }   
        return $found;
    }   //  LdapSource :: in_arrayi()

/**
 * Checks if it's connected to the database
 *
 * @return boolean True if the database is connected, else false
 */
    public function isConnected() {
        return $this->connected;
    }   //  LdapSource :: isConnected()

/*
 *  Check if param is logically equal to the basedn
 *
 *  @param string $targetDN
 *  @returns boolean
 */
    public function isEqualtoBaseDn( $targetDN ){
        $parts = preg_split('/,\s*/', $this->config['basedn']);
        $pattern = '/'.implode(',\s*', $parts).'/i';
        return(preg_match($pattern, $targetDN) === 1);
    }   //  LdapSource :: isEqualtoBaseDn()

/**
 * Returns a formatted error message from previous database operation.
 *
 * @return string Error message with error number
 */
    public function lastError() {
        if (ldap_errno($this->_connection)) {
            return ldap_errno($this->_connection) . ': ' . ldap_error($this->_connection);
        }
        return null;
    }   // LdapSource :: lastError()

/**
 * Returns number of rows in previous resultset. 
 * If no previous resultset exists, this returns null.
 *
 * @return int Number of rows in resultset
 */
    public function lastNumRows($source = null) {
        if ($this->_result and is_resource($this->_result)) {
            return @ ldap_count_entries($this->_connection, $this->_result);
        }
        return null;
    }   // LdapSource :: lastNumRows()

/**
 * Returns an array of sources (tables) in the database.
 *
 * @param mixed $data
 * @return array Array of tablenames in the database
 */
    public function listSources($data = null) {
            $cache = parent::listSources();
            if ($cache !== null) {
                    return $cache;
            }
    }   //  LdapSource :: listSources()

/**
 * Log given LDAP query.
 *
 * @param string $query LDAP statement
 * @todo: Add hook to log errors instead of returning false
 */
    public function logQuery($query) {
        $this->_queriesCnt++;
        $this->_queriesTime += $this->took;
        $this->_queriesLog[] = array(
            'query' => $query,
            'affected' => $this->affected,
            'numRows' => $this->numRows,
            'took' => $this->took
        );
        if (count($this->_queriesLog) > $this->_queriesLogMax) {
            array_pop($this->_queriesLog);
        }
    }   //  LdapSource :: logQuery()

/*
 *  Convert condition array for magic method
 *
 */
    public function magic_condition($key, $value) {
        if (!isset($value) || !is_array($value)) {
            return null;
        }
        $filter = sprintf("(%s=%s)", strtolower($key), $value[0]);
        return [ 'conditions' => $filter ];
    }   //  magic_condition()

/**
 * Field name
 *
 * This looks weird, but for LDAP we just return the name of the field as is.
 *
 * @param string $field Field name
 * @return string Field name
 * @author Graham Weldon
 */
    public function name($field) {
        return $field;
    }   //  LdapSource :: name()

/**
 * DataSource Query abstraction
 *  In findBy* case, 
 *      this should be called as query('findBy***', $value, $model);
 *  In case calling directly from Controller/Command,
 *      this should be called as query('search', $query)
 *      and we can't access to the model object.
 * @return resource Result resource identifier.
*/
    public function query() {
        $args = func_get_args();
        $method = $args[0];   //  query type
        $query = $args[1];
        if (count($args) === 2) {   //  direct query() call
            $query['type'] = $method;   //  'search'
            $query['_noModel'] = true;  //  no model
            $query['conditions'] = $this->_conditions($query['conditions']);
            return $this->fetchAll($query);
        }
        $model = $args[2];
        if (strncmp($method, 'findBy', 6) == 0)    {
            $cond = $this->magic_condition(
                preg_replace('/^findBy/', '', $method), $args[1]);
            return $model->find('first', $cond);
        } else if (strncmp($method, 'findAllBy', 9) == 0)    {
            $cond = $this->magic_condition($method, 
                preg_replace('/^findAllBy/', '', $method), $args[1]);
            return $model->find('all', $cond);
        }
        switch ($method) {
        case 'auth':
            //  $query = [ 0 => [ 
            //      'dn' => 'uid=hotta,ou=Users...' ,
            //      'password' => raw_password
            //  ]];
            $dn = $query[0]['dn'];
            $password = $query[0]['password'];
            return $this->auth($dn, $password);
        case 'findSchema':
            $query = $this->__getLDAPschema();
            // $this->findSchema($query);
            break;
        case 'findConfig':
            return $this->config;
            break;
        case 'search':
        default:
            $query = $this->read($this->model, $query);
            break;
            }
    }   //  LdapSource :: query()

/*
 *
 *
 */
    public function queryAssociation(& $model, & $linkModel, $type, 
        $association, $assocData, & $queryData, $external = false, 
        & $resultSet, $recursive, $stack) {

        if (!isset ($resultSet) || !is_array($resultSet)) {
            if (Configure::read('debug') > 0) {
                echo '<div style = "font: Verdana bold 12px; color: #FF0000">SQL Error in model '
                 . $model->name . ': ';
                if (isset ($this->error) && $this->error != null) {
                    echo $this->error;
                }
                echo '</div>';
            }
            return null;
        }

        $count = count($resultSet);
        for ($i = 0; $i < $count; $i++) {
            $row = & $resultSet[$i];
            $queryData = $this->generateAssociationQuery($model, $linkModel, 
                $type, $association, $assocData, $queryData, $external, $row);
            $fetch = $this->_executeQuery($queryData);
            $fetch = ldap_get_entries($this->_connection, $fetch);
            $fetch = $this->_ldapFormat($linkModel,$fetch);

            if (!empty ($fetch) && is_array($fetch)) {
                if ($recursive > 0) {
                    foreach ($linkModel->__associations as $type1) {
                        foreach ($linkModel-> {$type1 } as $assoc1 => $assocData1) {
                            $deepModel = & $linkModel->{$assocData1['className']};
                            if ($deepModel->alias != $model->name) {
                                $tmpStack = $stack;
                                $tmpStack[] = $assoc1;
                                if ($linkModel->useDbConfig == $deepModel->useDbConfig) {
                                    $db = & $this;
                                } else {
                                    $db = & ConnectionManager::getDataSource(
                                        $deepModel->useDbConfig);
                                }
                                $queryData = array();
                                $db->queryAssociation($linkModel, $deepModel, 
                                    $type1, $assoc1, $assocData1, $queryData,
                                    true, $fetch, $recursive -1, $tmpStack);
                            }
                        }   //  foreach()
                    }   //  foreach()
                }
                $this->__mergeAssociation($resultSet[$i], $fetch, $association, $type);
            } else {
                $tempArray[0][$association] = false;
                $this->__mergeAssociation($resultSet[$i], $tempArray, $association, $type);
            }
        }   //  for()
    }   //  LdapSource :: queryAssociation()

/**
 * The "R" in CRUD
 *
 * @param Model $model
 * @param array $queryData
 * @param integer $recursive Number of levels of association
 * @return array $resultSet
 */
    public function read(Model $model, $queryData = array(), $recursive = null ) {
        $this->model = $model;
        $this->__scrubQueryData($queryData);
        if (!is_null($recursive)) {
            $_recursive = $model->recursive;
            $model->recursive = $recursive;
        }

        // Check if we are doing a 'count' .. this is kinda ugly 
        //  but i couldn't find a better way to do this, yet
        if ( is_string( $queryData['fields'] ) 
        && $queryData['fields'] == 'COUNT(*) AS ' . $this->name( 'count' ) ) {
            $queryData['fields'] = array();
        }

        // Prepare query data ------------------------ 
        $queryData['conditions'] = $this->_conditions( $queryData['conditions'] );
        if (empty($queryData['targetDn'])) {
            $queryData['targetDn'] = $model->useTable;
        }
        $queryData['type'] = 'search';

        if (empty($queryData['order'])) {
            $queryData['order'] = array($model->primaryKey);
        }
        // Associations links --------------------------
        if (isset($model->__associations)) {
            foreach ($model->__associations as $type) {
                foreach ($model->{$type} as $assoc => $assocData) {
                    if ($model->recursive > -1) {
                        $linkModel = & $model->{$assoc};
                        $linkedModels[] = $type . '/' . $assoc;
                    }
                }
            }
        }

        // Execute search query ------------------------
        $res = $this->_executeQuery($queryData );

        if ($this->lastNumRows()==0)    {
            return false;
        }
        // Format results  -----------------------------
        ldap_sort($this->_connection, $res, $queryData['order'][0]);
        $resultSet = ldap_get_entries($this->_connection, $res);
        $resultSet = $this->_ldapFormat($model, $resultSet);	

        // Query on linked models  ----------------------
        if (($model->recursive > 0) && isset($model->__associations) ) {
            foreach ($model->__associations as $type) {
                foreach ($model->{$type} as $assoc => $assocData) {
                    $db = null;
                    $linkModel = & $model->{$assoc};
                    if ($model->useDbConfig == $linkModel->useDbConfig) {
                        $db = & $this;
                    } else {
                        $db = & ConnectionManager::getDataSource(
                            $linkModel->useDbConfig);
                    }
                    if (isset ($db) && $db != null) {
                        $stack = array ($assoc);
                        $array = array ();
                        $db->queryAssociation($model, $linkModel, $type, 
                            $assoc, $assocData, $array, true, $resultSet, 
                            $model->recursive - 1, $stack);
                        unset ($db);
                    }
                }
            }
        }

        if (!is_null($recursive)) {
            $model->recursive = $_recursive;
        }

        // Add the count field to the resultSet (needed by find() to work out 
        //  how many entries we got back .. used when $model->exists() is called)
        $resultSet[0][0]['count'] = $this->lastNumRows();
        return $resultSet;
    }   //  LdapSource :: read()

/**
 * Reconnects to database server with optional new settings
 *
 * @param array $config An array defining the new configuration settings
 * @return boolean True on success, false on failure
 */
    public function reconnect($config = null) {
        $this->disconnect();
        if ($config != null) {
            $this->config = array_merge($this->_baseConfig, $this->config, $config);
        }
        return $this->connect();
    }   //  LdapSource :: reconnect()

/**
* If you want to pull everything from a netscape stype ldap server 
* iPlanet, Redhat-DS, Project-389 etc you need to ask for specific 
* attributes like so.  Other wise the attributes listed below wont
* show up
*/
    public function setActiveDirectoryEnv() {
        //Need to disable referals for AD
        ldap_set_option($this->_connection, LDAP_OPT_REFERRALS, 0);
        $this->OperationalAttributes = ' + ';
        $this->SchemaAttributes = 'objectClasses attributeTypes ldapSyntaxes '
        .   'matchingRules matchingRuleUse createTimestamp modifyTimestamp '
        .   'subschemaSubentry';
    }   //  LdapSource :: setActiveDirectoryEnv()

    public function setNetscapeEnv() {
        $this->OperationalAttributes = 'accountUnlockTime aci copiedFrom '
        .   'copyingFrom createTimestamp creatorsName dncomp entrydn entryid '
        .   'hasSubordinates ldapSchemas ldapSyntaxes modifiersName '
        .   'modifyTimestamp nsAccountLock nsAIMStatusGraphic nsAIMStatusText '
        .   'nsBackendSuffix nscpEntryDN nsds5ReplConflict nsICQStatusGraphic '
        .   'nsICQStatusText nsIdleTimeout nsLookThroughLimit nsRole nsRoleDN '
        .   'nsSchemaCSN nsSizeLimit nsTimeLimit nsUniqueId nsYIMStatusGraphic '
        .   'nsYIMStatusText numSubordinates parentid passwordAllowChangeTime '
        .   'passwordExpirationTime passwordExpWarned passwordGraceUserTime '
        .   'passwordHistory passwordRetryCount pwdExpirationWarned '
        .   'pwdGraceUserTime pwdHistory pwdpolicysubentry retryCountResetTime '
        .   'subschemaSubentry';
        $this->SchemaAttributes = 'objectClasses attributeTypes ldapSyntaxes '
        .   'matchingRules matchingRuleUse createTimestamp modifyTimestamp';
    }   //  LdapSource :: setNetscapeEnv()

    public function setOpenLDAPEnv() {
        $this->OperationalAttributes = ' + ';
    }   //  LdapSource :: setOpenLDAPEnv()

    public function setSchemaPath() {
        $checkDN = ldap_read($this->_connection, '', 'objectClass=*', 
            array('subschemaSubentry'));
        $schemaEntry = ldap_get_entries($this->_connection, $checkDN);
        $this->SchemaDN = $schemaEntry[0]['subschemasubentry'][0];
    }   //  LdapSource :: setSchemaPath()

/**
 * Outputs the contents of the queries log. If in a non-CLI environment 
 * the sql_log element will be rendered and output. If in a CLI environment,
 * a plain text log is generated.
 *
 * @param boolean $sorted Get the queries sorted by time taken, 
 *      defaults to false.
 * @return void
 */
    public function showLog($sorted = false) {
        $log = $this->getLog($sorted, false);
        if (empty($log['log'])) {
            return;
        }

        if (PHP_SAPI != 'cli') {
            $controller = null;
            $View = new View($controller, false);
            //  TODO: configKeyName seems to be defined nowhere?
            $View->set('logs', array($this->configKeyName => $log));
            echo $View->element('ldap_dump', array('_forced_from_ldap_' => true));
        } else {
            foreach ($log['log'] as $k => $i) {
                print (($k + 1) . ". {$i['query']}\n");
            }
        }
    }   //  LdapSource :: showLog()

/**
 * Output information about a LDAP query. The query, number of rows 
 * in resultset, and execution time in microseconds. If the query fails, 
 * an error is output instead.
 *
 * @param string $query Query to show information on.
 */
    public function showQuery($query) {
        $error = $this->error;
        if (strlen($query) > 200 && !$this->fullDebug) {
            $query = substr($query, 0, 200) . '[...]';
        }

        if (Configure::read('debug') > 0 || $error) {
        //  TODO not abstracted
            print ("<p style = \"text-align:left\"><b>Query:</b> {$query} "
                .  "<small>[ Num:{$this->numRows} "
                .  "Took:{$this->took}ms]</small>");
            if ($error) {
                print ("<br /><span style = \"color:Red;text-align:left\">"
                .   "<b>ERROR:</b> {$this->error}</span>");
            }
            print ('</p>');
        }
    }   //  LdapSource :: showQuery()

/**
 * decode avtive directory sid
 *
 * @param string $sid
 * @return string
 */
    public function sid_decode($osid) {
        $sid = false;
        $u = unpack("H2rev/H2b/nc/Nd/V*e", $osid);
        if ($u) {
            $n232 = pow(2,2);
            unset($u["b"]); // unused
            $u["c"] = $n232 * $u["c"] + $u["d"];
            unset($u["d"]);
            $sid="S";
            foreach ($u as $v) {
                if ($v < 0) {
                    $v = $n232 + $v;
                }
                $sid .= "-" . $v;
            }
        }
        return $sid;
    }   //  LdapSource :: sid_decode()

/**
 * The "U" in CRUD
 */
    public function update(
        Model $model, $fields = null, $values = null, $conditions = null ) {

        $fieldsData = array();
        if ($fields == null) {
            unset($fields, $values);
            $fields = array_keys( $model->data );
            $values = array_values( $model->data );
        }
        for ($i = 0; $i < count( $fields ); $i++) {
            $fieldsData[$fields[$i]] = $values[$i];
        }

        // set our scope
        $queryData['scope'] = 'base';
        if ($model->primaryKey == 'dn') {
            $queryData['targetDn'] = $model->id;
        } elseif (isset($model->useTable) && !empty($model->useTable)) {
            $queryData['targetDn'] = $model->primaryKey 
                . '=' . $model->id . ', ' . $model->useTable;
        }

        // fetch the record
        // Find the user we will update as we need their dn
        $resultSet = $this->read( $model, $queryData, $model->recursive );

        // now we need to find out what's different about the old entry 
        // and the new one and only changes those parts
        $current = $resultSet[0][$model->alias];
        $update = $model->data[$model->alias];

        foreach( $update as $attr => $value)    {
            if (isset($update[$attr]) && !empty($update[$attr]) &&
                $attr != $model->primaryKey) {
                $entry[$attr] = $update[$attr];
            } elseif (!empty($current[$attr]) 
            && (isset($update[$attr]) && empty($update[$attr])) )  {
                $entry[$attr] = array();
            }
        }

        // if this isn't a password reset, then remove the password field 
        // to avoid constraint violations...
        if (!$this->in_arrayi('userpassword', $update)) {
            unset($entry['userpassword']);
        }
        unset($entry['count']);
        unset($entry['dn']);

        if( $resultSet) {
            $_dn = $resultSet[0][$model->alias]['dn'];

            if ( @ldap_modify( $this->_connection, $_dn, $entry ) ) {
                return true;
            } else {
                $this->log("Error updating $_dn: " 
                  . ldap_error($this->_connection) . "\nHere is what I sent: " 
                  . print_r($entry,true), 'error');
                return false;
          }
        }

        // If we get this far, something went horribly wrong ..
        $model->onError();
        return false;
    }   //  LdapSource :: update()

/**
 * Creates a filter string by parsing given conditions data. 
 *  $conditions = [ 'id' => 'test' ];
 *  $conditions = [ 'and' =>
 *      [ 'id' => 'test' ],
 *      [ 'sex' => 'mail' ]
 *  ];
 *
 * @param string|array $conditions Array or string of conditions, or any value.
 * @return string filter string.
 */

    private function _conditions($conditions){
        if (empty($conditions)) {
            return '(objectClass=*)';
        }
        if (is_string($conditions)) {
            return $conditions;
        }
        if (!is_array($conditions)) {
            return '(objectClass=*)';
        }
        // Lets parse the types of operands that cakephp wil use and even add 
        // a few LDAP specific ones fuzzy & approximate  are unique to ldap
        $operands = array('and', 'or', 'not', 'fuzzy', 'approximate');
        $str ='';
        if (isset($this->model))    {
            $pat = "/^{$this->model->name}\./";
        }
        foreach($conditions as $key=>$value) {
            $fuzzy = false;
            if (isset($pat))    {
                $key = preg_replace($pat, '', $key);
            }
            if (is_array($value) && in_array(strtolower($key),$operands) ) {
                switch(strtolower($key)){
                case 'and':
                    $str .= '(&';
                    break;
                case 'or':
                    $str .= '(|';
                    break;
                case 'not':
                    $str .= '(!';
                    break;
                case 'fuzzy':
                case 'approximate':
                    $fuzzy = true;
                default:
                    $str .= '(';
                    break;
                }
                foreach ($value as $attr => $assignment) {
                    $attr = preg_replace('/^[A-Za-z0-9]+\.(.+)$/', '$1', $attr);
                    if(is_array($assignment))   {
                        $str .= $this->_conditions([$attr => $assignment]);
                    } else if ($fuzzy) {
                        $str .= '('.$attr.'~='.$assignment.')';
                        $fuzzy = false;
                    }else{
                        $str .= '('.$attr.'='.$assignment.')';
                        $fuzzy = false;
                    }
                }
                $str .= ')';
            } else if (is_string($key) && is_string($value)) {
                $key = preg_replace('/^[A-Za-z0-9]+\.(.+)$/', '$1', $key);
                if (preg_match('/ like/i', $key) > 0) { //Here we support the Like caluse
                    $key = preg_replace('/ like/i', '', $key);
                    $value = preg_replace('/\%/', '*', $value);
                    $str .= '('.$key.'='.$value.')';
                } else if(preg_match('/ <=/', $key)) { //Less than or equal
                    $key = preg_replace('/ <=/i', '', $key);
                    $str .= '('.$key.'<='.$value.')';
                }else if(preg_match('/ >=/', $key)) { //Greator than or equal
                    $key = preg_replace('/ >=/i', '', $key);
                    $str .= '('.$key.'>='.$value.')';
                }else{// generic match
                    $str .= '('.$key.'='.$value.')';
                }
            }
        }   //  foreach()
        return $str;
    }   //  LdapSource :: _conditions()

/**
 * issue ldap search query
 * In case calling from direct query() call, 
 *  we can't access to the model object
 *
 * @param array $query Some LDAP query to be executed
 *  $query = [
 *      'basedn' => full path of search base dn
 *  ];
 * @param bool $cache whether to use cache
 * @return resource id 
 */
    private function _executeQuery($query = array(), $cache = true) {
        $options = array('log' => $this->fullDebug);
        $t = microtime(true);

        if (isset($query['basedn']) && is_string($query['basedn'])) {
            $query['targetDn'] = $query['basedn'];
        } else if (isset($query['targetDn']) && is_string($query['targetDn'])) {
            $pat = '/,[ \t]+(\w+)=/';
            $query['targetDn'] = preg_replace($pat, ',$1=',$query['targetDn']);
        } else  {
            $query['targetDn'] = null;
        }
        if (!$this->isEqualtoBaseDn($query['targetDn']))    {
            if($query['targetDn'] != null){
                $seperator = (substr($query['targetDn'], -1) == ',') ? '' : ',';
                if ( (strpos($query['targetDn'], '=') === false) 
                && (isset($this->model) && !empty($this->model)) ) {
                    //Fix TargetDN here 
                    $key = $this->model->primaryKey;
                    $table = $this->model->useTable;
                    $query['targetDn'] = $key . '=' . $query['targetDn']
                        . ', ' . $table.$seperator . $this->config['basedn'];
                } else {
                    $query['targetDn'] = $query['targetDn']
                    .   $seperator . $this->config['basedn'];
                }
            } else {
                $query['targetDn'] = $this->model->useTable . ',' 
                    . $this->config['basedn'];
            }
        }
        if (!isset($query['_noModel']))   {
            $model = $this->model->name;
            $pat = "/^\({$model}\.(.+)$/";
            $query['conditions'] = 
                preg_replace($pat, '('.'$1', $query['conditions']);
        }
        if (isset($query['limit']) && is_array($query['limit']))    {
            $query['limit'] = $query['limit'][0];
        }
        $res = false;
        $query_string = $this->_queryToString($query);
        if ($cache && isset ($this->_queryCache[$query_string])) {
            if (strpos(trim(strtolower($query_string)), $query['type']) 
            !== false) {
                $res = $this->_queryCache[$query_string];
                $this->log(__FUNCTION__. '() : Cache used', 'debug');
            }
        } else if ($query['type'] === 'search') {
            // TODO pb ldap_search & $query['limit']
            if( empty($query['fields']) ){
                $query['fields'] = $this->defaultNSAttributes();
            }

            //Handle LDAP Scope
            if(isset($query['scope']) && $query['scope'] == 'base'){
                $res = @ ldap_read($this->_connection, $query['targetDn'], 
                    $query['conditions'], $query['fields']);
            } elseif (isset($query['scope']) && $query['scope'] == 'one') {
                $res = @ ldap_list($this->_connection, $query['targetDn'], 
                    $query['conditions'], $query['fields']);
            } else {
                if ($query['fields'] == 1) {
                    $query['fields'] = array();
                }
                $res = @ ldap_search($this->_connection, $query['targetDn'], 
                    $query['conditions'], $query['fields'], 0, $query['limit']);
            }

            if (!$res) {
                $errMsg = ldap_error($this->_connection);
                $this->log("Query Params Failed:"
                . print_r($query,true).' Error: '.$errMsg,'ldap.error');
            }

            if ($cache) {
                if (strpos(trim(strtolower($query_string)), $query['type']) 
                !== false) {
                    $this->_queryCache[$query_string] = $res;
                }
            }
        }

        $this->_result = $res;

        if ($options['log']) {
            $this->took = round((microtime(true) - $t) * 1000, 0);
            $this->error = $this->lastError();
            $this->numRows = $this->lastNumRows();
            $this->logQuery($query_string);
        }
        return $this->_result;
    }   //  LdapSource :: _executeQuery()

/**
 *  Implementation of findAllBy*() magic method.
 *
 * @param string $method 
 * @param string $value
 */
    protected function _findAllBy($method, $value = null)    {
        if (!$value || !is_array($value))  {
            return null;
        }
        $attr = strtolower(preg_replace('/^findAllBy/', '', $method));
        $query = [
            'type' => 'search',
            'conditions' => sprintf("(%s=%s)", $attr, $value[0]),
            'scope' => 'sub',
            'limit' => LDAP_ENTRY_KIMIT
        ];
        return $this->fetchAll($query, array());
    }   //  LdapSource :: _findAllBy()

/**
 *  Implementation of findBy*() magic method.
 *
 * @param string $method 
 * @param string $value
 */
    protected function _findBy($method, $value = null)    {
        if (!$value || !is_array($value))  {
            return null;
        }
        $attr = strtolower(preg_replace('/^findBy/', '', $method));
        $query = [
            'type' => 'search',
            'conditions' => sprintf("(%s=%s)", $attr, $value[0]),
            'scope' => 'sub',
            'limit' => 1
        ];
        return $this->fetchAll($query, array(), $model);
    }   //  LdapSource :: _findBy()

/*
 *
 *
 */
    function _ldapFormat(& $model, $data) {
        $res = array ();

        foreach ($data as $key => $row){
            if ($key === 'count')   {
                continue;
            }
        
            foreach ($row as $key1 => $param) {
                if ($key1 === 'dn') {
                    $res[$key][$model->name][$key1] = $param;
                    continue;
                }
                if (!is_numeric($key1)) {
                    continue;
                }
                if ($row[$param]['count'] === 1)    {
                    if (in_array($param, ['objectguid', 'objectsid']))   {
                        $row[$param][0] = $this->sid_decode($row[$param][0]);
                    }
                    $res[$key][$model->name][$param] = $row[$param][0];
                } else {
                    foreach ($row[$param] as $key2 => $item) {
                        if ($key2 === 'count')  {
                            continue;
                        }
                        list($k, $v) = $item;
                        $res[$key][$model->name][$param][] = $item;
                    }
                }
            }
        }
        return $res;
    }   //  LdapSource :: _ldapFormat()

/*
 *
 *
 */
    private function _ldapQuote($str) {
        return str_replace(
            array( '\\', ' ', '*', '(', ')' ),
            array( '\\5c', '\\20', '\\2a', '\\28', '\\29' ),
            $str
        );
    }   //  LdapSource :: _ldapQuote()

/*
 *
 *
 */
    private function _parse_list( $i, $strings, &$attrs ) {
/**
 ** A list starts with a ( followed by a list of attributes separated by $ terminated by )
 ** The first token can therefore be a ( or a (NAME or a (NAME)
 ** The last token can therefore be a ) or NAME)
 ** The last token may be terminate by more than one bracket
 */
        $string = $strings[$i];
        if (!preg_match('/^\(/',$string)) {
        // A bareword only - can be terminated by a ) if the last item
            if (preg_match('/\)+$/',$string))   {
                $string = preg_replace('/\)+$/','',$string);
            }
            array_push($attrs, $string);
        } elseif (preg_match('/^\(.*\)$/',$string)) {
            $string = preg_replace('/^\(/','',$string);
            $string = preg_replace('/\)+$/','',$string);
            array_push($attrs, $string);
        } else {
        // Handle the opening cases first
            if ($string == '(') {
                $i++;
            } elseif (preg_match('/^\(./',$string)) {
                $string = preg_replace('/^\(/','',$string);
                array_push ($attrs, $string);
                $i++;
            }
            // Token is either a name, a $ or a ')'
            // NAME can be terminated by one or more ')'
            while (! preg_match('/\)+$/',$strings[$i])) {
                $string = $strings[$i];
                if ($string == '$') {
                    $i++;
                    continue;
                }
                if (preg_match('/\)$/',$string)) {
                    $string = preg_replace('/\)+$/','',$string);
                } else {
                    $i++;
                }
                array_push ($attrs, $string);
            }   //  while()
        }   //  else()
        sort($attrs);
        return $i;
    }   //  LdapSource :: _parse_list()

/*
 * The following was kindly "borrowed" from the excellent 
 *  phpldapadmin project 
 *
 */
    private function __getLDAPschema() {
        $schemaTypes = array( 'objectclasses', 'attributetypes' );
        $this->results = @ldap_read($this->_connection, $this->SchemaDN, 
            $this->SchemaFilter, $schemaTypes,0,0,0,LDAP_DEREF_ALWAYS);
        if( is_null( $this->results ) ) {
            $this->log( "LDAP schema filter $this->SchemaFilter is invalid!", 'ldap.error');
            return false;
        }

        $schema_entries = @ldap_get_entries( $this->_connection, $this->results );
        $return = array();
        if( $schema_entries ) {
            foreach( $schemaTypes as $n ) {
                $schemaTypeEntries = $schema_entries[0][$n];
                for( $x = 0; $x < $schemaTypeEntries['count']; $x++ ) {
                    $entry = array();
                    $strings = preg_split('/[\s,]+/', 
                        $schemaTypeEntries[$x], -1, PREG_SPLIT_DELIM_CAPTURE);
                    $str_count = count( $strings );
                    for ( $i=0; $i < $str_count; $i++ ) {
                        switch ($strings[$i]) {

                        case '(':
                            break;

                        case 'NAME':
                            if ( $strings[$i+1] != '(' ) {
                                do {
                                    $i++;
                                    if( !isset( $entry['name'] ) 
                                    || strlen( $entry['name'] ) == 0 )  {
                                        $entry['name'] = $strings[$i];
                                    } else {
                                        $entry['name'] .= ' '.$strings[$i];
                                    }
                                } while ( !preg_match('/\'$/s', $strings[$i]));
                            } else {
                                $i++;
                                do {
                                    $i++;
                                    if( !isset( $entry['name'] ) 
                                    || strlen( $entry['name'] ) == 0)   {
                                        $entry['name'] = $strings[$i];
                                    } else {
                                        $entry['name'] .= ' ' . $strings[$i];
                                    }
                                } while ( !preg_match( '/\'$/s', $strings[$i] ) );
                                do {
                                    $i++;
                                } while ( !preg_match( '/\)+\)?/', $strings[$i] ) );
                            }
                            $entry['name'] = preg_replace('/^\'/', '', $entry['name'] );
                            $entry['name'] = preg_replace('/\'$/', '', $entry['name'] );
                            break;

                        case 'DESC':
                            do {
                                $i++;
                                if ( !isset( $entry['description'] ) 
                                || strlen( $entry['description'] ) == 0 )   {
                                    $entry['description'] = $strings[$i];
                                } else {
                                    $entry['description'] .= ' ' . $strings[$i];
                                }
                            } while ( !preg_match( '/\'$/s', $strings[$i] ) );
                            break;

                        case 'OBSOLETE':
                            $entry['is_obsolete'] = TRUE;
                            break;

                        case 'SUP':
                            $entry['sup_classes'] = array();
                            if ( $strings[$i+1] != '(' ) {
                                $i++;
                                array_push( $entry['sup_classes'], 
                                    preg_replace( "/'/", '', $strings[$i] ) );
                            } else {
                                $i++;
                                do {
                                    $i++;
                                    if ( $strings[$i] != '$' )  {
                                        array_push( $entry['sup_classes'], 
                                            preg_replace( "/'/", '', $strings[$i] ) );
                                    }
                                } while (! preg_match('/\)+\)?/',$strings[$i+1]));
                            }
                            break;

                        case 'ABSTRACT':
                            $entry['type'] = 'abstract';
                            break;

                        case 'STRUCTURAL':
                            $entry['type'] = 'structural';
                            break;

                        case 'SINGLE-VALUE':
                            $entry['multiValue'] = 'false';
                            break;

                        case 'AUXILIARY':
                            $entry['type'] = 'auxiliary';
                            break;

                        case 'MUST':
                            $entry['must'] = array();
                            $i = $this->_parse_list(++$i, $strings, $entry['must']);
                            break;

                        case 'MAY':
                            $entry['may'] = array();
                            $i = $this->_parse_list(++$i, $strings, $entry['may']);
                            break;

                        default:
                            if( preg_match( '/[\d\.]+/i', $strings[$i]) && $i == 1 ) {
                                $entry['oid'] = $strings[$i];
                            }
                            break;
                        }   //  switch()
                    }   //  for()
                    if( !isset( $return[$n] ) || !is_array( $return[$n] ) ) {
                        $return[$n] = array();
                    }
                    // make lowercase for consistency
                    $return[strtolower($n)][strtolower($entry['name'])] = $entry;
                    // array_push( $return[$n][$entry['name']], $entry );
                }   //  for()
            }   //  foreach()
        }   //  if()
        return $return;
    }   //  LdapSource :: __getLDAPschema()

/*
 *
 *
 */
    private function __getObjectclasses() {
        $cache = null;
        if ($this->cacheSources !== false) {
            if (isset($this->__descriptions['ldap_objectclasses'])) {
                $cache = $this->__descriptions['ldap_objectclasses'];
            } else {
                $cache = $this->__cacheDescription('objectclasses');
            }
        }

        if ($cache != null) {
            return $cache;
        }

        // If we get this far, then we haven't cached the attribute types, yet!
        $ldapschema = $this->__getLDAPschema();
        $objectclasses = $ldapschema['objectclasses'];

        // Cache away
        $this->__cacheDescription( 'objectclasses', $objectclasses );

        return $objectclasses;
    }   //  LdapSource :: __getObjectclasses()

/*
 *
 *
 */
    private function _queryToString($query) {
        $tmp = '';
        if (!empty($query['scope']))    {
            $tmp .= ' | scope: '.$query['scope'];
        }
        if (!empty($query['conditions']))   {
            $tmp .= ' | cond: '. $query['conditions'];
        }
        if (!empty($query['targetDn']))     {
            $tmp .= ' | targetDn: '.$query['targetDn'];
        }
        $fields = '';
        if (!empty($query['fields']) && is_array( $query['fields'] ) ) {
            $fields = implode(', ', $query['fields']);
            $tmp .= ' | fields: '.$fields;
        }

        if (!empty($query['order']))    {                    
            $tmp .= ' | order: '.$query['order'][0];
        }
        if (!empty($query['limit']) && is_string( $query['limit'] ) ) {
            $tmp .= ' | limit: '.$query['limit'];
        }
        return $query['type'] . $tmp;
    }   //  LdapSource :: _queryToString()

/*
 * Courtesy of gabriel at hrz dot uni-marburg dot de 
 * @ http://ar.php.net/ldap_delete
 */
    private function __deleteRecursively( $_dn ) {

        // Search for sub entries
        $subentries = ldap_list( $this->_connection, $_dn, 
            "objectClass=*", array() );
        $info = ldap_get_entries( $this->_connection, $subentries );
        for( $i = 0; $i < $info['count']; $i++ ) {
            // deleting recursively sub entries
            $result = $this->__deleteRecursively( $info[$i]['dn'] );
            if( !$result ) {
                return false;
            }
        }
        return( @ldap_delete( $this->_connection, $_dn ) );
    }   //  LdapSource :: __deleteRecursively()

/*
 *
 *
 */
    private function __mergeAssociation(& $data, $merge, $association, $type) {

        if (isset ($merge[0]) && !isset ($merge[0][$association])) {
            $association = Inflector::pluralize($association);
        }

        if ($type == 'belongsTo' || $type == 'hasOne') {
            if (isset ($merge[$association])) {
                $data[$association] = $merge[$association][0];
            } else {
                if (count($merge[0][$association]) > 1) {
                    foreach ($merge[0] as $assoc => $data2) {
                        if ($assoc != $association) {
                            $merge[0][$association][$assoc] = $data2;
                        }
                    }
                }
                if (!isset ($data[$association])) {
                    $data[$association] = $merge[0][$association];
                } else {
                    if (is_array($merge[0][$association])) {
                        $data[$association] = 
                    array_merge($merge[0][$association], $data[$association]);
                    }
                }
            }
        } else {
            if ($merge[0][$association] === false) {
                if (!isset ($data[$association])) {
                    $data[$association] = array ();
                }
            } else {
                foreach ($merge as $i => $row) {
                    if (count($row) == 1) {
                        $data[$association][] = $row[$association];
                    } else {
                        $tmp = array_merge($row[$association], $row);
                        unset ($tmp[$association]);
                        $data[$association][] = $tmp;
                    }
                }
            }
        }
    }   //  LdapSource :: __mergeAssociation()

/**
 * Private helper method to remove query metadata in given data array.
 *
 * @param array $data
 */
    private function __scrubQueryData(& $data) {
        if (!isset ($data['type'])) {
            $data['type'] = 'default';
        }
        if (!isset ($data['conditions']))   {
            $data['conditions'] = array();
        }
        if (!isset ($data['targetDn']))     {
            $data['targetDn'] = null;
        }
        if (!isset ($data['fields']) && empty($data['fields'])) {
            $data['fields'] = array ();
        }
        if (!isset ($data['order']) && empty($data['order']))   {
            $data['order'] = array ();
        }
        if (!isset ($data['limit']))    {
            $data['limit'] = null;
        }
    }   //  LdapSource :: __scrubQueryData()

}   //  class LdapSource extends DataSource
