<?php
/*
 * app/Plugin/Yaldap2/Model/Yaldap2_User.php
 */
class   Yaldap2_User extends AppModel {
    public  $name        = 'Yaldap2_User';
    public  $useDbConfig = 'ldap';   //  cf. app/Config/database.php 
    public  $primaryKey  = 'uid';
    public  $useTable    = 'ou=Users';
}
