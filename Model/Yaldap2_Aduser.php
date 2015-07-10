<?php
/*
 * app/Plugin/Yaldap2/Model/Yaldap2_Aduser.php
 *  ActiveDirectory Access Class
 *
 */
class   Aduser    extends AppModel {
    public  $name        = 'Aduser';
    public  $useDbConfig = 'ad';   //  app/Config/database.php のメンバ変数名
    public  $primaryKey  = 'cn';
    public  $useTable    = 'ou=Users';
/**
 * decode avtive directory's XXsid
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
    }   //  Aduser :: sid_decode()

}   //  class   Aduser    extends AppModel {
