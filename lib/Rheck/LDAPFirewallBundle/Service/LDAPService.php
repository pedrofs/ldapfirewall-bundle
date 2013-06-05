<?php
namespace Rheck\LDAPFirewallBundle\Service;

class LDAPService
{
    protected $connection;

    protected $host;
    protected $dn;
    protected $roleDn;

    public function __construct($kernel)
    {
        $this->host   = $kernel->getParameter('rheck_ldap_firewall.ldap.host');
        $this->dn     = $kernel->getParameter('rheck_ldap_firewall.ldap.dn');
        $this->roleDn = $kernel->getParameter('rheck_ldap_firewall.ldap.roleDn');
    }

    public function bind($connection, $username, $password)
    {
        return ldap_bind($connection, 'uid=' . $username . ',' . $this->getDn(), $password);
    }

    public function read($connection, $dn, $attributes, $attrsOnly = array())
    {
        $read = ldap_read($connection, $dn, $attributes, $attrsOnly);

        return ldap_get_entries($connection, $read);
    }

    public function search($connection, $dn, $attributes, $attrsOnly = array())
    {
        $search = ldap_search($connection, $dn, $attributes, $attrsOnly);

        return ldap_get_entries($connection, $search);
    }

    public function getConnection()
    {
        if (is_null($this->connection)) {
            $connection = ldap_connect($this->host);

            ldap_set_option($connection, LDAP_OPT_PROTOCOL_VERSION, 3);
            ldap_set_option($connection, LDAP_OPT_REFERRALS, 0);

            $this->connection = $connection;
        }

        return $this->connection;
    }

    public function getDn()
    {
        return $this->dn;
    }

    public function getRoleDn()
    {
        return $this->roleDn;
    }

}