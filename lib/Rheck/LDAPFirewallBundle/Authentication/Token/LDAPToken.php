<?php
namespace Rheck\LDAPFirewallBundle\Authentication\Token;

use Symfony\Component\Security\Core\Authentication\Token\AbstractToken;

class LDAPToken extends AbstractToken
{
    protected $ldapUserCredentials;
    protected $ldapCredentials;

    public function __construct(array $roles = array())
    {
        parent::__construct($roles);

        // If the user has roles, consider it authenticated
        $this->setAuthenticated(count($roles) > 0);
    }

    public function getCredentials()
    {
        return '';
    }

    public function setLDAPUserCredentials($ldapUserCredentials)
    {
        $this->ldapUserCredentials = $ldapUserCredentials;
    }

    public function getLDAPUserCredentials()
    {
        return $this->ldapUserCredentials;
    }

    public function setLDAPCredentials($ldapCredentials)
    {
        $this->ldapCredentials = $ldapCredentials;
    }

    public function getLDAPCredentials()
    {
        return $this->ldapCredentials;
    }
}
