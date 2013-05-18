<?php
namespace Rheck\LDAPFirewallBundle\Authentication\Provider;

use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;
use Rheck\LDAPFirewallBundle\Authentication\Token\LDAPToken;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\NonceExpiredException;
use Symfony\Component\Security\Core\User\UserProviderInterface;

class LDAPProvider implements AuthenticationProviderInterface
{

    protected $userProvider;
    protected $cacheDir;

    public function __construct(UserProviderInterface $userProvider, $cacheDir)
    {
        $this->userProvider = $userProvider;
        $this->cacheDir     = $cacheDir;
    }

    public function authenticate(TokenInterface $token)
    {
        $ldapUserCredentials = $token->getLDAPUserCredentials();
        $ldapCredentials     = $token->getLDAPCredentials();

        $ldapConnection = ldap_connect($ldapCredentials['ldap']['host']);

        ldap_set_option($ldapConnection, LDAP_OPT_PROTOCOL_VERSION, 3);
        ldap_set_option($ldapConnection, LDAP_OPT_REFERRALS, 0);

        if ($ldapConnection) {
            $ldapDn = str_replace('USER_CREDENTIAL', $ldapUserCredentials['username'], $ldapCredentials['ldap']['dn']);

            $ldapBind = ldap_bind($ldapConnection, $ldapDn, $ldapUserCredentials['password']);

            if (true === $ldapBind) {
                $ldapRead  = ldap_read($ldapConnection, $ldapDn, "(objectclass=*)", array('ou', 'sn', 'cn', 'mail'));
                $ldapEntry = ldap_get_entries($ldapConnection, $ldapRead);

                if (is_array($ldapEntry) && isset($ldapEntry['count']) && $ldapEntry['count']) {
                    $ldapUserObject = $ldapEntry[0];

                    $user = $this->userProvider->loadUserByUsername($ldapUserCredentials['username']);
                    
                    if (!$user) {
                        throw new AuthenticationException('The user was found on LDAP but don\'t exist on system.');
                    }

                    $authenticatedToken = new LDAPToken($user->getRoles());
                    $authenticatedToken->setUser($user);
                    $authenticatedToken->setLDAPUserCredentials($ldapUserCredentials);
                    $authenticatedToken->setLDAPCredentials($ldapCredentials);

                    return $authenticatedToken;
                }
            }

            throw new AuthenticationException('The LDAP credentials are not found.');
        }

        throw new AuthenticationException('The LDAP authentication failed.');
    }

    public function supports(TokenInterface $token)
    {
        return $token instanceof LDAPToken;
    }
}
