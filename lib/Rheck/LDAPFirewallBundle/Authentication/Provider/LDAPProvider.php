<?php
namespace Rheck\LDAPFirewallBundle\Authentication\Provider;

use ConradCaine\Core\Library\EntityBundle\Entity\User;
use Rheck\LDAPFirewallBundle\Service\LDAPService;
use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;
use Rheck\LDAPFirewallBundle\Authentication\Token\LDAPToken;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\NonceExpiredException;
use ConradCaine\Core\Library\EntityBundle\Manager\EntityLibrary;
use Symfony\Component\Security\Core\User\UserProviderInterface;

class LDAPProvider implements AuthenticationProviderInterface
{

    protected $entityLibrary;
    protected $userProvider;
    protected $ldapService;
    protected $cacheDir;

    public function __construct(UserProviderInterface $userProvider, $cacheDir, EntityLibrary $entityLibrary, LDAPService $ldapService)
    {
        $this->userProvider  = $userProvider;
        $this->cacheDir      = $cacheDir;
        $this->entityLibrary = $entityLibrary;
        $this->ldapService   = $ldapService;
    }

    public function authenticate(TokenInterface $token)
    {
        $ldapUserCredentials = $token->getLDAPUserCredentials();

        $ldapConnection = $this->ldapService->getConnection();

        if ($ldapConnection) {
            $ldapBind = $this->ldapService->bind($ldapConnection, $ldapUserCredentials['username'], $ldapUserCredentials['password']);

            if (true === $ldapBind) {
                $ldapEntry = $this->ldapService->read($ldapConnection, "uid=" . $ldapUserCredentials['username'] . "," . $this->ldapService->getDn(), "(objectclass=*)", array('ou', 'sn', 'cn', 'mail'));

                if (is_array($ldapEntry) && isset($ldapEntry['count']) && $ldapEntry['count']) {
                    $ldapUserObject = $ldapEntry[0];

                    $user = $this->entityLibrary->get('User')->findOneByUsername($ldapUserCredentials['username']);

                    if (!$user) {
                        $roleGeneral  = $this->entityLibrary->get('Role')->findOneByName('ROLE_GENERAL');
                        $groupGeneral = $this->entityLibrary->get('UserGroup')->findOneByName('General');

                        $user = new User();
                        $user->setName($ldapUserObject['cn'][0] . ' ' . $ldapUserObject['sn'][0]);
                        $user->setEmail($ldapUserObject['mail'][0]);
                        $user->setUsername($ldapUserCredentials['username']);
                        $user->setSalt(uniqid());
                        $user->addRole($roleGeneral);
                        $user->addUserGroup($groupGeneral);

                        $this->entityLibrary->get('User')->save($user);
                    }

                    $authenticatedToken = new LDAPToken($user->getRoles());
                    $authenticatedToken->setUser($user);
                    $authenticatedToken->setLDAPUserCredentials($ldapUserCredentials);

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
