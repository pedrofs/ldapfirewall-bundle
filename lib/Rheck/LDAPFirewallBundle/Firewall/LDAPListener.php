<?php
namespace Rheck\LDAPFirewallBundle\Firewall;

use Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Firewall\ListenerInterface;
use Symfony\Component\Security\Core\SecurityContextInterface;
use Rheck\LDAPFirewallBundle\Authentication\Token\LDAPToken;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Bundle\FrameworkBundle\Routing\Router;
use Symfony\Component\HttpFoundation\Response;

class LDAPListener implements ListenerInterface
{

    protected $session;
    protected $securityContext;
    protected $ldapCredentials;
    protected $authenticationManager;
    protected $allowedRoutes = array(
        '_rheck_ldap_login',
        '_rheck_ldap_logincheck'
    );

    public function __construct(SecurityContextInterface $securityContext, AuthenticationManagerInterface $authenticationManager, Session $session, Router $router, $kernel)
    {
        $this->securityContext = $securityContext;
        $this->authenticationManager = $authenticationManager;
        $this->session = $session;
        $this->router = $router;

        $this->ldapCredentials = array(
            'ldap' => array(
                'host' => $kernel->getParameter('rheck_ldap_firewall.ldap_host'),
                'dn'   => $kernel->getParameter('rheck_ldap_firewall.ldap_dn'),
            )
        );
    }

    public function handle(GetResponseEvent $event)
    {
        $request      = $event->getRequest();
        $currentRoute = $request->attributes->get('_route');

        if (!$this->session->has('LDAP_LOGIN_CALLBACK')) {
            if (in_array($currentRoute, $this->allowedRoutes)) {
                // TODO: get the default url
                $this->session->set('LDAP_LOGIN_CALLBACK', '_conradcaine_frontend_default_index');
            } else {
                $this->session->set('LDAP_LOGIN_CALLBACK', $currentRoute);
            }
        }

        if (in_array($currentRoute, $this->allowedRoutes)) {
            return;
        }

        if (!$this->session->has('LDAP_LOGIN')) {
            $event->setResponse(RedirectResponse::create($this->router->generate('_rheck_ldap_login')));
            return;
        }

        $ldapUserCredentials = $this->session->get('LDAP_LOGIN');

        $token = new LDAPToken();
        $token->setUser('ldap_proxy_user');
        $token->setLDAPUserCredentials($ldapUserCredentials);
        $token->setLDAPCredentials($this->ldapCredentials);

        try {
            $authToken = $this->authenticationManager->authenticate($token);

            $this->securityContext->setToken($authToken);
        } catch (AuthenticationException $failed) {
            $this->session->set('LDAP_LOGIN_ERROR', 'Some error was occurred! Can\'t connect to LDAP.');

            $event->setResponse(RedirectResponse::create($this->router->generate('_rheck_ldap_login')));
        } catch (\Exception $e) {
            $this->session->set('LDAP_LOGIN_ERROR', 'Invalid credentials.');

            $event->setResponse(RedirectResponse::create($this->router->generate('_rheck_ldap_login')));
        }
    }
}
