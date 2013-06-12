<?php
namespace Rheck\LDAPFirewallBundle\Controller;

use Symfony\Component\Security\Core\Authentication\Token\AnonymousToken;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Template;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Method;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Route;
use Symfony\Bundle\FrameworkBundle\Controller\Controller;

class AuthenticationController extends Controller {

    /**
     * @Template("RheckLDAPFirewallBundle:Authentication:login.html.twig")
     * @Route("/login", name="_rheck_ldap_login")
     * @Method("GET")
     */
    public function loginAction() {
        $securityContext = $this->get('security.context');
        $session         = $this->get('session');

        if (!$securityContext->getToken() instanceof AnonymousToken) {
            $defaultUrl = $this->container->getParameter('rheck_ldap_firewall.default_url');
            return $this->redirect($this->generateUrl($defaultUrl));
        }

        $error = null;
        if ($session->has('LDAP_LOGIN_ERROR')) {
            $error = $session->get('LDAP_LOGIN_ERROR');
            $session->remove('LDAP_LOGIN_ERROR');
        }

        $username = '';
        if ($session->has('LDAP_LOGIN')) {
            $ccLogin = $session->get('LDAP_LOGIN');
            $username = $ccLogin['username'];
        }

        return array(
            'lastUsername' => $username,
            'error'        => $error
        );
    }

    /**
     * @Route("/login-check", name="_rheck_ldap_logincheck")
     * @Method("POST")
     */
    public function loginCheckAction() {
        $request = $this->get('request');
        $session = $this->get('session');

        $loginParams = $request->request->get('login');

        $session->set(
            'LDAP_LOGIN',
            array(
                'username' => $loginParams['_username'],
                'password' => $loginParams['_password']
            )
        );

//        if ($session->has('LDAP_LOGIN_CALLBACK')) {
//            $callbackUrl = $session->get('LDAP_LOGIN_CALLBACK');
//            $session->remove('LDAP_LOGIN_CALLBACK');
//
//            return $this->redirect($this->generateUrl($callbackUrl));
//        }

        $defaultUrl = $this->container->getParameter('rheck_ldap_firewall.default_url');
        return $this->redirect($this->generateUrl($defaultUrl));
    }

}
