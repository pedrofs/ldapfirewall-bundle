<?php
namespace Rheck\LDAPFirewallBundle\DependencyInjection;

use Symfony\Component\HttpKernel\DependencyInjection\Extension;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\Config\Definition\Processor;
use Symfony\Component\DependencyInjection\Loader;
use Symfony\Component\Config\FileLocator;

class RheckLDAPFirewallExtension extends Extension
{
    public function load(array $configs, ContainerBuilder $container)
    {
        $configuration = new Configuration();
        $processor     = new Processor();
        $config        = $processor->processConfiguration($configuration, $configs);

        $container->setParameter('rheck_ldap_firewall.default_url', $config['default_url']);
        $container->setParameter('rheck_ldap_firewall.login_url', $config['login_url']);
        $container->setParameter('rheck_ldap_firewall.ldap.host', $config['ldap']['host']);
        $container->setParameter('rheck_ldap_firewall.ldap.dn', $config['ldap']['dn']);
        $container->setParameter('rheck_ldap_firewall.ldap.roleDn', $config['ldap']['roleDn']);

        $loader = new Loader\YamlFileLoader(
            $container,
            new FileLocator(__DIR__.'/../Resources/config')
        );

        $loader->load('authentication.yml');
    }
}