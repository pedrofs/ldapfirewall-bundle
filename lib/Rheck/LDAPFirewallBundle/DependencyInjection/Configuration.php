<?php
namespace Rheck\LDAPFirewallBundle\DependencyInjection;

use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;

class Configuration implements ConfigurationInterface
{
    public function getConfigTreeBuilder()
    {
        $treeBuilder = new TreeBuilder();
        $rootNode = $treeBuilder->root('rheck_ldap_firewall');

        $rootNode
            ->children()
            ->scalarNode('default_url')->defaultValue('')->end()
            ->scalarNode('login_url')->defaultValue('_rheck_ldap_login')->end()
            ->scalarNode('ldap_host')->defaultValue('')->end()
            ->scalarNode('ldap_dn')->defaultValue('')->end()
            ->end()
        ;

        return $treeBuilder;
    }
}
?>