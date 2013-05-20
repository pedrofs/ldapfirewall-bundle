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
            ->arrayNode('ldap')
                ->addDefaultsIfNotSet()
                ->children()
                    ->scalarNode('host')->defaultValue('')->end()
                    ->scalarNode('dn')->defaultValue('')->end()
                ->end()
            ->end()
            ->end()
        ;

        return $treeBuilder;
    }
}
?>