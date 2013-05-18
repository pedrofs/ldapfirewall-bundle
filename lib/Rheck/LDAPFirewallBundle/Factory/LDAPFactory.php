<?php
namespace RHeck\LDAPFirewallBundle\Factory;

use Symfony\Bundle\SecurityBundle\DependencyInjection\Security\Factory\SecurityFactoryInterface;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Component\DependencyInjection\DefinitionDecorator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;

class LDAPFactory implements SecurityFactoryInterface
{

    public function create(ContainerBuilder $container, $id, $config, $userProvider, $defaultEntryPoint)
    {
        $providerId = 'security.authentication.provider.ldap.'.$id;
        $container
            ->setDefinition($providerId, new DefinitionDecorator('ldap.security.authentication.provider'))
            ->replaceArgument(0, new Reference($userProvider))
        ;

        $listenerId = 'security.authentication.listener.ldap.'.$id;
        $listener = $container->setDefinition($listenerId, new DefinitionDecorator('ldap.security.authentication.listener'));

        return array($providerId, $listenerId, $defaultEntryPoint);
    }

    public function getPosition()
    {
        return 'pre_auth';
    }

    public function getKey()
    {
        return 'ldap';
    }

    public function addConfiguration(NodeDefinition $node)
    {
    }
}
