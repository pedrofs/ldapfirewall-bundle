<?php
namespace Rheck\LDAPFirewallBundle;

use Rheck\LDAPFirewallBundle\Factory\LDAPFactory;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\HttpKernel\Bundle\Bundle;

class RheckLDAPFirewallBundle extends Bundle
{
    public function build(ContainerBuilder $container)
    {
        parent::build($container);

        $extension = $container->getExtension('security');
        $extension->addSecurityListenerFactory(new LDAPFactory());
    }
}