<?php
namespace Rheck\LDAPFirewallBundle\Authentication\Provider;

interface EntityLibraryInterface
{
    public function get($model);
}