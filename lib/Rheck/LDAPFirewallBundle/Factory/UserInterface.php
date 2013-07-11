<?php
namespace RHeck\LDAPFirewallBundle\Factory;

interface UserInterface
{
    public function setName($name);

    public function setEmail($email);

    public function setUserName($userName);

    public function setSalt($salt);

    public function addRole($role);

    public function addUserGroup($group);
}
