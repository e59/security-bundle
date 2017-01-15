<?php
namespace Cangulo\SecurityBundle\Security;

use Symfony\Component\DependencyInjection\ContainerAwareInterface;
use Symfony\Component\DependencyInjection\ContainerAwareTrait;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\User\UserInterface;

class LoginNaTora implements ContainerAwareInterface {
    use ContainerAwareTrait;

    public function __construct(ContainerInterface $container)
    {
        $this->setContainer($container);
    }

    public function __invoke(UserInterface $user, $firewall, $roles) {
        $token = new UsernamePasswordToken($user, null, $firewall, $roles);
        $this->container->get('security.token_storage')->setToken($token);
        $this->container->get('session')->set('_security_' . $firewall, serialize($token));
    }
}
