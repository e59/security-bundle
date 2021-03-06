<?php

namespace Cangulo\SecurityBundle\Entity\Repository;

use Carbon\Carbon;

/**
 * SenhaRepository
 *
 * This class was generated by the Doctrine ORM. Add your own custom
 * repository methods below.
 */
class SenhaRepository extends \Doctrine\ORM\EntityRepository
{

    public function obterTokenValido($token)
    {

        return $this->getEntityManager()
            ->createQuery('SELECT p FROM CanguloSecurityBundle:Senha p where p.token = :token and p.criado >= :criado')
            ->setParameter('token', $token)
            ->setParameter('criado', Carbon::now()->subDays(3))
            ->getOneOrNullResult();
    }
}
