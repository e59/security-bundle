<?php

namespace Cangulo\SecurityBundle\Controller;

use Cangulo\SecurityBundle\Entity\Senha;
use Ramsey\Uuid\Uuid;
use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Route;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Security;
use Symfony\Component\Form\Extension\Core\Type\RepeatedType;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Validator\Constraints\Email;
use Symfony\Component\Form\Extension\Core\Type\EmailType;
use Symfony\Component\Form\Extension\Core\Type\PasswordType;
use Symfony\Component\Form\Extension\Core\Type\SubmitType;
use Symfony\Component\Security\Core\Validator\Constraints\UserPassword;
use Symfony\Component\Validator\Constraints\NotBlank;
use Cangulo\SecurityBundle\Entity\Cliente;
use Symfony\Component\Routing\Router;


class DefaultController extends Controller
{

    protected function login(
        $prefix = '',
        $layout = 'CanguloSecurityBundle::layout.html.twig',
        $template = 'CanguloSecurityBundle:Default:login.html.twig'
    ) {
        $authenticationUtils = $this->get('security.authentication_utils');

        // get the login error if there is one
        $error = $authenticationUtils->getLastAuthenticationError();

        // last username entered by the user
        $lastUsername = $authenticationUtils->getLastUsername();

        $form = $this->createFormBuilder()
            ->add('email', EmailType::class,
                [
                    'data' => $lastUsername,
                    'constraints' => [
                        new Email(),
                        new NotBlank(),
                    ],
                ])
            ->add('senha', PasswordType::class,
                [
                    'required' => true,
                    'label' => 'Senha',
                    'constraints' => [
                        new NotBlank(),
                    ],
                ])
            ->add('save', SubmitType::class, array('label' => 'OK', 'attr' => ['class' => 'btn-default']))
            ->getForm();


        return $this->render($template, array(
            'layout' => $layout,
            'last_username' => $lastUsername,
            'error' => $error,
            'form' => $form->createView(),
            'prefix' => $prefix,
        ));
    }

    protected function logout()
    {
        return new Response('');
    }

    protected function passwordChange(
        Request $request,
        $entityManagerName = 'default',
        $prefix = '',
        $layout = 'CanguloSecurityBundle::layout.html.twig',
        $template = 'CanguloSecurityBundle:Default:password_change.html.twig'
    ) {

        $entity = $this->getUser();

        $form = $this->createFormBuilder()
            ->add('senha', PasswordType::class,
                [
                    'required' => true,
                    'label' => 'Senha',
                    'constraints' => [
                        new NotBlank(),
                        new UserPassword(['message' => 'Senha não confere']),
                    ],
                ])
            ->add('nova_senha', RepeatedType::class,
                [
                    'type' => PasswordType::class,
                    'invalid_message' => 'Nova senha e confirmação não conferem',
                    'options' => array('attr' => array('class' => 'password-field')),
                    'required' => true,
                    'first_options' => array('label' => 'Nova senha'),
                    'second_options' => array('label' => 'Confirme a nova senha'),
                ])
            ->add('save', SubmitType::class, array('label' => 'OK', 'attr' => ['class' => 'btn-default']))
            ->getForm();

        $form->handleRequest($request);

        if ($form->isSubmitted() && $form->isValid()) {

            $data = $form->getData();

            $encoder = $this->container->get('security.password_encoder');
            $encoded = $encoder->encodePassword($entity, $data['nova_senha']);
            $entity->setSenha($encoded);

            $em = $this->getDoctrine()->getManager($entityManagerName);
            $em->persist($entity);

            try {
                $em->flush();
                $this->addFlash('success', 'Sua senha foi alterada.');
                return $this->redirectToRoute('homepage');
            } catch (\Exception $e) {
                $this->addFlash('danger',
                    'Erro de sistema. A equipe já foi notificada. Por favor, tente mais tarde.'); // que mentira
            }
        }

        return $this->render($template, [
            'form' => $form->createView(),
            'layout' => $layout,
            'prefix' => $prefix,
        ]);


    }


    protected function passwordRequest(
        Request $request,
        $repository,
        $subject,
        $from,
        $entityManagerName = 'default',
        $destination = 'homepage',
        $layout = 'CanguloSecurityBundle::layout.html.twig',
        $htmlTemplate = 'CanguloSecurityBundle:Default/Emails:password_new.html.twig',
        $textTemplate = 'CanguloSecurityBundle:Default/Emails:password_new.txt.twig',
        $formTemplate = 'CanguloSecurityBundle:Default:password_request.html.twig'
    ) {
        $form = $this->createFormBuilder()
            ->add('email', EmailType::class,
                [
                    'constraints' => [
                        new Email(),
                        new NotBlank(),
                    ],
                ])
            ->add('save', SubmitType::class, array('label' => 'OK', 'attr' => ['class' => 'btn-default']))
            ->getForm();

        $form->handleRequest($request);

        if ($form->isSubmitted() && $form->isValid()) {

            $data = $form->getData();


            $em = $this->getDoctrine()->getManager($entityManagerName);
            $entity = $em->getRepository($repository)->findOneByEmail($data['email']);

            if ($entity) {
                $passwordRequest = new Senha();
                $passwordRequest->setEmail($data['email']);
                $passwordRequest->setToken(base64_encode(random_bytes(10) . '|' . Uuid::uuid4() . '|' . uniqid('token',
                        true) . '|' . microtime()));
                $url = $this->get('router')->generate("$prefix/password-new", ['token' => $passwordRequest->getToken()],
                    Router::ABSOLUTE_URL);
                $em->persist($passwordRequest);

                try {
                    $em->flush();
                    $message = \Swift_Message::newInstance()
                        ->setSubject($subject)
                        ->setFrom($from)
                        ->setTo($data['email'])
                        ->setBody(
                            $this->renderView(
                                $htmlTemplate,
                                [
                                    'entity' => $entity,
                                    'url' => $url,
                                ]
                            ),
                            'text/html'
                        )
                        ->addPart(
                            $this->renderView(
                                $textTemplate,
                                [
                                    'entity' => $entity,
                                    'url' => $url,
                                ]
                            ),
                            'text/plain'
                        );

                    $this->get('mailer')->send($message);

                } catch (\Exception $e) {
                    $this->addFlash('danger',
                        'Erro de sistema. A equipe já foi notificada. Por favor, tente mais tarde.'); // que mentira
                }
            }
            $this->addFlash('success',
                sprintf('Caso o email "%s" possua um cadastro aqui, ele receberá em breve um link para a recriação de sua senha.',
                    $data['email']));
            return $this->redirectToRoute("$prefix");

        }

        return $this->render($formTemplate, [
            'form' => $form->createView(),
            'layout' => $layout,
            'prefix' => $prefix,
        ]);
    }

    protected function passwordNew(
        Request $request,
        $repository,
        $firewall,
        $entityManagerName = 'default',
        $prefix = '',
        $layout = 'CanguloSecurityBundle::layout.html.twig',
        $invalidTemplate = 'CanguloSecurityBundle:Default:password_new__invalid_link.html.twig',
        $formTemplate = 'CanguloSecurityBundle:Default:password_new.html.twig'
    ) {

        $token = $request->query->get('token');

        $em = $this->getDoctrine()->getManager($entityManagerName);

        /** @var $req Senha */
        $req = $em->getRepository('CanguloSecurityBundle:Senha')->obterTokenValido($token);

        if ($req) {

            $entity = $em->getRepository($repository)->findOneByEmail($req->getEmail());

            if ($entity) {
                $form = $this->createFormBuilder()
                    ->add('senha', RepeatedType::class,
                        [
                            'type' => PasswordType::class,
                            'invalid_message' => 'Nova senha e confirmação não conferem',
                            'options' => array('attr' => array('class' => 'password-field')),
                            'required' => true,
                            'first_options' => array('label' => 'Nova senha'),
                            'second_options' => array('label' => 'Confirme a nova senha'),
                        ])
                    ->add('save', SubmitType::class, array('label' => 'OK', 'attr' => ['class' => 'btn-default']))
                    ->getForm();

                $form->handleRequest($request);

                if ($form->isSubmitted() && $form->isValid()) {

                    $data = $form->getData();

                    $encoder = $this->container->get('security.password_encoder');
                    $encoded = $encoder->encodePassword($entity, $data['senha']);
                    $entity->setSenha($encoded);

                    $em->remove($req);

                    try {
                        $em->flush();
                        $this->addFlash('success', 'Sua senha foi criada.');
                        ($this->get('security.login_na_tora'))($entity, $firewall, $entity->getRoles());
                        return $this->redirectToRoute("$destination");
                    } catch (\Exception $e) {
                        $this->addFlash('danger',
                            'Erro de sistema. A equipe já foi notificada. Por favor, tente mais tarde.'); // que mentira
                    }
                }

                return $this->render($formTemplate, [
                    'form' => $form->createView(),
                    'layout' => $layout,
                    'prefix' => $prefix,
                ]);
            }
        }

        return $this->render($invalidTemplate, [
            'prefix' => $prefix,
            'layout' => $layout,
        ]);
    }

}
