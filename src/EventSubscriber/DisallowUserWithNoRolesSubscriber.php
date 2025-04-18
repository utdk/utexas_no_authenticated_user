<?php

namespace Drupal\utexas_no_authenticated_user\EventSubscriber;

use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Extension\ModuleHandler;
use Drupal\Core\Logger\LoggerChannelFactoryInterface;
use Drupal\Core\Routing\RouteMatchInterface;
use Drupal\Core\Routing\TrustedRedirectResponse;
use Drupal\Core\Session\AccountInterface;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * Event subscriber subscribing to KernelEvents::REQUEST.
 */
class DisallowUserWithNoRolesSubscriber implements EventSubscriberInterface {

  /**
   * The exception boolean.
   *
   * @var bool
   */
  protected bool $exception = FALSE;

  /**
   * The current account.
   *
   * @var \Drupal\Core\Session\AccountInterface
   */
  protected $account;

  /**
   * A configuration object.
   *
   * @var \Drupal\Core\Config\ImmutableConfig
   */
  protected $config;

  /**
   * Logger Factory.
   *
   * @var \Drupal\Core\Logger\LoggerChannelFactoryInterface
   */
  protected $loggerFactory;

  /**
   * The current route match.
   *
   * @var \Drupal\Core\Routing\RouteMatchInterface
   */
  protected $routeMatch;

  /**
   * The Drupal module helper.
   *
   * @var \Drupal\Core\Extension\ModuleHandler
   */
  protected $moduleHandler;

  /**
   * The Drupal entity manager.
   *
   * @var \Drupal\Core\Entity\EntityTypeManagerInterface
   */
  protected $entityTypeManager;

  /**
   * {@inheritdoc}
   *
   * @param \Drupal\Core\Session\AccountInterface $account
   *   The current account.
   * @param Drupal\Core\Logger\LoggerChannelFactoryInterface $loggerFactory
   *   A logger instance.
   * @param \Drupal\Core\Routing\RouteMatchInterface $route_match
   *   The current route match.
   * @param \Drupal\Core\Extension\ModuleHandlerInterface $module_handler
   *   The module handler.
   * @param \Drupal\Core\Entity\EntityTypeManagerInterface $entityTypeManager
   *   The entity type manager.
   */
  public function __construct(AccountInterface $account, LoggerChannelFactoryInterface $loggerFactory, RouteMatchInterface $route_match, ModuleHandler $module_handler, EntityTypeManagerInterface $entityTypeManager) {
    $this->account = $account;
    $this->loggerFactory = $loggerFactory->get('utexas_no_authenticated_user');
    $this->routeMatch = $route_match;
    $this->moduleHandler = $module_handler;
    $this->entityTypeManager = $entityTypeManager;
  }

  /**
   * Evaluate 403s and 404s requested by users with just the authenticated role.
   *
   * @param \Symfony\Component\HttpKernel\Event\RequestEvent $event
   *   The subscribed event.
   */
  public function onExceptionRedirect(RequestEvent $event) {
    $exception = $event->getThrowable();
    if ($exception instanceof NotFoundHttpException || $exception instanceof AccessDeniedHttpException) {
      if ($this->userHasOnlyAuthenticatedRole()) {
        $this->logoutDeleteUser($event);
      }
      $this->exception = TRUE;
    }
  }

  /**
   * On 2xx requests, Log out & delete user with only "authenticated" role.
   *
   * @param \Symfony\Component\HttpKernel\Event\RequestEvent $event
   *   The subscribed event.
   */
  public function onRequestRedirect(RequestEvent $event) {
    if ($event->getRequestType() !== 1) {
      // Prevent evaluations on sub requests.
      return;
    }
    // Here we are handling responses that are not 403s or 404s.
    if (!$this->exception && $this->userHasOnlyAuthenticatedRole()) {
      $this->logoutDeleteUser($event);
    }
  }

  /**
   * Whether the request is coming from a user with only 'authenticated' role.
   *
   * @return bool
   *   TRUE only if the user only has the 'authenticated' role.
   */
  public function userHasOnlyAuthenticatedRole() {
    if ($this->account->isAnonymous()) {
      return FALSE;
    }
    $uid = (int) $this->account->id();
    $roles = $this->account->getRoles();
    if ($uid !== 1 && $roles == ['authenticated']) {
      return TRUE;
    }
    return FALSE;
  }

  /**
   * Perform the actual logout, delete, and redirection.
   *
   * @param \Symfony\Component\HttpKernel\Event\RequestEvent $event
   *   The subscribed event.
   */
  public function logoutDeleteUser($event) {
    $this->loggerFactory->notice('The account with username @username was automatically deleted since the account had no roles.', [
      '@username' => $this->account->getAccountName(),
    ]);
    $uid = (int) $this->account->id();
    $this->entityTypeManager->getStorage('user')->load($uid)->delete();
    // If using Enterprise Authentication, redirect to the EntAuth portal.
    if ($this->moduleHandler->moduleExists('samlauth')) {
      $response = new TrustedRedirectResponse('https://enterprise.login.utexas.edu/idp/profile/Logout', RedirectResponse::HTTP_FOUND);
    }
    else {
      $response = new RedirectResponse('/user/logout', RedirectResponse::HTTP_FOUND);
    }
    $event->setResponse($response);
  }

  /**
   * {@inheritdoc}
   */
  public static function getSubscribedEvents(): array {
    // Scenarios where the request returns an exception, like a 403.
    $events[KernelEvents::EXCEPTION][] = ['onExceptionRedirect'];
    // Scenarios where the request is normal, e.g. 200.
    $events[KernelEvents::REQUEST][] = ['onRequestRedirect', 31];
    return $events;
  }

}
