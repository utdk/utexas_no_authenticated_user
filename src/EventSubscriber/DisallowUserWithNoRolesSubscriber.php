<?php

namespace Drupal\utexas_no_authenticated_user\EventSubscriber;

use Drupal\Core\Logger\LoggerChannelFactoryInterface;
use Drupal\Core\Routing\RouteMatchInterface;
use Drupal\Core\Session\AccountInterface;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * Event subscriber subscribing to KernelEvents::REQUEST.
 */
class DisallowUserWithNoRolesSubscriber implements EventSubscriberInterface {

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
   * {@inheritdoc}
   *
   * @param \Drupal\Core\Session\AccountInterface $account
   *   The current account.
   * @param Drupal\Core\Logger\LoggerChannelFactoryInterface $loggerFactory
   *   A logger instance.
   * @param \Drupal\Core\Routing\RouteMatchInterface $route_match
   *   The current route match.
   */
  public function __construct(AccountInterface $account, LoggerChannelFactoryInterface $loggerFactory, RouteMatchInterface $route_match) {
    $this->account = $account;
    $this->loggerFactory = $loggerFactory->get('utexas_no_authenticated_user');
    $this->routeMatch = $route_match;
  }

  /**
   * Log out & delete any user that only has the "authenticated" role.
   *
   * @param \Symfony\Component\HttpKernel\Event\RequestEvent $event
   *   The subscribed event.
   */
  public function checkAuthStatus(RequestEvent $event) {
    if ($this->account->isAnonymous()) {
      return;
    }
    $uid = (int) $this->account->id();
    $roles = $this->account->getRoles();
    if ($uid !== 1 && $roles == ['authenticated']) {
      $this->loggerFactory->notice('The account with username @username was automatically deleted since the account had no roles.', [
        '@username' => $this->account->getAccountName(),
      ]);
      // Dependency injection is more complicated code than static calls
      // and therefore has a negative Developer Experience (DX) for our team.
      // We mark these PHPCS standards as ignored.
      // phpcs:ignore
      \Drupal::entityTypeManager()->getStorage('user')->load($uid)->delete();
      $response = new RedirectResponse('/system/403', RedirectResponse::HTTP_FOUND);
      $event->setResponse($response);
    }
  }

  /**
   * {@inheritdoc}
   */
  public static function getSubscribedEvents(): array {
    $events[KernelEvents::REQUEST][] = ['checkAuthStatus'];
    return $events;
  }

}
