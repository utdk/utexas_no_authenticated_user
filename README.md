# UTexas No Authenticated User

This is a Drupal module that automatically logs out and deletes any user account that only has the "authenticated" user role on any page request.

This is primarily useful on sites where some or all content require an elevated level of access -- beyond simply authentication -- to view.

In the case of using role-based assignment via the [simplesamlphp_auth](https://drupal.org/project/simplesamlphp_auth) module,
this also helpfully prevents populating the Drupal user table with essentially
non-functional accounts.

Full documentation can be found at https://drupalkit.its.utexas.edu/docs/
