# acme-distributed
Simple ACME client for distributed certificate ordering

# Description
**acme-distributed** is a simple ACME client for special use cases. It does not implement all functionality that other ACME clients offer. If you are just looking for an ordinary ACME client, please look elsewhere.

The corner case implemented by this client is the separation of certificate ordering from fullfilling http-01 authorization requests. This can be useful in the following scenarios:

* You can not have (or do not want) the ACME client on your web server(s) for whatever reasons
* Your webservers cannot initiate connections to the outside world
* You do not want your private account key on your web servers
* You want to centralize your LE certficate management and not have multiple hosts (i.e. your webservers) being responsible for that

# Requirements
**acme-distributed** requires

* Ruby 2.2 or higher
* The following ruby gems
  * acme-client
  * net-ssh
  
The host managing the certificates needs SSH access to the hosts serving the authorization requests. The only privilege required for the user is write access to the directory where the authorization requests are created.
