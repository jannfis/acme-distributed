# acme-distributed
Simple command line ACME client for distributed certificate ordering. It's a rather dirty hack. Use at your own risk.

# Description
**acme-distributed** is a simple ACME client for special use cases. It does not implement all functionality that other ACME clients offer. If you are just looking for an ordinary ACME client, please look elsewhere.

The corner case implemented by this client is the separation of certificate ordering from fullfilling http-01 authorization requests. This can be useful in the following scenarios:

* You can not have (or do not want) the ACME client on your web server(s) for whatever reasons
* Your webservers cannot initiate connections to the outside world
* You do not want your private account key on your web servers
* You want to centralize your LE certficate management and not have multiple hosts (i.e. your webservers) being responsible for that

Please note that **acme-distributed** will not (nor will ever) deploy any certificates to your servers. This task is left to whatever configuration management or provisioning tools you might have in place.

# Requirements
**acme-distributed** requires

* Ruby 2.2 or higher
* The following ruby gems
  * acme-client
  * net-ssh
  
The host managing the certificates needs SSH access to the hosts serving the authorization requests. The only privilege required for the user is write access to the directory where the authorization requests are created.

# Configuration
**acme-distributed** uses configuration files in simple YAML format. The following configurables are available:

## Endpoint configuration
Define the available ACME endpoints for this configuration.  

* **url** is the ACME API endpoint URL to use
* **private_key** refers to the account's private RSA key in PEM format. It must exist (i.e. you need to have setup an account before)

The **url** and **private_key** options are mandatory.

You can name the endpoints as you wish, the names **production** and **staging** below are just examples.

```yaml
endpoints:                                                                                                                                                                  
  production:                                                                                                                                                               
    url: https://acme-v02.api.letsencrypt.org/directory                                                                                                                     
    private_key: /etc/acme-deploy/accounts/production/private-key.pem                                                                                                       
    email_addr: certs@example.com
  staging:
    url: https://acme-staging-v02.api.letsencrypt.org/directory
    private_key: /etc/acme-deploy/accounts/staging/private-key.pem
    email_addr: certs@example.com
```
## Certificate configuration
You can define any number of certificates **acme-distributed** should handle. Each certificate needs a unique name name, which is given as the entry key.

* **subject** specifies the CN in the certificate's subject
* **key** specifies the (local) path to the private key used for generating the CSR and for the final certificate
* **path** specifies the (local) path the final certificate will be stored at in PEM format
* **san** specifies a list of additional DNS names the certificate shall be valid for

The options **subject**, **key** and **path** are mandatory.

```yaml
certificates:
  ssl.example.com:
    subject: ssl.example.com
    san:
      - ssl2.example.com
      - ssl3.example.com
    key: /etc/acme-deploy/keys/ssl.example.com.key
    path: /etc/acme-deploy/certs/ssl.example.com.pem

  secure.example.com:
    subject: secure.example.com
    key: /etc/acme-deploy/keys/secure.example.com.key
    path: /etc/acme-deploy/certs/secure.example.com.pem

```
## Authorization server configuration
The list of servers which will handle the http-01 authorization challenges are defined here. You can define any number of servers you wish, and you should define all servers here that will have the certificates deployed (e.g. those that will terminate SSL requests for the FQDNs specified in the configured certificates.)

* **hostname** specifies the DNS hostname (or IP address) of the server to connect to via SSH
* **username** specifies the remote username to use
* **ssh_port** specifies the TCP port the SSH daemon on the server listens to
* **acme_path** specifies the path on the remote server where authorization challenges are put

The **hostname** and **acme_path** options are mandatory.

If **username** is not given, the name of the local user will be used for SSH login.
If **ssh_port** is not given, the standard value of 22 will be used.

```yaml
webservers:
  frontend_web_1:
    hostname: www1.example.com
    username: acme
    ssh_port: 22
    acme_path: /var/www/acme
  frontend_web_2:
    hostname: www2.example.com
    username: acme
    ssh_port: 22
    acme_path: /var/www/acme

```
