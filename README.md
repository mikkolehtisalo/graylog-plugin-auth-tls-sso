# TLS SSO Authentication Plugin for Graylog

This is a fork of the [Graylog SSO plugin](https://github.com/Graylog2/graylog-plugin-auth-sso) for TLS 
certificate based SSO. At this moment only the [FINeID](http://vrk.fi/varmenteet-fineid) smart cards are 
supported, but adding more smart card and certificate types should be very easy.

**Required Graylog version:** 2.1.0 and later

Installation
------------

[Download the plugin](https://github.com/mikkolehtisalo/graylog-plugin-auth-tls-sso/releases)
and place the `.jar` file in your Graylog plugin directory. The plugin directory
is the `plugins/` folder relative from your `graylog-server` directory by default
and can be configured in your `graylog.conf` file. 

Configure the web server or the load balancer to handle client certificate authentication, and to pass the certificate
information to Graylog. It is important to notice that **the plugin does not validate the certificates**. This must be
 done by the front-end services.
 
Remember to restart `graylog-server`, and the web server or load balancer after configuration changes.

Example configuration for Apache (2.3.3+)
------------------------------------------

```
# Basics
SSLEngine on
SSLCertificateFile      /etc/ssl/certs/graylog-server.pem
SSLCertificateKeyFile /etc/ssl/private/graylog-server.key

# TLS settings to secure (modern) defaults
SSLProtocol             all -SSLv3 -TLSv1 -TLSv1.1
SSLCipherSuite          ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256
SSLHonorCipherOrder     on
SSLCompression          off
SSLSessionTickets       off
 
# Client certificate authentication
# SSLCACertificateFile should contain the CA certificate chain of the valid client certificates
SSLCACertificateFile "/etc/ssl/certs/vrk.pem"
SSLVerifyClient require
SSLVerifyDepth 10
 
# HSTS
Header always set Strict-Transport-Security "max-age=15768000"
 
# Enable OCSP Stapling
SSLUseStapling          on
SSLStaplingResponderTimeout 5
SSLStaplingReturnResponderErrors off
SSLStaplingCache        shmcb:/var/run/ocsp(128000)

# Add the authentication header to the requests that are proxied to Graylog
SSLOptions +ExportCertData
RequestHeader set tls-client-cert "%{SSL_CLIENT_CERT}s"

# OCSP
SSLOCSPEnable on
```

Example configuration for F5 BIG-IP
-------------------------------------

Configure the following:

* Import the front-end certificate and keys
* Import CA certificates of the clients, as concatenated PEM
* Change the (client) SSL profile to *require* client authentication, and add the CA certificates
* Add certificate validation (OCSP/CRL) related configuration to client profile
* Add to virtual Service: Service port 443 (HTTPS), http profile, SSL profile (client/clientssl)
* Add an iRule for injecting the header to the virtual service

Example iRule:

```
 when HTTP_REQUEST {
    if { [SSL::cert count] > 0 } {
        HTTP::header insert "tls-client-cert" [X509::whole [SSL::cert 0]]
    }
}
```

Development
-----------

You can improve your development experience for the web interface part of your plugin
dramatically by making use of hot reloading. To do this, do the following:

* `git clone https://github.com/Graylog2/graylog2-server.git`
* `cd graylog2-server/graylog2-web-interface`
* `ln -s $YOURPLUGIN plugin/`
* `npm install && npm start`

Getting started
---------------

This project is using Maven 3 and requires Java 8 or higher.

* Clone this repository.
* Run `mvn package` to build a JAR file.
* Optional: Run `mvn jdeb:jdeb` and `mvn rpm:rpm` to create a DEB and RPM package respectively.
* Copy generated JAR file in target directory to your Graylog plugin directory.
* Restart the Graylog.

Plugin Release
--------------

We are using the maven release plugin:

```
$ mvn release:prepare
[...]
$ mvn release:perform
```

This sets the version numbers, creates a tag and pushes to GitHub. Travis CI will build the release artifacts and upload to GitHub automatically.
