# Oh my OAuth!

_Oh my OAuth!_ is a java client library for OAuth 2.0. It fits within server side applications also known
as confidential clients in the OAuth lingo. It supports the Authorization Code Flow and is capable of refreshing
access tokens.

Usage of _Oh my OAuth!_ is rather limited. It only supports the Amazon Cognito as OAuth 2.0 provider.
There are no Maven coordinates and the documentation is pretty much left in the code. 

Under no circumstances is this project in a production ready state.

## Requirements

This project tries to align itself with Jakarta EE Platform, version 9

* Jakarta Servlet API 5.0
* Jakarta JSON Processing 2.0
* Java Version 11

## Getting started with Amazon Cognito

At its core _Oh my OAuth!_ is only filter definition in web.xml.

```
<filter>
    <filter-name>OhMyOAuth</filter-name>
    <filter-class>org.myoauth.MyOAuthFilter</filter-class>
    <!--Cognito User Pool Id -->
    <init-param>
        <param-name>userPoolId</param-name>
        <param-value>eu-central-1_ABCDEF</param-value>
    </init-param>
    <!-- App client id -->
    <init-param>
       <param-name>clientId</param-name>
       <param-value>abc1234567890</param-value>
    </init-param>
    <!-- App client secret -->
    <init-param>
        <param-name>clientSecret</param-name>
        <param-value>xxx</param-value>
    </init-param>
    <!-- Amazon Cognito domain -->
    <init-param>
        <param-name>prefixDomainName</param-name>
        <param-value>someprefix</param-value>
    </init-param>
    <!-- AWS Region -->
    <init-param>
        <param-name>region</param-name>
        <param-value>eu-central-1</param-value>
    </init-param>
    <!-- Callback URL(s) -->
    <init-param>
        <param-name>redirectURI</param-name>
        <param-value>https://host.example.com/callback</param-value>
    </init-param>
</filter>

<filter-mapping>
    <filter-name>OhMyOAuth</filter-name>
    <url-pattern>/*</url-pattern>
</filter-mapping>
```

## License

BSD 0-Clause License (0BSD)

