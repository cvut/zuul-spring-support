Zuul Spring Support [![Build Status](https://travis-ci.org/cvut/zuul-spring-support.png)](https://travis-ci.org/cvut/zuul-spring-support)
===================

This project provides some convenient classes for OAuth 2.0 resource providers and clients implemented with [Spring Security OAuth][spring-security-oauth].


Standalone Resource Provider
----------------------------

With Spring Security OAuth it’s quite easy to split an _authorization server_ and a _resource provider_ into separate components (Zuul OAAS is a standalone authorization server). Everything you need on the resource provider side is to implement [ResourceServerTokenServices][] that somehow verifies tokens on a remote authorization server.

If you’re using Zuul OAAS (and potentially other authorization servers), there’s such a class – [RemoteResourceTokenServices][].

### XML configuration

There’s an example of using `oauth:resource-server` with `RemoteResourceTokenServices`. The OAAS TokenInfo endpoint is itself secured with OAuth 2.0.

```xml
    <oauth:resource-server id="resourceServerFilter"
           token-services-ref="tokenServices" />

    <bean id="tokenServices" class="cz.cvut.zuul.support.spring.provider.RemoteResourceTokenServices"
          p:restTemplate-ref="tokenInfoRestTemplate"
          p:tokenInfoEndpointUrl="https://oaas.example.org/api/v1/tokeninfo" />

    <oauth:rest-template id="tokenInfoRestTemplate" resource="tokeninfo-resource" />

    <oauth:resource id="tokeninfo-resource"
           type="client_credentials"
           client-id="264ff434-1d2e-46b9-a3c8-fa7d182b7190"
           client-secret="kahc2fai1eo6uip5ied2deishei5ooNg"
           scope="urn:zuul:oauth:oaas:tokeninfo"
           access-token-uri="https://oaas.example.org/oauth/token"
           client-authentication-scheme="form" />
```

For a complete configuration see [this sample][provider-security.xml].

### Java-based configuration

If you prefer Java-based configuration instead, then you can simply extend our [OAuth2ResourceServerConfigurerAdapter][], define security rules and provide your `ResourceServerTokenServices`… that’s all you need to secure resource provider (and register [springSecurityFilterChain][] of course)! There’s also a convenient [RemoteResourceTokenServicesBuilder][] for [RemoteResourceTokenServices][].

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig extends OAuth2ResourceServerConfigurerAdapter {

    protected ResourceServerTokenServices getResourceServerTokenServices() {
        return new RemoteResourceTokenServicesBuilder()
                .tokenInfoEndpointUri( "https://oaas.example.org/api/v1/tokeninfo" )
                .secured()
                    .clientId( "264ff434-1d2e-46b9-a3c8-fa7d182b7190" )
                    .clientSecret( "kahc2fai1eo6uip5ied2deishei5ooNg" )
                    .scope( "urn:zuul:oauth:oaas:tokeninfo" )
                    .accessTokenUri( "https://oaas.example.org/oauth/token" )
                    .clientAuthenticationScheme( AuthenticationScheme.form )
                .build();
    }

    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/api/**")
                    .access("#oauth2.hasScope('urn:zuul:oauth:sample.read')");
    }
}
```


Programmatic creation of OAuth2RestTemplate
-------------------------------------------

Spring Security OAuth2 it’s super easy to use on the client side thanks to its XML namespace configuration. However, if you prefer Java-based configuration, there’s no such support _yet_. Meanwhile you can use [OAuth2RestTemplateBuilder][] from this project.

```java
new OAuth2RestTemplateBuilder()
        .clientCredentialsGrant()
            .id( "sample" )
            .clientId( "264ff434-1d2e-46b9-a3c8-fa7d182b7190" )
            .clientSecret( "kahc2fai1eo6uip5ied2deishei5ooNg" )
            .scope( "urn:zuul:oauth:sample.read" )
            .accessTokenUri( "https://oaas.example.org/oauth/token" )
            .clientAuthenticationScheme( AuthenticationScheme.form )
        .build();
```

License
-------

This project is licensed under [MIT license](http://opensource.org/licenses/MIT).


[spring-security-oauth]: http://projects.spring.io/spring-security-oauth
[ResourceServerTokenServices]: http://docs.spring.io/spring-security/oauth/apidocs/org/springframework/security/oauth2/provider/token/ResourceServerTokenServices.html
[RemoteResourceTokenServices]: /src/main/java/cz/cvut/zuul/support/spring/provider/RemoteResourceTokenServices.java
[provider-security.xml]: https://github.com/cvut/zuul-samples/blob/master/spring-provider/src/main/webapp/WEB-INF/spring/security.xml
[OAuth2ResourceServerConfigurerAdapter]: /src/main/java/cz/cvut/zuul/support/spring/provider/OAuth2ResourceServerConfigurerAdapter.java
[springSecurityFilterChain]: http://docs.spring.io/spring-security/site/docs/3.2.x/reference/htmlsingle/#ns-web-xml
[RemoteResourceTokenServicesBuilder]: /src/main/java/cz/cvut/zuul/support/spring/provider/RemoteResourceTokenServicesBuilder.java
[OAuth2RestTemplateBuilder]: /src/main/java/cz/cvut/zuul/support/spring/client/OAuth2RestTemplateBuilder.java
