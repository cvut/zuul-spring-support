/*
 * The MIT License
 *
 * Copyright 2013-2014 Czech Technical University in Prague.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package cz.cvut.zuul.support.spring.client;

import org.springframework.security.oauth2.client.DefaultOAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.resource.BaseOAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsResourceDetails;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.client.token.grant.implicit.ImplicitResourceDetails;
import org.springframework.security.oauth2.client.token.grant.password.ResourceOwnerPasswordResourceDetails;
import org.springframework.security.oauth2.client.token.grant.redirect.AbstractRedirectResourceDetails;
import org.springframework.security.oauth2.common.AuthenticationScheme;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.Arrays;

/**
 * Builder(s) used to create {@link OAuth2ProtectedResourceDetails} for a specific
 * authorization grant and {@link OAuth2RestTemplate}.
 *
 * <p>This class is quite ugly, I know, but don't know how to do it better in
 * plain Java. :/</p>
 *
 * @see OAuth2RestTemplateBuilder
 */
@SuppressWarnings("unchecked")
abstract class OAuth2ResourceDetailsBuilder<B extends OAuth2ResourceDetailsBuilder<B>> {

    private final BaseOAuth2ProtectedResourceDetails resourceDetails;


    OAuth2ResourceDetailsBuilder(BaseOAuth2ProtectedResourceDetails resourceDetails) {
        this.resourceDetails = resourceDetails;
        this.resourceDetails.setScope(new ArrayList<String>());
    }

    /**
     * @param id An arbitrary unique identifier of this client.
     */
    public B id(String id) {
        resourceDetails.setId(id);
        return (B) this;
    }

    /**
     * The client identifier to use for this protected resource.
     */
    public B clientId(String clientId) {
        resourceDetails.setClientId(clientId);
        return (B) this;
    }

    /**
     * The scope of this resource.
     */
    public B scope(String... scopes) {
        resourceDetails.getScope().addAll(Arrays.asList(scopes));
        return (B) this;
    }

    /**
     * The name of the bearer token. The default is "access_token", which is according to the spec, but some providers
     * (e.g. Facebook) don't conform to the spec.)
     */
    public B tokenName(String tokenName) {
        resourceDetails.setTokenName(tokenName);
        return (B) this;
    }

    /**
     * @return Configured {@code OAuth2ProtectedResourceDetails} instance.
     */
    public OAuth2ProtectedResourceDetails getResourceDetails() {
        if (! StringUtils.hasText(resourceDetails.getId())) {
            resourceDetails.setId(resourceDetails.getClientId());
        }
        validate();

        return resourceDetails;
    }

    /**
     * @return Configured {@code OAuth2RestTemplate} instance for this resource.
     */
    public OAuth2RestTemplate build() {
        OAuth2ProtectedResourceDetails resource = getResourceDetails();

        OAuth2ClientContext context = resource.isClientOnly()
                    ? new DefaultOAuth2ClientContext()
                    : new ScopedOAuth2ClientContext(resource.getId());

        return new OAuth2RestTemplate(resource, context);
    }


    protected BaseOAuth2ProtectedResourceDetails resourceDetails() {
        return resourceDetails;
    }

    protected void validate() {
        Assert.hasText(resourceDetails.getId(), "An id must be supplied");
        Assert.hasText(resourceDetails.getClientId(), "A clientId must be supplied");
    }



    abstract static class UserAuthorizationResourceBuilder <B extends UserAuthorizationResourceBuilder<B>>
            extends OAuth2ResourceDetailsBuilder<B> {

        UserAuthorizationResourceBuilder(AbstractRedirectResourceDetails resourceDetails) {
            super(resourceDetails);
        }

        /**
         * Flag to signal that the current URI (if set) in the request should be used in preference to the pre-established
         * redirect URI.
         */
        public B useCurrentUri(boolean useCurrentUri) {
            resourceDetails().setUseCurrentUri(useCurrentUri);
            return (B) this;
        }

        /**
         * The URI to which the user is to be redirected to authorize an access token.
         */
        public B userAuthorizationUri(String userAuthorizationUri) {
            resourceDetails().setUserAuthorizationUri(userAuthorizationUri);
            return (B) this;
        }

        /**
         * The redirect URI that has been pre-established with the server. If present, the redirect URI will be omitted from
         * the user authorization request because the server doesn't need to know it.
         */
        public B preEstablishedRedirectUri(String preEstablishedRedirectUri) {
            resourceDetails().setPreEstablishedRedirectUri(preEstablishedRedirectUri);
            return (B) this;
        }

        /**
         * The bearer token method for this resource. Default value is "header".
         */
        public B authenticationScheme(AuthenticationScheme scheme) {
            resourceDetails().setAuthenticationScheme(scheme);
            return (B) this;
        }

        @Override
        protected AbstractRedirectResourceDetails resourceDetails() {
            return (AbstractRedirectResourceDetails) super.resourceDetails();
        }

        @Override
        protected void validate() {
            super.validate();
            Assert.hasText(resourceDetails().getUserAuthorizationUri(),
                    "An authorization URI must be supplied for a resource of type " + resourceDetails().getGrantType());
        }
    }


    abstract static class ClientAuthenticationResourceBuilder <B extends ClientAuthenticationResourceBuilder<B>>
            extends OAuth2ResourceDetailsBuilder<B> {

        ClientAuthenticationResourceBuilder(BaseOAuth2ProtectedResourceDetails resourceDetails) {
            super(resourceDetails);
        }

        /**
         * The URL to use to obtain an OAuth2 access token.
         */
        public B accessTokenUri(String accessTokenUri) {
            resourceDetails().setAccessTokenUri(accessTokenUri);
            return (B) this;
        }

        /**
         * The client secret.
         */
        public B clientSecret(String clientSecret) {
            resourceDetails().setClientSecret(clientSecret);
            return (B) this;
        }

        /**
         * The scheme to use to authenticate the client. Default value is "header".
         */
        public B clientAuthenticationScheme(AuthenticationScheme scheme) {
            resourceDetails().setClientAuthenticationScheme(scheme);
            return (B) this;
        }

        @Override
        protected void validate() {
            super.validate();
            Assert.hasText(resourceDetails().getAccessTokenUri(),
                    "An accessTokenUri must be supplied on a resource of type " + resourceDetails().getGrantType());
        }
    }



    public static class AuthorizationCodeResourceBuilder extends UserAuthorizationResourceBuilder<AuthorizationCodeResourceBuilder> {

        AuthorizationCodeResourceBuilder() {
            super(new AuthorizationCodeResourceDetails());
        }

        /**
         * The URL to use to obtain an OAuth2 access token.
         */
        public AuthorizationCodeResourceBuilder accessTokenUri(String accessTokenUri) {
            resourceDetails().setAccessTokenUri(accessTokenUri);
            return this;
        }

        /**
         * The client secret.
         */
        public AuthorizationCodeResourceBuilder clientSecret(String clientSecret) {
            resourceDetails().setClientSecret(clientSecret);
            return this;
        }

        /**
         * The scheme to use to authenticate the client. Default value is "header".
         */
        public AuthorizationCodeResourceBuilder clientAuthenticationScheme(AuthenticationScheme scheme) {
            resourceDetails().setClientAuthenticationScheme(scheme);
            return this;
        }

        @Override
        protected void validate() {
            super.validate();
            Assert.hasText(resourceDetails().getAccessTokenUri(),
                    "An accessTokenUri must be supplied on a resource of type " + resourceDetails().getGrantType());
        }
    }


    public static class ImplicitResourceBuilder extends UserAuthorizationResourceBuilder<ImplicitResourceBuilder> {

        ImplicitResourceBuilder() {
            super(new ImplicitResourceDetails());
        }
    }


    public static class ClientCredentialsResourceBuilder extends ClientAuthenticationResourceBuilder<ClientCredentialsResourceBuilder> {

        ClientCredentialsResourceBuilder() {
            super(new ClientCredentialsResourceDetails());
        }
    }


    public static class ResourceOwnerPasswordResourceBuilder extends ClientAuthenticationResourceBuilder<ResourceOwnerPasswordResourceBuilder> {

        ResourceOwnerPasswordResourceBuilder() {
            super(new ResourceOwnerPasswordResourceDetails());
        }
    }
}
