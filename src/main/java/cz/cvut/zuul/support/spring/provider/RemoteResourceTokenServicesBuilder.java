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
package cz.cvut.zuul.support.spring.provider;

import lombok.Setter;
import lombok.experimental.Accessors;
import org.springframework.security.config.annotation.SecurityBuilder;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsResourceDetails;
import org.springframework.security.oauth2.common.AuthenticationScheme;
import org.springframework.util.Assert;
import org.springframework.web.client.RestTemplate;

import java.util.Arrays;

import static lombok.AccessLevel.NONE;

/**
 * {@code SecurityBuilder} used to create a {@link RemoteResourceTokenServices}.
 */
@Setter @Accessors(fluent=true)
public final class RemoteResourceTokenServicesBuilder implements SecurityBuilder<RemoteResourceTokenServices> {

    private final RemoteResourceTokenServicesBuilder parent = this;

    private @Setter(NONE) ClientCredentialsResourceDetails resourceDetails;

    /**
     * URL of the resource at OAuth2 authorization server that will be used to
     * obtain authentication info for Access Tokens received from clients.
     */
    private String tokenInfoEndpointUri;

    /**
     * Name of URL query parameter (GET) or request body attribute (POST)
     * that holds Access Token value. Default is <tt>token</tt>.
     */
    private String tokenParameterName = "token";

    /**
     * Instance of {@link RestTemplate}, or {@link org.springframework.security.oauth2.client.OAuth2RestTemplate}
     * to access TokenInfo Endpoint. This cannot be used along with {@link #secured()}.
     */
    private RestTemplate restTemplate;


    /**
     * Configure OAuth 2.0 parameters for a secured TokenInfo endpoint.
     * This cannot be used when the {@link #restTemplate(RestTemplate) restTemplate}
     * is specified.
     */
    public ResourceDetailsBuilder secured() {
        return new ResourceDetailsBuilder();
    }

    public RemoteResourceTokenServices build() {
        if (resourceDetails != null && restTemplate != null) {
            throw new IllegalStateException("secured() cannot be used along with custom restTemplate");
        }

        if (restTemplate == null) {
            restTemplate = resourceDetails != null ? new OAuth2RestTemplate(resourceDetails) : new RestTemplate();
        }
        RemoteResourceTokenServices services = new RemoteResourceTokenServices();
        services.setTokenInfoEndpointUrl(tokenInfoEndpointUri);
        services.setTokenParameterName(tokenParameterName);
        services.setRestTemplate(restTemplate);
        services.afterPropertiesSet();

        return services;
    }



    @Setter @Accessors(fluent=true)
    public final class ResourceDetailsBuilder {

        private static final String DEFAULT_SCOPE = "urn:zuul:oaas:tokeninfo";

        private @Setter(NONE) String[] scope = new String[]{ DEFAULT_SCOPE };

        /**
         * The client ID to access the OAAS.
         */
        private String clientId;

        /**
         * The client secret to access the OAAS.
         */
        private String clientSecret;

        /**
         * The URL to use to obtain an access token for communication with the OAAS.
         */
        private String accessTokenUri;

        /**
         * The scheme to use to authenticate. The default value is "header".
         */
        private AuthenticationScheme clientAuthenticationScheme = AuthenticationScheme.header;


        /**
         * The scope required by the OAAS to access the TokenInfo Endpoint.
         * The default scope is <tt>urn:zuul:oaas:tokeninfo</tt>.
         */
        public ResourceDetailsBuilder scope(String... scopes) {
            this.scope = scopes;
            return this;
        }

        public RemoteResourceTokenServicesBuilder and() {
            Assert.hasText(clientId, "A clientId must be supplied");
            Assert.hasText(clientSecret, "A clientSecret must be supplied");
            Assert.hasText(accessTokenUri, "An accessTokenUri must be supplied");

            ClientCredentialsResourceDetails resource = new ClientCredentialsResourceDetails();
            resource.setClientId(clientId);
            resource.setClientSecret(clientSecret);
            resource.setScope(Arrays.asList(scope));
            resource.setAccessTokenUri(accessTokenUri);
            resource.setClientAuthenticationScheme(clientAuthenticationScheme);
            parent.resourceDetails = resource;

            return parent;
        }

        public RemoteResourceTokenServices build() {
            return and().build();
        }
    }
}
