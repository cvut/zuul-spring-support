/*
 * The MIT License
 *
 * Copyright 2013 Jakub Jirutka <jakub@jirutka.cz>.
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

import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.SecurityBuilder;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsResourceDetails;
import org.springframework.security.oauth2.common.AuthenticationScheme;
import org.springframework.util.Assert;
import org.springframework.web.client.RestTemplate;

import java.util.Arrays;

/**
 * {@code SecurityBuilder} used to create a {@link RemoteResourceTokenServices}.
 */
public class RemoteResourceTokenServicesBuilder implements SecurityBuilder<RemoteResourceTokenServices> {

    private RemoteResourceTokenServices tokenServices = new RemoteResourceTokenServices();
    private ClientCredentialsResourceDetails resourceDetails;
    private RestTemplate restTemplate;
    private boolean secured = false;


    /**
     * URL of the resource at OAuth2 authorization server that will be used to
     * obtain authentication info for Access Tokens received from clients.
     */
    public RemoteResourceTokenServicesBuilder checkTokenEndpointUri(String checkTokenEndpointUri) {
        tokenServices.setCheckTokenEndpointUrl(checkTokenEndpointUri);
        return this;
    }

    /**
     * Name of URL query parameter (GET) or request body attribute (POST)
     * that holds Access Token value. Default is <tt>access_token</tt>.
     */
    public RemoteResourceTokenServicesBuilder tokenParameterName(String parameterName) {
        tokenServices.setTokenParameterName(parameterName);
        return this;
    }

    /**
     * Which HTTP method use to request authentication info for Access Token at
     * Check Token Endpoint? Default is POST.
     *
     * @param requestMethod GET or POST
     */
    public RemoteResourceTokenServicesBuilder requestMethod(HttpMethod requestMethod) {
        tokenServices.setMethod(requestMethod);
        return this;
    }

    /**
     * Instance of {@link RestTemplate}, or {@link org.springframework.security.oauth2.client.OAuth2RestTemplate}
     * to access Check Token Endpoint. If provided then {@link #secured()} will be ignored.
     */
    public RemoteResourceTokenServicesBuilder restTemplate(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
        return this;
    }

    /**
     * Configure OAuth 2.0 parameters for a secured Check Token resource.
     */
    public ResourceDetailsBuilder secured() {
        this.secured = true;
        return new ResourceDetailsBuilder();
    }

    public RemoteResourceTokenServices build() {
        if (secured) {
            Assert.hasText(resourceDetails.getClientId(), "A clientId must be supplied");
            Assert.hasText(resourceDetails.getClientSecret(), "A clientSecret must be supplied");
            Assert.hasText(resourceDetails.getAccessTokenUri(), "An accessTokenUri must be supplied");
        }

        if (restTemplate == null) {
            restTemplate = secured ? new OAuth2RestTemplate(resourceDetails) : new RestTemplate();
        }
        tokenServices.setRestTemplate(restTemplate);
        tokenServices.afterPropertiesSet();

        return tokenServices;
    }



    public class ResourceDetailsBuilder {

        private static final String DEFAULT_SCOPE = "urn:zuul:oaas:check-token";

        private ResourceDetailsBuilder() {
            resourceDetails = new ClientCredentialsResourceDetails();
            resourceDetails.setScope(Arrays.asList(DEFAULT_SCOPE));
        }

        /**
         * The client ID to access the OAAS.
         */
        public ResourceDetailsBuilder clientId(String clientId) {
            resourceDetails.setClientId(clientId);
            return this;
        }

        /**
         * The client secret to access the OAAS.
         */
        public ResourceDetailsBuilder clientSecret(String clientSecret) {
            resourceDetails.setClientSecret(clientSecret);
            return this;
        }

        /**
         * The scope required by the OAAS to access the Check Token Endpoint.
         * The default scope is <tt>urn:zuul:oaas:check-token</tt>.
         */
        public ResourceDetailsBuilder scope(String... scopes) {
            resourceDetails.setScope(Arrays.asList(scopes));
            return this;
        }

        /**
         * The URL to use to obtain an access token for communication with the OAAS.
         */
        public ResourceDetailsBuilder accessTokenUri(String accessTokenUri) {
            resourceDetails.setAccessTokenUri(accessTokenUri);
            return this;
        }

        /**
         * The scheme to use to authenticate. The default value is "header".
         */
        public ResourceDetailsBuilder clientAuthenticationScheme(AuthenticationScheme scheme) {
            resourceDetails.setClientAuthenticationScheme(scheme);
            return this;
        }

        public RemoteResourceTokenServicesBuilder and() {
            return RemoteResourceTokenServicesBuilder.this;
        }

        public RemoteResourceTokenServices build() {
            return RemoteResourceTokenServicesBuilder.this.build();
        }
    }
}
