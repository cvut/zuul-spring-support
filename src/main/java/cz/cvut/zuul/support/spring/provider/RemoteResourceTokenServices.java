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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Required;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.BaseClientDetails;
import org.springframework.security.oauth2.provider.DefaultAuthorizationRequest;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.util.Assert;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.HashSet;
import java.util.Set;

import static java.util.Arrays.asList;


/**
 * Implementation of {@link ResourceServerTokenServices} for a standalone
 * OAuth 2.0 resource server (provider) using a remote authorization server to
 * obtain an authentication for access tokens.
 *
 * <p>Please note that this communication between Resource Server and
 * Authorization Server is beyond the scope of the RFC 6749 specification.
 * Therefore particular implementations of the TokenInfo Endpoint may vary
 * on various OAuth 2.0 authorization servers.</p>
 */
public class RemoteResourceTokenServices implements ResourceServerTokenServices, InitializingBean {

    private static final Logger LOG = LoggerFactory.getLogger(RemoteResourceTokenServices.class);

    private static final GrantedAuthority DEFAULT_USER_AUTHORITY = new SimpleGrantedAuthority("ROLE_USER");
    private static final String AGE_HEADER = "Age";

    private String tokenInfoEndpointUrl;
    private String tokenParameterName = "token";
    private RestTemplate restTemplate;
    private boolean decorateErrorHandler = true;



    public void afterPropertiesSet() {
        Assert.notNull(restTemplate, "restTemplate must not be null");
        Assert.hasText(tokenInfoEndpointUrl, "tokenInfoEndpointUrl must not be blank");

        if (decorateErrorHandler) {
            restTemplate.setErrorHandler(new TokenValidationErrorHandler(restTemplate.getErrorHandler()));
        }
        //add query parameter with placeholder for token value
        tokenInfoEndpointUrl = UriComponentsBuilder.fromUriString(tokenInfoEndpointUrl)
                .queryParam(tokenParameterName, "{value}")
                .build().toUriString();
    }


    public OAuth2Authentication loadAuthentication(String accessToken) throws AuthenticationException {
        LOG.debug("Verifying access token {} on authorization server: {}", accessToken, tokenInfoEndpointUrl);

        TokenInfo tokenInfo = requestTokenInfo(accessToken);

        LOG.debug("Server returned: {}", tokenInfo);

        Assert.state(tokenInfo.getClientId() != null, "Client id must be present in response from auth server");

        AuthorizationRequest clientAuthentication = createClientAuthentication(tokenInfo);
        Authentication userAuthentication = createUserAuthentication(tokenInfo);

        return new OAuth2Authentication(clientAuthentication, userAuthentication);
    }

    public OAuth2AccessToken readAccessToken(String accessToken) {
        throw new UnsupportedOperationException("Not supported: read access token");
    }


    private AuthorizationRequest createClientAuthentication(TokenInfo tokenInfo) {
        DefaultAuthorizationRequest auth = new DefaultAuthorizationRequest(tokenInfo.getClientId(), tokenInfo.getScope());

        if (!tokenInfo.getAudience().isEmpty() || !tokenInfo.getClientAuthorities().isEmpty()) {
            BaseClientDetails details = new BaseClientDetails();

            details.setClientId(tokenInfo.getClientId());
            details.setResourceIds(tokenInfo.getAudience());
            details.setAuthorities(tokenInfo.getClientAuthorities());

            auth.addClientDetails(details);
            auth.setApproved(true);
        }
        return auth;
    }

    private Authentication createUserAuthentication(TokenInfo tokenInfo) {
        if (tokenInfo.isClientOnly()) return null;

        Set<GrantedAuthority> authorities = tokenInfo.getUserAuthorities();
        if (authorities.isEmpty()) {
            // User authorities had better not be empty or we might mistake user for unauthenticated
            authorities = new HashSet<>(asList(DEFAULT_USER_AUTHORITY));
        }
        return new UsernamePasswordAuthenticationToken(tokenInfo.getUserId(), null, authorities);
    }

    private TokenInfo requestTokenInfo(String token) {
        ResponseEntity<TokenInfo> response = restTemplate.getForEntity(tokenInfoEndpointUrl, TokenInfo.class, token);

        // if token was in cache, then we must ensure if it's still valid
        if (response.getHeaders().containsKey(AGE_HEADER)) {
            long age = Long.parseLong(response.getHeaders().getFirst(AGE_HEADER));

            if (response.getBody().getExpiresIn() < age) {
                throw new InvalidClientTokenException("Access token has expired: " + token);
            }
        }
        return response.getBody();
    }


    //////////  Accessors  //////////

    /**
     * URL of the resource at OAuth2 authorization server that will be used to
     * obtain authentication info for Access Tokens received from clients.
     *
     * @param tokenInfoEndpointUrl URL of the TokenInfo Endpoint
     */
    @Required
    public void setTokenInfoEndpointUrl(String tokenInfoEndpointUrl) {
        this.tokenInfoEndpointUrl = tokenInfoEndpointUrl;
    }

    /**
     * Name of URL query parameter that holds Access Token value.
     * Default is <tt>access_token</tt>.
     */
    public void setTokenParameterName(String name) {
        Assert.isTrue(name != null && name.matches("[a-zA-Z0-9\\-_]+"),
                "Parameter name should contain only alphanumeric chars, dash and underscore");
        this.tokenParameterName = name;
    }

    /**
     * Instance of {@link RestTemplate}, or {@link org.springframework.security.oauth2.client.OAuth2RestTemplate}
     * for protected TokenInfo Endpoint (usually <tt>client_credentials</tt>
     * grant is used).
     */
    @Required
    public void setRestTemplate(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    /**
     * With default setting, this class decorates {@linkplain org.springframework.web.client.ResponseErrorHandler}
     * from the given RestTemplate with our {@link TokenValidationErrorHandler}.
     *
     * If you want to use your custom ErrorHandler instead, set this to <tt>false</tt>
     * and ErrorHandler from the RestTemplate will be used as is.
     *
     * @param decorateErrorHandler <tt>false</tt> to disable ErrorHandler decoration
     */
    public void setDecorateErrorHandler(boolean decorateErrorHandler) {
        this.decorateErrorHandler = decorateErrorHandler;
    }
}
