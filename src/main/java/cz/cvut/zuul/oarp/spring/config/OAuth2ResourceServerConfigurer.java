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
package cz.cvut.zuul.oarp.spring.config;

import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationProcessingFilter;
import org.springframework.security.oauth2.provider.expression.OAuth2WebSecurityExpressionHandler;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;

/**
 * Adds support for OAuth 2.0 authorization (resource server).
 *
 * <h2>Security Filters</h2>
 *
 * The following Filters are populated
 *
 * <ul>
 *     <li>{@link OAuth2AuthenticationProcessingFilter}</li>
 * </ul>
 *
 * <h2>Shared Objects Created</h2>
 *
 * No shared objects are created.
 *
 * <h2>Shared Objects Used</h2>
 *
 * The following shared objects are used:
 *
 * <ul>
 *     <li>{@link AuthenticationManager} is used when not provided by
 *         {@link #oauthAuthenticationManager(AuthenticationManager)}</li>
 * </ul>
 *
 * <h2>Affected Configurers</h2>
 *
 * The {@link ExpressionUrlAuthorizationConfigurer} is affected - {@link SecurityExpressionHandler}
 * is changed to {@link OAuth2WebSecurityExpressionHandler}.
 *
 *
 * <h2>Note for Groovy</h2>
 *
 * <p>When used in Groovy code, the adapter must be explicitly casted to
 * {@code SecurityConfigurerAdapter} when passed to
 * {@link org.springframework.security.config.annotation.AbstractConfiguredSecurityBuilder#apply(SecurityConfigurerAdapter) apply()}
 * method; otherwise the wrong overloaded method is called.</p>
 *
 * <pre>http.apply((SecurityConfigurerAdapter) new OAuth2ResourceServerConfigurer())</pre>
 *
 * @see cz.cvut.zuul.oarp.spring.config.OAuth2ResourceServerConfigurerAdapter
 *
 * @author Jakub Jirutka <jakub@jirutka.cz>
 */
public class OAuth2ResourceServerConfigurer extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {

    private SecurityExpressionHandler<FilterInvocation> expressionHandler = new OAuth2WebSecurityExpressionHandler();
    private AuthenticationManager authenticationManager;

    /**
     * The {@code AuthenticationManager} to be used by {@link OAuth2AuthenticationProcessingFilter},
     * When not provided, the default {@code AuthenticationManager} from a
     * {@link HttpSecurity} builder is used.
     */
    public OAuth2ResourceServerConfigurer oauthAuthenticationManager(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
        return this;
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {

        http.getConfigurer(ExpressionUrlAuthorizationConfigurer.class)
            .getRegistry()
                .expressionHandler(expressionHandler);

        OAuth2AuthenticationProcessingFilter resourcesServerFilter = new OAuth2AuthenticationProcessingFilter();
        resourcesServerFilter.setAuthenticationManager(getAuthenticationManager(http));

        http.addFilterBefore(postProcess(resourcesServerFilter), AbstractPreAuthenticatedProcessingFilter.class);
    }


    private AuthenticationManager getAuthenticationManager(HttpSecurity http) {
        if (authenticationManager == null) {

            authenticationManager = http.getSharedObject(AuthenticationManager.class);
            if (authenticationManager == null) {
                throw new IllegalStateException("AuthenticationManager not found");
            }
        }
        return authenticationManager;
    }
}
