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
import org.springframework.security.config.annotation.web.configurers.ExceptionHandlingConfigurer;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;
import org.springframework.security.config.annotation.web.configurers.SessionManagementConfigurer;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationManager;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationProcessingFilter;
import org.springframework.security.oauth2.provider.error.OAuth2AccessDeniedHandler;
import org.springframework.security.oauth2.provider.error.OAuth2AuthenticationEntryPoint;
import org.springframework.security.oauth2.provider.expression.OAuth2WebSecurityExpressionHandler;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.util.Assert;

import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;

/**
 * OAuth2 configurer for a standalone resource server (i.e. without an authorization server).
 *
 * <h2>Example configuration</h2>
 * <pre>
 * &#064;Configuration
 * &#064;EnableWebSecurity
 * public class SecurityConfig extends WebSecurityConfigurerAdapter {
 *
 *     &#064;Bean
 *     public ResourceServerTokenServices resourceServerTokenServices() {
 *         return new StandaloneResourceTokenServicesBuilder()
 *                 .checkTokenEndpointUri("https://auth.example.org/oauth/check-token")
 *                 .build();
 *     }
 *
 *     protected void configure(HttpSecurity http) throws Exception {
 *         http.apply(new StandaloneResourceServerConfigurer())
 *                 .resourceTokenServices(resourceServerTokenServices())
 *             .and()
 *             .authorizeRequests()
 *                 .antMatchers("/api/**")
 *                 .access("#oauth2.hasScope('urn:zuul:oauth:sample.read')");
 *     }
 * }</pre>
 *
 * <h2>Note for Groovy</h2>
 *
 * <p>When used in Groovy code, the adapter must be explicitly casted to
 * {@code SecurityConfigurerAdapter} when passed to
 * {@link org.springframework.security.config.annotation.AbstractConfiguredSecurityBuilder#apply(SecurityConfigurerAdapter) apply()}
 * method; otherwise the wrong overloaded method is called.</p>
 *
 * <pre>
 * http.apply((SecurityConfigurerAdapter) new StandaloneResourceServerConfigurer())
 *     .resourceTokenServices(resourceServerTokenServices())
 * </pre>
 *
 * @author Jakub Jirutka <jakub@jirutka.cz>
 */
public class StandaloneResourceServerConfigurer extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {

    private AccessDeniedHandler accessDeniedHandler = new OAuth2AccessDeniedHandler();
    private AuthenticationEntryPoint authenticationEntryPoint = new OAuth2AuthenticationEntryPoint();
    private SecurityExpressionHandler<FilterInvocation> expressionHandler = new OAuth2WebSecurityExpressionHandler();

    private String resourceId;
    private ResourceServerTokenServices resourceTokenServices;


    /**
     * When no one is provided, {@link OAuth2AuthenticationEntryPoint} will be used.
     * Argument must not be <tt>null</tt>.
     */
    public StandaloneResourceServerConfigurer authenticationEntryPoint(AuthenticationEntryPoint authenticationEntryPoint) {
        Assert.notNull(authenticationEntryPoint, "authenticationEntryPoint must not be null");
        this.authenticationEntryPoint = authenticationEntryPoint;
        return this;
    }

    /**
     * The required resourceId a token must be granted for. If empty or absent then all resource
     * ids are allowed, otherwise only tokens which are granted to a client that contains this
     * resource id will be legal.
     *
     * @param resourceId The required resourceId or <tt>null</tt> for any.
     */
    public StandaloneResourceServerConfigurer resourceId(String resourceId) {
        this.resourceId = resourceId;
        return this;
    }

    /**
     * @see cz.cvut.zuul.oarp.spring.StandaloneResourceTokenServices
     * @see StandaloneResourceTokenServicesBuilder
     */
    public StandaloneResourceServerConfigurer resourceTokenServices(ResourceServerTokenServices tokenServices) {
        this.resourceTokenServices = tokenServices;
        return this;
    }


    @Override
    public void init(HttpSecurity http) throws Exception {
        http.setSharedObject(AuthenticationEntryPoint.class, authenticationEntryPoint);
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {

        Assert.notNull(resourceTokenServices, "A resourceTokenServices must be supplied");

        http.getConfigurer(ExpressionUrlAuthorizationConfigurer.class)
            .getRegistry()
            .expressionHandler(expressionHandler);

        http.getConfigurer(ExceptionHandlingConfigurer.class)
            .accessDeniedHandler(accessDeniedHandler);

        http.getConfigurer(SessionManagementConfigurer.class)
            .sessionCreationPolicy(STATELESS);

        OAuth2AuthenticationProcessingFilter resourcesServerFilter = new OAuth2AuthenticationProcessingFilter();
        resourcesServerFilter.setAuthenticationManager(oauthAuthenticationManager());
        resourcesServerFilter = postProcess(resourcesServerFilter);

        http.addFilterBefore(resourcesServerFilter, AbstractPreAuthenticatedProcessingFilter.class);
    }

    private AuthenticationManager oauthAuthenticationManager() {

        OAuth2AuthenticationManager manager = new OAuth2AuthenticationManager();
        manager.setResourceId(resourceId);
        manager.setTokenServices(resourceTokenServices);

        return manager;
    }
}
