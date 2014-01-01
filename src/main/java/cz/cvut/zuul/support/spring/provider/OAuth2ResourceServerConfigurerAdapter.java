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
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.WebSecurityConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationManager;
import org.springframework.security.oauth2.provider.error.OAuth2AccessDeniedHandler;
import org.springframework.security.oauth2.provider.error.OAuth2AuthenticationEntryPoint;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.web.accept.ContentNegotiationStrategy;
import org.springframework.web.accept.HeaderContentNegotiationStrategy;

import static java.util.Collections.EMPTY_MAP;
import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;

/**
 * Provides a convenient base class for creating a {@link WebSecurityConfigurer}
 * instance for OAuth 2.0 Resource Server. The implementation allows customization
 * by overriding methods.
 *
 * @see org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
 */
@Order(100)
public abstract class OAuth2ResourceServerConfigurerAdapter implements WebSecurityConfigurer<WebSecurity> {

    private final Logger log = LoggerFactory.getLogger(OAuth2ResourceServerConfigurerAdapter.class);

    private ApplicationContext context;
    private ContentNegotiationStrategy contentNegotiationStrategy = new HeaderContentNegotiationStrategy();
    private AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();

    private ObjectPostProcessor<Object> objectPostProcessor = new ObjectPostProcessor<Object>() {
        public <T> T postProcess(T object) {
            throw new IllegalStateException(ObjectPostProcessor.class.getName()
                    + " is a required bean. Ensure you have used @EnableWebSecurity and @Configuration");
        }
    };

    private AccessDeniedHandler accessDeniedHandler = new OAuth2AccessDeniedHandler();
    private AuthenticationEntryPoint authenticationEntryPoint = new OAuth2AuthenticationEntryPoint();

    private HttpSecurity http;
    private boolean disableDefaults;


    /**
     * Creates an instance with the default configuration enabled.
     */
    protected OAuth2ResourceServerConfigurerAdapter() {
        this(false);
    }

    /**
     * Creates an instance which allows specifying if the default configuration
     * should be enabled. Disabling the default configuration should be
     * considered more advanced usage as it requires more understanding of how
     * the framework is implemented.
     *
     * @param disableDefaults
     *            true if the default configuration should be enabled,
     *            else false
     */
    protected OAuth2ResourceServerConfigurerAdapter(boolean disableDefaults) {
        this.disableDefaults = disableDefaults;
    }


     public void init(final WebSecurity web) throws Exception {
        final HttpSecurity http = getHttp();

         web.addSecurityFilterChainBuilder(http)
            .postBuildAction(new Runnable() {
                public void run() {
                    FilterSecurityInterceptor securityInterceptor = http.getSharedObject(FilterSecurityInterceptor.class);
                    web.securityInterceptor(securityInterceptor);
                }
            });
    }

    /**
     * Override this method to configure {@link WebSecurity}. For example,
     * if you wish to ignore certain requests.
     */
    public void configure(WebSecurity web) throws Exception {
    }

    /**
     * Override this method to configure the {@link HttpSecurity}.
     * Typically subclasses should not invoke this method by calling super
     * as it may override their configuration. The default configuration is:
     *
     * <pre>
     * http.authorizeRequests()
     *     .anyRequest().authenticated()
     * </pre>
     */
    protected void configure(HttpSecurity http) throws Exception {
        log.debug("Using default configure(HttpSecurity). If subclassed this will " +
                  "potentially override subclass configure(HttpSecurity).");

        http.authorizeRequests()
            .anyRequest().authenticated();
    }

    /**
     * Provides an {@link AuthenticationManager} to be used by OAuth filter.
     * This implementation creates {@link OAuth2AuthenticationManager}.
     *
     * <p>This method might be overridden to provide a custom
     * {@code AuthenticationManager}.</p>
     */
    protected AuthenticationManager getOAuthAuthenticationManager() {
        OAuth2AuthenticationManager manager = new OAuth2AuthenticationManager();
        manager.setTokenServices(getResourceServerTokenServices());

        return manager;
    }

    /**
     * Used by the default implementation of {@link #getOAuthAuthenticationManager()}
     * to obtain an {@link ResourceServerTokenServices}. The default strategy
     * is to autowire it by type.
     *
     * <p>This method might be overridden to provide an instance of
     * {@link ResourceServerTokenServices} directly.</p>
     */
    protected ResourceServerTokenServices getResourceServerTokenServices() {
        return context.getBean(ResourceServerTokenServices.class);
    }

    /**
     * Creates the {@link HttpSecurity} or returns the current instance.
     */
    protected final HttpSecurity getHttp() throws Exception {
        if (http != null) {
            return http;
        }
        AuthenticationManager authManager = objectPostProcessor.postProcess(getOAuthAuthenticationManager());

        AuthenticationManagerBuilder authBuilder = new AuthenticationManagerBuilder(objectPostProcessor);
        authBuilder.parentAuthenticationManager(authManager);

        http = new HttpSecurity(objectPostProcessor, authBuilder, EMPTY_MAP);
        http.setSharedObject(ApplicationContext.class, context);
        http.setSharedObject(ContentNegotiationStrategy.class, contentNegotiationStrategy);
        http.setSharedObject(AuthenticationTrustResolver.class, trustResolver);

        if (!disableDefaults) {
            http.apply(new OAuth2ResourceServerConfigurer()).and()
                .exceptionHandling()
                    .authenticationEntryPoint(authenticationEntryPoint)
                    .accessDeniedHandler(accessDeniedHandler).and()
                .headers().and()
                .sessionManagement()
                    .sessionCreationPolicy(STATELESS).and()
                .anonymous().and()
                .servletApi();
        }
        configure(http);

        return http;
    }


    //////// Accessors ////////

    @Autowired
    public void setApplicationContext(ApplicationContext context) {
        this.context = context;
    }

    @Autowired(required=false)
    public void setTrustResolver(AuthenticationTrustResolver trustResolver) {
        this.trustResolver = trustResolver;
    }

    @Autowired(required=false)
    public void setContentNegotationStrategy(ContentNegotiationStrategy contentNegotiationStrategy) {
        this.contentNegotiationStrategy = contentNegotiationStrategy;
    }

    @Autowired(required=false)
    public void setObjectPostProcessor(ObjectPostProcessor<Object> objectPostProcessor) {
        this.objectPostProcessor = objectPostProcessor;
    }
}
