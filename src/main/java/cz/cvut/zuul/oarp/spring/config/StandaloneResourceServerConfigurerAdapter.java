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

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;

/**
 * @author Jakub Jirutka <jakub@jirutka.cz>
 */
public abstract class StandaloneResourceServerConfigurerAdapter extends WebSecurityConfigurerAdapter {

    protected abstract void configure(StandaloneResourceTokenServicesBuilder builder);

    protected abstract void configureHttp(HttpSecurity http) throws Exception;

    /**
     * @see StandaloneResourceServerConfigurer#resourceId(String)
     */
    protected String resourceId() { return null; }


    @Bean
    public ResourceServerTokenServices resourceServerTokenServices() {
        StandaloneResourceTokenServicesBuilder builder = new StandaloneResourceTokenServicesBuilder();
        configure(builder);

        return builder.build();
    }

    /**
     * DO NOT OVERRIDE THIS! Implement {@link #configureHttp(HttpSecurity)} instead.
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.apply(new StandaloneResourceServerConfigurer())
                .resourceId(resourceId())
                .resourceTokenServices(resourceServerTokenServices());
        configureHttp(http);
    }
}
