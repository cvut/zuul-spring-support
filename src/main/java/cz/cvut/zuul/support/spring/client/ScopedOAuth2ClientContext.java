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

import org.springframework.beans.factory.ObjectFactory;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.client.token.DefaultAccessTokenRequest;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.HttpServletRequest;
import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

import static org.springframework.web.context.request.RequestAttributes.SCOPE_REQUEST;
import static org.springframework.web.context.request.RequestContextHolder.currentRequestAttributes;

/**
 * The scoped {@code OAuth2ClientContext} implementation that keeps context
 * for distinct resources and resource owners.
 *
 * <p>This was originally created as a replacement for "magic" in
 * {@link org.springframework.security.oauth2.config.RestTemplateBeanDefinitionParser}
 * to allow easy use in java-based configuration.</p>
 *
 * TODO unit tests
 */
public class ScopedOAuth2ClientContext implements OAuth2ClientContext {

    private static final String CLIENT_CONTEXT = "clientContext";
    private static final String TOKEN_REQUEST = "tokenRequest";

    private final ObjectFactory<ClientContextHolder> clientContextFactory = new ObjectFactory<ClientContextHolder>() {

        public ClientContextHolder getObject() {
            return new ClientContextHolder();
        }
    };

    private final ObjectFactory<AccessTokenRequest> tokenRequestFactory = new ObjectFactory<AccessTokenRequest>() {

        public AccessTokenRequest getObject() {
            Map<String, String[]> parameters = getRequest().getParameterMap();
            String currentUri = (String) getRequest().getAttribute("currentUri");

            DefaultAccessTokenRequest request = new DefaultAccessTokenRequest(parameters);
            request.setCurrentUri(currentUri);

            return request;
        }
    };

    private final String id;

    /**
     * @param id The unique context identifier.
     */
    public ScopedOAuth2ClientContext(String id) {
        this.id = id;
    }


    public OAuth2AccessToken getAccessToken() {
        return getClientContext().accessToken;
    }

    public void setAccessToken(OAuth2AccessToken accessToken) {
        getClientContext().accessToken = accessToken;
        getAccessTokenRequest().setExistingToken(accessToken);
    }

    public void setPreservedState(String stateKey, Object preservedState) {
        getClientContext().state.put(stateKey, preservedState);
    }

    public Object removePreservedState(String stateKey) {
        return getClientContext().state.remove(stateKey);
    }

    public AccessTokenRequest getAccessTokenRequest() {
        return requestAttribute(TOKEN_REQUEST, tokenRequestFactory);
    }


    private ClientContextHolder getClientContext() {
        return sessionAttribute(CLIENT_CONTEXT, clientContextFactory);
    }


    private <T> T requestAttribute(String name, ObjectFactory<T> factory) {
        return scopedAttribute(name, factory, SCOPE_REQUEST);
    }

    private <T> T sessionAttribute(String name, ObjectFactory<T> factory) {
        synchronized (currentRequestAttributes().getSessionMutex()) {
            return scopedAttribute(name, factory, RequestAttributes.SCOPE_SESSION);
        }
    }

    @SuppressWarnings("unchecked")
    private <T> T scopedAttribute(String name, ObjectFactory<T> factory, int scope) {
        RequestAttributes attributes = currentRequestAttributes();
        String key = prefixKey(name);

        Object value = attributes.getAttribute(key, scope);
        if (value == null) {
            value = factory.getObject();
            attributes.setAttribute(key, value, scope);
        }
        return (T) value;
    }

    private String prefixKey(String suffix) {
        return getClass().getName() + "#" + id + "_" + suffix;
    }

    private HttpServletRequest getRequest() {
        return ((ServletRequestAttributes) currentRequestAttributes()).getRequest();
    }


    private static class ClientContextHolder implements Serializable {
        OAuth2AccessToken accessToken;
        Map<String, Object> state = new HashMap<>();
    }
}
