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
package cz.cvut.zuul.oarp.spring;

import lombok.Data;
import org.codehaus.jackson.annotate.JsonAutoDetect;
import org.codehaus.jackson.annotate.JsonIgnoreProperties;
import org.codehaus.jackson.annotate.JsonMethod;
import org.codehaus.jackson.annotate.JsonProperty;
import org.codehaus.jackson.map.annotate.JsonDeserialize;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.provider.BaseClientDetails.ArrayOrStringDeserializer;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import static java.util.Collections.emptySet;

/**
 * Authentication info about OAuth2 Token from remote authorization server.
 *
 * @author Jakub Jirutka <jakub@jirutka.cz>
 */
@Data
@JsonAutoDetect(JsonMethod.NONE)
@JsonIgnoreProperties(ignoreUnknown = true)
public class TokenInfo {

    @JsonProperty("client_id")
    private String clientId;

    @JsonProperty("scope")
    @JsonDeserialize(using = ArrayOrStringDeserializer.class)
    private Set<String> scope = emptySet();

    @JsonProperty("audience") //alias resource_ids
    @JsonDeserialize(using = ArrayOrStringDeserializer.class)
    private Set<String> audience = emptySet();

    @JsonProperty("client_authorities")
    @JsonDeserialize(using = ArrayOrStringDeserializer.class)
    private Set<String> clientAuthorities = emptySet();

    @JsonProperty("expires_in")
    private Integer expiresIn;

    @JsonProperty("user_id")
    private String userId;

    @JsonProperty("user_email")
    private String userEmail;

    @JsonProperty("user_authorities")
    @JsonDeserialize(using = ArrayOrStringDeserializer.class)
    private Set<String> userAuthorities = emptySet();


    public boolean isClientOnly() {
        return userId == null;
    }

    public Set<GrantedAuthority> getUserAuthorities() {
        return toGrantedAuthorities(userAuthorities);
    }

    public void setUserAuthorities(Collection<? extends GrantedAuthority> authorities) {
        this.userAuthorities = AuthorityUtils.authorityListToSet(authorities);
    }

    public Set<GrantedAuthority> getClientAuthorities() {
        return toGrantedAuthorities(clientAuthorities);
    }

    public void setClientAuthorities(Collection<? extends GrantedAuthority> authorities) {
        this.clientAuthorities = AuthorityUtils.authorityListToSet(authorities);
    }

    private Set<GrantedAuthority> toGrantedAuthorities(Collection<String> authorities) {
        Set<GrantedAuthority> result = new HashSet<>();
        for (String authority : authorities) {
            result.add(new SimpleGrantedAuthority(authority));
        }
        return result;
    }
}
