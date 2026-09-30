package com.asherglobal.cop.apigateway.security.authentication;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class JwtAuthentication extends AbstractAuthenticationToken {

    private final String userId;

    public JwtAuthentication(
            String userId,
            Collection<? extends GrantedAuthority> authorities) {

        super(authorities);
        this.userId = userId;
        setAuthenticated(true);
    }

    @Override
    public Object getPrincipal() {
        return userId;
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    public String getUserId() {
        return userId;
    }
}