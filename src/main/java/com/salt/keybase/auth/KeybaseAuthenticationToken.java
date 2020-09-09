package com.salt.keybase.auth;

import java.util.Collection;

import com.salt.keybase.dataobjects.SignedResponse;
import com.salt.keybase.dataobjects.UserPrincipal;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityCoreVersion;

public class KeybaseAuthenticationToken extends AbstractAuthenticationToken {

    private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

    private final UserPrincipal principal;

	private SignedResponse signedResponse;

	public KeybaseAuthenticationToken(SignedResponse signedResponse) {
		super(null);
		this.principal = null;
		this.signedResponse=signedResponse;
		super.setAuthenticated(false);
	}

	public KeybaseAuthenticationToken(UserPrincipal principal, Collection<? extends GrantedAuthority> authorities, SignedResponse signedResponse) {
		super(authorities);
        this.principal = new UserPrincipal(principal.getUsername(), authorities);
		this.signedResponse=signedResponse;
		super.setAuthenticated(true); // must use super, as we override
	}
    // No such thing as credentials as user is authenticated by a verified challenge
	public Object getCredentials() {
		return null;
    }
    
    public SignedResponse getSignedResponse() {
		return signedResponse;
	}


	public Object getPrincipal() {
		return this.principal;
	}

	public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
		if (isAuthenticated) {
			throw new IllegalArgumentException(
					"Cannot set this token to trusted - use constructor which takes a GrantedAuthority list instead");
		}

		super.setAuthenticated(false);
	}

	@Override
	public void eraseCredentials() {
		super.eraseCredentials();
        this.signedResponse=null;
	}
}
