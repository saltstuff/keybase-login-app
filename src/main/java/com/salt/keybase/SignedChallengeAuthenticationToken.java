package com.salt.keybase;

import java.util.Collection;

import com.salt.keybase.dataobjects.UserPrincipal;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityCoreVersion;

public class SignedChallengeAuthenticationToken extends AbstractAuthenticationToken {

    private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

    private final UserPrincipal principal;

    private String signedChallenge;

	public SignedChallengeAuthenticationToken(String signedUnverifiedChallenge) {
		super(null);
        this.principal = null;
        this.signedChallenge=signedUnverifiedChallenge;
		setAuthenticated(false);
	}

	public SignedChallengeAuthenticationToken(UserPrincipal principal, Collection<? extends GrantedAuthority> authorities, String signedVerifiedChallenge) {
		super(authorities);
        this.principal = new UserPrincipal(principal.getUsername(), authorities);
        this.signedChallenge=signedVerifiedChallenge;
		super.setAuthenticated(true); // must use super, as we override
	}
    // No such thing as credentials as user is authenticated by a verified challenge
	public Object getCredentials() {
		return null;
    }
    
    public String getSignedChallenge() {
		return signedChallenge;
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
        this.signedChallenge=null;
	}
}
