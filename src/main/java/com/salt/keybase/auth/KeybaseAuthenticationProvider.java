package com.salt.keybase.auth;

import java.util.LinkedList;
import java.util.List;

import com.salt.keybase.dataobjects.SignedResponse;
import com.salt.keybase.dataobjects.UserPrincipal;
import com.salt.keybase.utils.ChallengeUtils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;


@Component
public class KeybaseAuthenticationProvider implements AuthenticationProvider {
	private static final Logger logger = LoggerFactory.getLogger(KeybaseAuthenticationProvider.class);

	@Override
	public Authentication authenticate(Authentication auth) throws AuthenticationException {
		try {
			logger.trace("Authenticating ...");
			if (auth != null) {
				SignedResponse signedResponse = ((KeybaseAuthenticationToken) auth).getSignedResponse();
				
				signedResponse=ChallengeUtils.verifySignedResponse(signedResponse);
				String verifiedUsername=signedResponse.getPublicKeyOfSigner().getUsername();
				if (verifiedUsername!=null) {
					logger.trace("Authentication succesful. Will create a new signed authentication token containing the principal with proper authorities.");
					final List<SimpleGrantedAuthority> authorities = new LinkedList<>();
					authorities.add(new SimpleGrantedAuthority("ROLE_USER"));
					UserPrincipal principal = new UserPrincipal(verifiedUsername, authorities);
					return new KeybaseAuthenticationToken(principal, authorities, signedResponse);
				}
			} 
		} catch (Exception e) {
			String errorMessage="External system authentication failed. Reason: " + e.getMessage();
			logger.error(errorMessage);
			throw new BadCredentialsException(errorMessage);	
		}
		return null;
	}

	@Override
	public boolean supports(Class<?> auth) {
		return auth.equals(KeybaseAuthenticationToken.class);
	}

	


}
