package com.salt.keybase.filters;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.salt.keybase.auth.KeybaseAuthenticationToken;
import com.salt.keybase.dataobjects.Challenge;
import com.salt.keybase.dataobjects.SignedResponse;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.GenericFilterBean;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This is our custom authentication filter that is used in the {@link SecurityConfig}.
 */

public class KeybaseAuthenticationFilter extends GenericFilterBean {

	private static final Logger logger = LoggerFactory.getLogger(KeybaseAuthenticationFilter.class);
	@Override

	public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain)
			throws IOException, ServletException {

		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) resp;

		// first read the signed response ciphertext
		String signedresponsCiphertext=request.getParameter("signedresponseCiphertext");
		String iv=request.getParameter("iv");
		if (!(signedresponsCiphertext==null || iv==null)) {
			logger.trace("signedresponseCiphertext and iv parameters intercepted by filter. Create token and validate it.");
			
			// We need to carry the IV of the original challenge, in order to be able to decrypt the challenge later
			Challenge originalChallenge=new Challenge();
			originalChallenge.setEncodedIV(iv);
			
			SignedResponse signedResponse=new SignedResponse();
			signedResponse.setSignedResponseCiphertext(signedresponsCiphertext);
			signedResponse.setOriginalChallenge(originalChallenge);
			
			KeybaseAuthenticationToken token = new KeybaseAuthenticationToken(signedResponse);
			SecurityContextHolder.getContext().setAuthentication(token);
		}

		// In either way we continue the filter chain to also apply filters that follow after our own.
		chain.doFilter(request, response);

	}
}