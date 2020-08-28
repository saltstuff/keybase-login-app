package com.salt.keybase;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.GenericFilterBean;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This is our custom authentication filter that is used in the {@link SecurityConfig}.
 */

public class ChallengeAuthenticationFilter extends GenericFilterBean {

	private static final Logger logger = LoggerFactory.getLogger(ChallengeAuthenticationFilter.class);
	@Override

	public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain)
			throws IOException, ServletException {

		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) resp;

		// first read the signed challenge
		String signedChallenge=request.getParameter("signedchallenge");
		if (signedChallenge!=null) {
			logger.trace("signedChallenge parameter intercepted by filter. Create token and validate it.");
			SignedChallengeAuthenticationToken token = new SignedChallengeAuthenticationToken(signedChallenge);
			SecurityContextHolder.getContext().setAuthentication(token);
		}

		// In either way we continue the filter chain to also apply filters that follow after our own.
		chain.doFilter(request, response);

	}
}