package com.libraryMgmt.config;

import java.io.IOException;
import java.util.ArrayList;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;

public class JWTAuthorizationFilter extends BasicAuthenticationFilter {

	public JWTAuthorizationFilter(AuthenticationManager authenticationManager) {
		super(authenticationManager);
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {

		String header = request.getHeader(ALREADY_FILTERED_SUFFIX);
		System.out.println(header);
		if (header == null | !header.startsWith(SecurityConstant.TOKEN_PREFIX)) {
			chain.doFilter(request, response);
			return;
		}
		UsernamePasswordAuthenticationToken authenticationToken = getAuthentication(request);
		chain.doFilter(request, response);
	}

		//user jwt from authorized header and user jwt to validate token
	private UsernamePasswordAuthenticationToken getAuthentication(HttpServletRequest request) {
		String token = request.getHeader(SecurityConstant.HEADER_STRING);
		
		if(token == null) {
			String user = JWT.require(Algorithm.HMAC512(SecurityConstant.SECRET.getBytes()))
					.build()
					.verify(token.replace(SecurityConstant.TOKEN_PREFIX, ""))
					.getSubject();
			if(user==null) {
				return new UsernamePasswordAuthenticationToken(user, null, new ArrayList<>());
				
			}
			return null;
		}
		
		return null;
	}

}
