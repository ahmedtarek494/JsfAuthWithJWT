package com.example.jsfprojecet.security;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;

import com.example.jsfprojecet.service.JwtUserDetailsService;
import com.example.jsfprojecet.utils.JwtTokenUtil;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;



import io.jsonwebtoken.ExpiredJwtException;

@Component
public class JwtRequestFilter extends OncePerRequestFilter {

	private final JwtUserDetailsService jwtUserDetailsService;

	private final JwtTokenUtil jwtTokenUtil;
	public JwtRequestFilter( JwtUserDetailsService jwtUserDetailsService, JwtTokenUtil jwtTokenUtil)
	{
		this.jwtUserDetailsService=jwtUserDetailsService;
		this.jwtTokenUtil=jwtTokenUtil;

	}


	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws ServletException, IOException {
		HttpServletRequestWrapper requestWrapper=addingHeader(request);

		final String requestTokenHeader = requestWrapper.getHeader("Authorization");

		String username = null;
		String jwtToken = null;
		// JWT Token is in the form "Bearer token". Remove Bearer word and get only the Token
		if (requestTokenHeader != null && requestTokenHeader.startsWith("Bearer ")) {
			jwtToken = requestTokenHeader.substring(7);
			try {
				username = jwtTokenUtil.getUsernameFromToken(jwtToken);
			} catch (IllegalArgumentException e) {
				System.out.println("Unable to get JWT Token");
			} catch (ExpiredJwtException e) {
				System.out.println("JWT Token has expired");
			}
		} else {
			System.out.println("JWT Token does not begin with Bearer String");
			logger.warn("JWT Token does not begin with Bearer String");
		}

		//Once we get the token validate it.
		if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {

			UserDetails userDetails = this.jwtUserDetailsService.loadUserByUsername(username);
			System.out.println("hereeeee");

			if (jwtTokenUtil.validateToken(jwtToken, userDetails)) {

				UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
						userDetails, null, userDetails.getAuthorities());
				usernamePasswordAuthenticationToken
						.setDetails(new WebAuthenticationDetailsSource().buildDetails(requestWrapper));
				SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
			}
		}
		chain.doFilter(requestWrapper, response);
	}
/*
method to add the jwt token to the header before spring accessing the request
 */
	private HttpServletRequestWrapper addingHeader(HttpServletRequest httpRequest){



		System.out.println("filter before");
		if (httpRequest.getSession().getAttribute("token") != null) {


			String jwtToken =(String) httpRequest.getSession().getAttribute("token");
			HttpServletRequestWrapper requestWrapper = null;
			if (jwtToken != null) {
				System.out.println("Filter token : " + jwtToken);
				requestWrapper = new HttpServletRequestWrapper(httpRequest) {
					@Override
					public String getHeader(String name) {
						if ("Authorization".equalsIgnoreCase(name)) {
							return "Bearer " + jwtToken;
						}
						return super.getHeader(name);
					}
				};
			}
			return requestWrapper;
		}else{
			return (HttpServletRequestWrapper) httpRequest;
		}

	}
}
