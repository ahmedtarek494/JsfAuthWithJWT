package com.example.jsfprojecet.service;

import java.util.Objects;

import com.example.jsfprojecet.model.JwtRequest;
import com.example.jsfprojecet.model.JwtResponse;
import com.example.jsfprojecet.utils.JwtTokenUtil;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;




@Service
public class JwtAuthenticationService {

	private final AuthenticationManager authenticationManager;

	private final JwtTokenUtil jwtTokenUtil;

	private final UserDetailsService jwtInMemoryUserDetailsService;

	public JwtAuthenticationService(AuthenticationManager authenticationManager, JwtTokenUtil jwtTokenUtil, UserDetailsService jwtInMemoryUserDetailsService) {
		this.authenticationManager = authenticationManager;
		this.jwtTokenUtil = jwtTokenUtil;
		this.jwtInMemoryUserDetailsService = jwtInMemoryUserDetailsService;
	}


	public JwtResponse createAuthenticationToken(JwtRequest authenticationRequest)
			throws Exception {

		authenticate(authenticationRequest.getUsername(), authenticationRequest.getPassword());

		final UserDetails userDetails = jwtInMemoryUserDetailsService
				.loadUserByUsername(authenticationRequest.getUsername());

		final String token = jwtTokenUtil.generateToken(userDetails);

		return new JwtResponse(token);
	}

	private void authenticate(String username, String password) throws Exception {
		Objects.requireNonNull(username);
		Objects.requireNonNull(password);

		try {
			authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
		} catch (DisabledException e) {
			throw new Exception("USER_DISABLED", e);
		} catch (BadCredentialsException e) {
			throw new Exception("INVALID_CREDENTIALS", e);
		}
	}
}
