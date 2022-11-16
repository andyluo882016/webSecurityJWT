package com.example.demo.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import com.example.demo.domain.AuthenticationRequest;
import com.example.demo.domain.AuthenticationResponse;
import com.example.demo.service.MyUserDetailsService;
import com.example.demo.util.JwtJutil;


@RestController
@CrossOrigin
public class HomeController {
	
	@Autowired
	private AuthenticationManager authenticationManager;
	@Autowired
	MyUserDetailsService userDetailService;
	@Autowired
	JwtJutil jwtTokenUtil;

	@GetMapping(path="/hello")
	public String show() {
		return "Hello My Testing";
	}
	

	@RequestMapping(value = "/authenticate", method = RequestMethod.POST)
	public ResponseEntity<?> createAuthenticationToken(@RequestBody AuthenticationRequest authenticationrequest) throws Exception{
		myauthenticate(authenticationrequest.getUsername(), authenticationrequest.getPassword());
		final UserDetails userDetails =userDetailService.loadUserByUsername(authenticationrequest.getPassword());

		String jwt = jwtTokenUtil.generateToken(userDetails);

	   return ResponseEntity.ok(new AuthenticationResponse(jwt));
	}

	private void myauthenticate(String username, String password) throws Exception {
		try {
			UsernamePasswordAuthenticationToken usertt=new UsernamePasswordAuthenticationToken(username, password);

			authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));

		}catch (DisabledException e) {
			throw new Exception("USER_DISABLED", e);
		} catch (BadCredentialsException e) {
			throw new Exception("INVALID_CREDENTIALS", e);
		}
	}
}
