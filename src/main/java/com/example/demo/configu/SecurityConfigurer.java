package com.example.demo.configu;

import com.example.demo.service.MyUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
//import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.example.demo.filter.JwtRequestFilter;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfigurer extends WebSecurityConfigurerAdapter{

	@Autowired
    private MyUserDetailsService customUserDetailsService;
	@Autowired
	JwtRequestFilter jwtRequestFilter;
	
	  @Override
	    protected void configure(AuthenticationManagerBuilder auth) throws Exception {

	        auth.userDetailsService(customUserDetailsService);//.passwordEncoder(encodepw());

	    }
	  
	  @Override
		protected void configure(HttpSecurity http)throws Exception {
			 http.csrf().disable()
			      .authorizeRequests().antMatchers("/authenticate").permitAll()
			      .anyRequest().authenticated()
			      .and().sessionManagement()
					.sessionCreationPolicy(SessionCreationPolicy.STATELESS);
			 
			  http.addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class);
					
		}
		@Override
		@Bean
	    public AuthenticationManager authenticationManagerBean() throws Exception {
	    	return super.authenticationManagerBean();
	    }

	   @Bean
		public PasswordEncoder passwordEncorder(){
		return NoOpPasswordEncoder.getInstance();
	    }

}
