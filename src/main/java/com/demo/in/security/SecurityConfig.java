package com.demo.in.security;

import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	// Authentication
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {

		auth.inMemoryAuthentication().withUser("admin").password("{noop}admin").authorities("ADMIN","EMPLOYEE","STUDENT");
		auth.inMemoryAuthentication().withUser("employee").password("{noop}employee").authorities("EMPLOYEE");
		auth.inMemoryAuthentication().withUser("student").password("{noop}student").authorities("STUDENT");

	}

	// Authorization
	@Override
	protected void configure(HttpSecurity http) throws Exception {
			http.authorizeRequests()
			.antMatchers("/").permitAll()
			.antMatchers("/welcome").authenticated()
			.antMatchers("/admin").hasAuthority("ADMIN")
			.antMatchers("/employee").hasAuthority("EMPLOYEE")
			.antMatchers("/student").hasAuthority("STUDENT")
			.and()
			.formLogin()
			.and()
			.logout()
			.logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
			.and()
			.exceptionHandling()
			.accessDeniedPage("/access-denied")
			;
	}

}
