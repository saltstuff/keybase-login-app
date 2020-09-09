package com.salt.keybase.config;

import com.salt.keybase.auth.KeybaseAuthenticationProvider;
import com.salt.keybase.filters.KeybaseAuthenticationFilter;

import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // Add KeybaseAuthenticationFilter before the
        // UsernamePasswordAuthenticationFilter
        // To make sure that the filter is not set too low in priority

        http.authorizeRequests().antMatchers("/css/**", "/index", "/challenge")
            .permitAll();            

        http.authorizeRequests()
            .antMatchers("/user/**")
            .hasAuthority("ROLE_USER")
            .and()
            .addFilterBefore(new KeybaseAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class)
            .logout()
            .logoutSuccessUrl("/index")
            .permitAll();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(new KeybaseAuthenticationProvider());
    }
}