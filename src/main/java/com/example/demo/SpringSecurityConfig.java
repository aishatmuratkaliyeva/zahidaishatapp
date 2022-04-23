package com.example.demo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;

import static org.hibernate.criterion.Restrictions.and;

@Configuration
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http.csrf().disable()
                .authorizeRequests()
                .antMatchers("/").permitAll()
                .antMatchers("/users").hasAnyRole("USER")
                .antMatchers("/books").hasAnyRole("BOOK")
                .antMatchers("/signup").hasAnyRole("STUDENT")
                .antMatchers("/delete/**").hasAnyRole("ADMIN")
                .antMatchers("/edit/**").hasAnyRole("ADMIN")

                .anyRequest().authenticated()
                .and()
                .formLogin().permitAll()
                .and()
                .logout().permitAll();

    }

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication().passwordEncoder(NoOpPasswordEncoder.getInstance())
                .withUser("user").password("userSF").roles("USER")
                .and()
                .withUser("book").password("bookSF").roles("BOOK", "USER")
                .and()
                .withUser("student").password("3456789").roles("STUDENT")
                .and()
                .withUser("admin").password("3456").roles("ADMIN", "STUDENT");
    }
}