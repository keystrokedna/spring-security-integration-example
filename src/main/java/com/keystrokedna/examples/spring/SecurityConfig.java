package com.keystrokedna.examples.spring;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configurers.provisioning.InMemoryUserDetailsManagerConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.util.Assert;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final UsersSettings usersSettings;

    private final KeystrokeDNAService keystrokeDNAHandler;

    @Autowired
    public SecurityConfig(UsersSettings usersSettings, KeystrokeDNAService keystrokeDNAHandler) {
        this.usersSettings = usersSettings;
        this.keystrokeDNAHandler = keystrokeDNAHandler;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // @formatter:off
        http
                .authorizeRequests()
                .antMatchers("/css/**",  "/images/**", "/login**").permitAll()
                .antMatchers("/success").hasRole("USER")
                .antMatchers("/2fa**").hasRole("2FA")
                .antMatchers("/new_device**").hasRole("NEW_DEVICE")
                .antMatchers("/approve_device**").hasRole("APPROVE_DEVICE")
                .antMatchers("/invalidSession").anonymous()
                .and()
                .formLogin()
                    .loginPage("/login")
                    .failureForwardUrl("/login?error=true")
                    .successHandler(keystrokeDNAHandler)
                    .permitAll()
                .and()
                .logout()
                    .logoutUrl("/logout")
                    .invalidateHttpSession(true)
                    .deleteCookies("JSESSIONID")
                    .permitAll()
                .and()
                .sessionManagement()
                    .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                    .invalidSessionUrl("/invalid_session")
                    .maximumSessions(1)
                    .and()
                    .sessionFixation().migrateSession()
                .and()
                .csrf()
                    .csrfTokenRepository(new CookieCsrfTokenRepository())
        ;
        // @formatter:on
    }

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder authentication)
            throws Exception {
        InMemoryUserDetailsManagerConfigurer<AuthenticationManagerBuilder> builder = authentication.inMemoryAuthentication();
        for (UsersSettings.User user : usersSettings.getUsers()) {
            Assert.isTrue(user.getName().length() >= 8, "Username should be at least 8 characters long");
            builder.withUser(user.getName())
                    .password(passwordEncoder().encode(user.getPass()))
                    .authorities("ROLE_USER");
        }
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}