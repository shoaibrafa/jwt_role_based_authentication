package com.sccurity.jwt_project.security;


import com.sccurity.jwt_project.filter.CustomAuthenticationFilter;
import com.sccurity.jwt_project.filter.CustomAuthorizationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final UserDetailsService userDetailsService;
    private final PasswordEncoder encoder;

    @Autowired
    public SecurityConfig(UserDetailsService userDetailsService, PasswordEncoder encoder) {
        this.userDetailsService = userDetailsService;
        this.encoder = encoder;
    }


    /**
     * AuthenticationManagerBuilder is used to tell spring security how to look for the clients who 
     * want to login. The options can be InMemoryAuthentication, JDBCAuthentication etc. Here in this project because we
     * are using Jpa then we tell spring to use a UserDetailsService. loadUserByUsername() method from ClientServiceImple
     * class which returns a UserDetails object that includes username, password and all the authorities.
     */

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(encoder);
    }


    /**
     * This is method is used to provide Authorizations and permissions.
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        /**
         * Here an object of CustomAuthenticationFilter is created and the setFilterProcessesUrl
         * method gets the login url as a String parameter. This method then extracts the username
         * and password from the url and if correct generates a token or blocks the access otherwise.
         */
        CustomAuthenticationFilter customAuthenticationFilter = new CustomAuthenticationFilter(authenticationManagerBean());
        customAuthenticationFilter.setFilterProcessesUrl("/api/login");

        http.csrf().disable();
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        http.authorizeRequests().antMatchers("/api/login/**", "/api/token/refresh/**").permitAll();

        /**
         * The following commented out code snippet uses configuration based authorization. It commented out
         * because in this project we are using annotation based authorization.
         */

//        http.authorizeRequests().antMatchers(HttpMethod.GET, "/api/users/**").hasAnyAuthority("ROLE_MANAGER");
//        http.authorizeRequests().antMatchers(HttpMethod.POST, "/api/user/save/**").hasAnyAuthority("ROLE_USER");
//        http.authorizeRequests().antMatchers(HttpMethod.GET, "/api/user_role/**").hasAnyAuthority("ROLE_USER");
//        http.authorizeRequests().antMatchers(HttpMethod.GET, "/api/admin_role/**").hasAnyAuthority("ROLE_ADMIN");
//        http.authorizeRequests().antMatchers(HttpMethod.GET, "/api/manager_role/").hasAnyAuthority("ROLE_MANAGER");
//        http.authorizeRequests().antMatchers(HttpMethod.GET, "/api/manager_role/test/**").hasAnyAuthority("ROLE_ADMIN");
//        http.authorizeRequests().antMatchers(HttpMethod.GET, "/api/super_admin_role/**").hasAnyAuthority("ROLE_SUPER_ADMIN");

//        http.authorizeRequests().antMatchers(HttpMethod.GET, "/api/user_role").hasRole("USER");
//        http.authorizeRequests().antMatchers(HttpMethod.GET, "/api/admin_role").hasRole("ADMIN");
//        http.authorizeRequests().antMatchers(HttpMethod.GET, "/api/manager_role").hasRole("MANAGER");
//        http.authorizeRequests().antMatchers(HttpMethod.GET, "/api/super_admin_role").hasRole("SUPER_ADMIN");


        http.authorizeRequests().anyRequest().authenticated();
        http.addFilter(customAuthenticationFilter);
        http.addFilterBefore(new CustomAuthorizationFilter(), UsernamePasswordAuthenticationFilter.class);
    }


    /**
     * The configure(HttpSecurity http) method requires an authenticationBean to implement a custom filter.
     */

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
}
