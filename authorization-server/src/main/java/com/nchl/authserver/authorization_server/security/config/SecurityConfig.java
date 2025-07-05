package com.nchl.authserver.authorization_server.security.config;

import com.nchl.authserver.authorization_server.security.filter.OAuthTokenCachingFilter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

@Configuration
@Slf4j
public class SecurityConfig {
    @Autowired
    private OAuthTokenCachingFilter oAuthTokenCachingFilter;
    @Bean
    @Order(1)
//    for OAuth2 endpoints
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
                OAuth2AuthorizationServerConfigurer.authorizationServer();

        http
                .securityMatcher(authorizationServerConfigurer.getEndpointsMatcher()) // ✅ critical
                .authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
                //ignore eventhoufh csrf token is not send in request
                .csrf(csrf -> csrf.ignoringRequestMatchers(authorizationServerConfigurer.getEndpointsMatcher())) // ✅ avoid 403 on POST
                .addFilterAfter(oAuthTokenCachingFilter, UsernamePasswordAuthenticationFilter.class)

                .with(authorizationServerConfigurer, configurer -> configurer.oidc(Customizer.withDefaults())) // ✅ attach configurer
                .exceptionHandling(exceptions ->
                        exceptions.defaultAuthenticationEntryPointFor(
                                new LoginUrlAuthenticationEntryPoint("/login"),
                                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                        )
                );

        return http.build();
    }

    @Bean
    @Order(2)
// Handles all non-OAuth2 requests:
// - Login form (/login)
// - Custom web pages
// - Application-specific APIs
// - Static resources (CSS, JS, images, etc.)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)

            throws Exception {
        log.info("Default Security Filter Chain initialized");

        http
                .authorizeHttpRequests((authorize) -> authorize
                        .anyRequest().authenticated()
                )
                // Form login handles the redirect to the login page from the
                // authorization server filter chain
                .formLogin(Customizer.withDefaults());
        return http.build();
    }
}
