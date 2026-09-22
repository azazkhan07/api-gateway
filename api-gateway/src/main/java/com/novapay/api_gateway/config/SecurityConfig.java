package com.novapay.api_gateway.config;

import com.novapay.api_gateway.exception.SecurityExceptionHandler;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.http.HttpMethod;

@Configuration
@EnableWebFluxSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final RedisBlacklistAuthenticationManager redisBlacklistAuthenticationManager;
    private final SecurityExceptionHandler securityExceptionHandler;

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        return http.csrf(ServerHttpSecurity.CsrfSpec::disable)
                .cors(cors -> {})
                .exceptionHandling(exceptionHandling -> exceptionHandling
                        .authenticationEntryPoint(securityExceptionHandler)
                        .accessDeniedHandler(securityExceptionHandler))
                        .authorizeExchange(exchange -> exchange
                        .pathMatchers(HttpMethod.OPTIONS, "/**")
                        .permitAll()
                        .pathMatchers("/auth/login", "/auth/register", "/auth/refresh-token")
                        .permitAll()
                        .pathMatchers("/swagger-ui/**", "/v3/api-docs/**")
                        .permitAll()
                        .pathMatchers("/actuator/health")
                        .permitAll()
                        .anyExchange()
                        .authenticated())
                        .oauth2ResourceServer(oauth2 ->
                                 oauth2.authenticationEntryPoint(securityExceptionHandler)
                                .accessDeniedHandler(securityExceptionHandler)
                                .jwt(jwt -> jwt.authenticationManager(redisBlacklistAuthenticationManager)))
                                .build();
    }
}
