package com.novapay.api_gateway.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Primary;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtReactiveAuthenticationManager;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

@Component
@Primary
@RequiredArgsConstructor
public class RedisBlacklistAuthenticationManager
        implements ReactiveAuthenticationManager {

    private static final String BLACKLIST_PREFIX = "blacklist:";

    private final JwtReactiveAuthenticationManager jwtAuthenticationManager;
    private final ReactiveStringRedisTemplate redisTemplate;

    @Override
    public Mono<Authentication> authenticate(Authentication authentication) {

        return jwtAuthenticationManager
                .authenticate(authentication)
                .flatMap(authenticated -> {

                    String token =
                            ((BearerTokenAuthenticationToken) authentication)
                                    .getToken();

                    return redisTemplate
                            .hasKey(BLACKLIST_PREFIX + token)
                            .flatMap(blacklisted -> {

                                if (Boolean.TRUE.equals(blacklisted)) {
                                    return Mono.error(
                                            new BadCredentialsException(
                                                    "JWT token has been revoked"));
                                }

                                return Mono.just(authenticated);
                            });
                });
    }
}