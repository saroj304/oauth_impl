package com.nchl.authserver.authorization_server.service.impl;

import com.nchl.authserver.authorization_server.model.OAuthToken;
import com.nchl.authserver.authorization_server.service.IOAuthTokenCacheService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;

@Service
public class OAuthTokenCacheService implements IOAuthTokenCacheService {

    private static final String TOKEN_PREFIX = "oauth:token:";

    @Autowired
    private RedisTemplate<String, OAuthToken> redisTemplate;

    public void storeToken(String userId, OAuthToken token) {
        redisTemplate.opsForValue().set(
                TOKEN_PREFIX + userId,
                token,
                Duration.ofSeconds(token.getExpiresIn()) // expires automatically
        );
    }

    public OAuthToken getToken(String userId) {
        return redisTemplate.opsForValue().get(TOKEN_PREFIX + userId);
    }

    public void deleteToken(String userId) {
        redisTemplate.delete(TOKEN_PREFIX + userId);
    }
}
