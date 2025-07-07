package com.nchl.authserver.authorization_server.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nchl.authserver.authorization_server.Utility.TokenCaptureResponseWrapper;
import com.nchl.authserver.authorization_server.model.OAuthToken;
import com.nchl.authserver.authorization_server.service.impl.OAuthTokenCacheService;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;

@Component
@Slf4j
public class OAuthTokenCachingFilter extends OncePerRequestFilter {

    @Autowired
    private OAuthTokenCacheService tokenCacheService;

    @Autowired
    private ObjectMapper objectMapper;

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        log.info("Request URI: {}", request.getRequestURI());

        return !request.getRequestURI().equals("/oauth2/token");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        TokenCaptureResponseWrapper wrappedResponse = new TokenCaptureResponseWrapper(response);

        // Proceed with the filter chain
        filterChain.doFilter(request, wrappedResponse);

        byte[] content = wrappedResponse.getCapturedContent();
        ServletOutputStream out = response.getOutputStream();

        // Always write response content back to client
        out.write(content);
        out.flush();

        // If response is OK and body is present, try to parse and cache token
        if (response.getStatus() == HttpServletResponse.SC_OK && content.length > 0) {
            String responseBody = new String(content, StandardCharsets.UTF_8);
            log.info("Token Capture Response: {}", responseBody);

            try {
                OAuthToken token = objectMapper.readValue(responseBody, OAuthToken.class);
                log.info("Parsed token: {}", token);

                // Extract user ID and client ID from the JWT
                SignedJWT signedJWT = (SignedJWT) JWTParser.parse(token.getIdToken());
                String userId = signedJWT.getJWTClaimsSet().getSubject();       // e.g., "nchl"
                String clientId = signedJWT.getJWTClaimsSet().getAudience().get(0); // e.g., "client"

                String cacheKey = "refresh:" + userId + ":" + clientId;
                log.debug("Caching token with key: {}", cacheKey);

                tokenCacheService.storeToken(cacheKey, token);

            } catch (Exception e) {
                log.error("Failed to parse or cache token", e);
            }
        }
    }

}
