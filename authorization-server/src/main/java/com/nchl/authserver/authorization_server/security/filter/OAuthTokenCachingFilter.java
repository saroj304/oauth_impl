package com.nchl.authserver.authorization_server.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nchl.authserver.authorization_server.Utility.TokenCaptureResponseWrapper;
import com.nchl.authserver.authorization_server.model.OAuthToken;
import com.nchl.authserver.authorization_server.service.impl.OAuthTokenCacheService;
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

        // Wrap response to capture the output
        TokenCaptureResponseWrapper capturingResponse = new TokenCaptureResponseWrapper(response);

        filterChain.doFilter(request, capturingResponse);

        byte[] content = capturingResponse.getCapturedContent();
        log.info("Token Capture Response: {}", objectMapper.writeValueAsString(content));
        if (response.getStatus() == HttpServletResponse.SC_OK && content.length > 0) {
            String responseBody = new String(content);

            // Parse JSON response
            OAuthToken token = objectMapper.readValue(responseBody, OAuthToken.class);
             log.info("parsed token: {}", token);
            // For demo: using "nc hl" (subject) or another identifier as key
            // In production: use userId/clientId or "jti" from the JWT for precise keys
            String userKey = "user:oauth:token:nchl";

            // Cache the token
            tokenCacheService.storeToken(userKey, token);

            // Write the original content back to the client
            ServletOutputStream out = response.getOutputStream();
            out.write(content);
            out.flush();
        } else {
            // Write content back if not 200 or no content
            ServletOutputStream out = response.getOutputStream();
            out.write(content);
            out.flush();
        }
    }
}
