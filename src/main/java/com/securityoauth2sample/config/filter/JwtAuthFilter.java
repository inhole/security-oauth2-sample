package com.securityoauth2sample.config.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.securityoauth2sample.config.JwtProperties;
import com.securityoauth2sample.exception.jwt.CustomJwtException;
import com.securityoauth2sample.exception.jwt.ExpectTokenException;
import com.securityoauth2sample.exception.jwt.ExpiredJwtException;
import com.securityoauth2sample.util.JwtUtils;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.PatternMatchUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@Slf4j
@RequiredArgsConstructor
@Component
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtUtils jwtUtils;
    private final JwtProperties jwtProperties;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        try {
            // 1. token 추출
            String token = resolveTokenFromRequest(request);
            
            // token 검증을 통해 만료 되었으면 refreshToken 으로 accessToken 재발급
            if (token != null) {
                // 2. 인증 정보 추출
                Authentication authentication = jwtUtils.getAuthentication(token);
                log.info("authentication = {}", authentication);

                // 3. SecurityContextHolder 인증 정보 set
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
            // 4. 다음 필터로 이동
            filterChain.doFilter(request, response);

        } catch (ExpiredJwtException e) {
            throw new ExpectTokenException();
        } catch (JwtException e) {
            throw new CustomJwtException(e);
        }
    }

    private String resolveTokenFromRequest(HttpServletRequest request) {
        // 1. header 값 추출
        String header = request.getHeader(jwtProperties.getJwtHeader());

        // 2. Bearer 체크 및 null 검증
        if (header == null || !header.startsWith(jwtProperties.getJwtType())) {
            return null;
        }

        // 3. token return
        return header = header.split(" ")[1];
    }
}
