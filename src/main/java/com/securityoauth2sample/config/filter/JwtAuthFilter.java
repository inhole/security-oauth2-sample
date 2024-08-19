package com.securityoauth2sample.config.filter;

import com.securityoauth2sample.config.properties.JwtProperties;
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
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

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
            String accessToken = resolveTokenFromRequest(request);

            // 2. token 검증
            if (jwtUtils.validateToken(accessToken)) {
                setAuthentication(accessToken);
            } else {
                // accessToken 재발행
                String issueAccessToken = jwtUtils.issueAccessToken(accessToken);

                if (StringUtils.hasText(issueAccessToken)) {
                    // 인증 정보 저장
                    setAuthentication(issueAccessToken);
                    response.setHeader(jwtProperties.getJwtHeader(), jwtProperties.getJwtType() + " " + issueAccessToken);
                }
            }
            // 3. 다음 필터로 이동
            filterChain.doFilter(request, response);

        } catch (ExpiredJwtException e) {
            throw new ExpectTokenException();
        } catch (JwtException e) {
            throw new CustomJwtException(e);
        }
    }

    private void setAuthentication(String accessToken) {
        // SecurityContextHolder 인증 정보 set
        Authentication authentication = jwtUtils.getAuthentication(accessToken);
        SecurityContextHolder.getContext().setAuthentication(authentication);
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
