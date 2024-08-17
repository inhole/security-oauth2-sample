package com.securityoauth2sample.config.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.Gson;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.io.IOException;

public class EmailPasswordAuthFilter extends AbstractAuthenticationProcessingFilter {

    private static final String DEFAULT_LOGIN_REQUEST_URL = "/auth/login";

    private final ObjectMapper objectMapper;

    public EmailPasswordAuthFilter(ObjectMapper objectMapper) {
        super(DEFAULT_LOGIN_REQUEST_URL);
        this.objectMapper = objectMapper;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
        // 1. 요청 본문에서 이메일과 비밀번호를 읽어 EmailPassword 객체로 반환
        EmailPassword emailPassword = objectMapper.readValue(request.getInputStream(), EmailPassword.class);

        // 2. 인증 정보 생성
        UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(emailPassword.getEmail(), emailPassword.getPassword());

        // 3. 요청의 유저 정보를 details에 저장
        authRequest.setDetails(this.authenticationDetailsSource.buildDetails(request));

        // 4. AuthenticationManager를 사용하여 인증을 시도합니다.
        return this.getAuthenticationManager().authenticate(authRequest);
    }

    @Getter
    private static class EmailPassword {
        public String email;
        public String password;
    }
}
