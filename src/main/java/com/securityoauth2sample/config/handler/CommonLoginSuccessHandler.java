package com.securityoauth2sample.config.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.securityoauth2sample.config.model.PrincipalDetail;
import com.securityoauth2sample.dto.response.LoginResponse;
import com.securityoauth2sample.util.JwtUtils;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Map;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@Slf4j
@RequiredArgsConstructor
@Component
public class CommonLoginSuccessHandler implements AuthenticationSuccessHandler {

    private final JwtUtils jwtUtils;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {

        // 1. PrincipalDetail 객체 생성
        PrincipalDetail principal = (PrincipalDetail) authentication.getPrincipal();

        // 2. AccessToken, RefreshToken 생성
        String accessToken = jwtUtils.generateAccessToken(authentication);
        jwtUtils.generateRefreshToken(authentication);
        LoginResponse loginResponse = new LoginResponse(accessToken);

        // 3. response
        ObjectMapper objectMapper = new ObjectMapper();
        response.setContentType(APPLICATION_JSON_VALUE);
        response.setCharacterEncoding(UTF_8.name());
        objectMapper.writeValue(response.getWriter(), loginResponse);

    }
}
