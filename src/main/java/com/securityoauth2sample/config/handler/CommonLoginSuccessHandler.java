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
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.util.Map;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@Slf4j
@RequiredArgsConstructor
@Component
public class CommonLoginSuccessHandler implements AuthenticationSuccessHandler {

    private final JwtUtils jwtUtils;
    private static final String URI = "/auth/success";

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {

//        PrincipalDetail principal = (PrincipalDetail) authentication.getPrincipal();

        // 1. AccessToken, RefreshToken 생성
        String accessToken = jwtUtils.generateAccessToken(authentication);
        jwtUtils.generateRefreshToken(authentication, accessToken);

        // 2. redirect
        String redirectUrl = UriComponentsBuilder.fromUriString(URI)
                .queryParam("accessToken", accessToken)
                .build().toUriString();
        response.sendRedirect(redirectUrl);

    }
}
