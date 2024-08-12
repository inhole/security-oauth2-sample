package com.securityoauth2sample.auth.handler;

import com.securityoauth2sample.auth.jwt.util.JwtProvider;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;

@RequiredArgsConstructor
@Component
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {

    private final JwtProvider jwtProvider;
    private static final String URI = "/auth/success";

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        // accessToken 발급
        String accessToken = jwtProvider.generateAccessToken(authentication);

        // 토큰 전달을 위한 redirect
        String redirectUrl = UriComponentsBuilder.fromUriString(URI)
                .queryParam("accessToken", accessToken)
                .build().toUriString();

        response.sendRedirect(redirectUrl);
    }
}
