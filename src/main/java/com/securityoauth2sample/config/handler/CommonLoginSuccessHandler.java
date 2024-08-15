package com.securityoauth2sample.config.handler;

import com.google.gson.Gson;
import com.securityoauth2sample.config.model.PrincipalDetail;
import com.securityoauth2sample.util.JwtUtils;
import com.securityoauth2sample.config.AppConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.Map;

@Slf4j
@Component
public class CommonLoginSuccessHandler implements AuthenticationSuccessHandler {

    private static AppConfig appConfig;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        log.info("--------------------------- CommonLoginSuccessHandler ---------------------------");

        PrincipalDetail principal = (PrincipalDetail) authentication.getPrincipal();

        log.info("authentication.getPrincipal() = {}", principal);


        Map<String, Object> responseMap = principal.getMemberInfo();
        responseMap.put("accessToken", JwtUtils.generateAccessToken(responseMap, appConfig.getAccessExpTime()));
        responseMap.put("refreshToken", JwtUtils.generateAccessToken(responseMap, appConfig.getRefreshExpTime()));

        Gson gson = new Gson();
        String json = gson.toJson(responseMap);

        response.setContentType("application/json; charset=UTF-8");

        PrintWriter writer = response.getWriter();
        writer.println(json);
        writer.flush();
    }
}
