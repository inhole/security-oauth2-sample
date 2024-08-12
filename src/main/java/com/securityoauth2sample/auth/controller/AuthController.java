package com.securityoauth2sample.auth.controller;

import com.securityoauth2sample.auth.jwt.util.JwtProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.token.TokenService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RequiredArgsConstructor
@RestController
public class AuthController {

    private final JwtProvider jwtProvider;

    @GetMapping("/get/key")
    public ResponseEntity<String> getKey() {
        String jwtKey = jwtProvider.generateKey();
        return ResponseEntity.ok(jwtKey);
    }
}
