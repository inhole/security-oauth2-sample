package com.securityoauth2sample.controller;

import com.securityoauth2sample.dto.request.SignUp;
import com.securityoauth2sample.dto.response.LoginResponse;
import com.securityoauth2sample.service.AuthService;
import com.securityoauth2sample.util.JwtUtils;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RequiredArgsConstructor
@RestController
public class AuthController {

    private final JwtUtils jwtProvider;
    private final AuthService authService;

    /**
     * 회원가입
     * @param signUp
     */
    @PostMapping("/auth/signUp")
    public void signUp(@RequestBody SignUp signUp) {
        authService.signUp(signUp);
    }

    @GetMapping("/auth/success")
    public ResponseEntity<LoginResponse> loginSuccess(@Valid LoginResponse loginResponse) {
        return ResponseEntity.ok(loginResponse);
    }

    @GetMapping("/test")
    public String test() {
        return "테스트 입니다.";
    }
}
