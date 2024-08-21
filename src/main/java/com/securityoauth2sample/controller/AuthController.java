package com.securityoauth2sample.controller;

import com.securityoauth2sample.config.model.PrincipalDetail;
import com.securityoauth2sample.dto.request.SignUp;
import com.securityoauth2sample.dto.response.LoginResponse;
import com.securityoauth2sample.service.AuthService;
import com.securityoauth2sample.service.TokenService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RequiredArgsConstructor
@RestController
public class AuthController {

    private final AuthService authService;
    private final TokenService tokenService;

    /**
     * 회원가입
     * @param signUp
     */
    @PostMapping("/auth/signUp")
    public void signUp(@RequestBody SignUp signUp) {
        authService.signUp(signUp);
    }

    /**
     * 로그인 성공 redirect
     * @param loginResponse
     * @return
     */
    @GetMapping("/auth/success")
    public ResponseEntity<LoginResponse> loginSuccess(@Valid LoginResponse loginResponse) {
        return ResponseEntity.ok(loginResponse);
    }

    /**
     * 로그아웃
     * @param principalDetail
     * @return
     */
    @DeleteMapping("/auth/logout")
    public ResponseEntity<Void> logout(@AuthenticationPrincipal PrincipalDetail principalDetail) {
        tokenService.deleteRefreshToken(principalDetail.getUsername());
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/test")
    public String test() {
        return "테스트 입니다.";
    }
}
