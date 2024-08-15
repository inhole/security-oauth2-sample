package com.securityoauth2sample.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.Gson;
import com.securityoauth2sample.domain.Member;
import com.securityoauth2sample.dto.request.SignUp;
import com.securityoauth2sample.repository.MemberRepository;
import com.securityoauth2sample.service.AuthService;
import com.securityoauth2sample.util.JwtUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@AutoConfigureMockMvc
@SpringBootTest
class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private MemberRepository memberRepository;

    @Autowired
    private AuthService authService;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private Gson gson;

    @Autowired
    private JwtUtils jwtUtils;

    @BeforeEach
    public void clean() {
        memberRepository.deleteAll();
    }

    @Test
    @DisplayName("회원가입")
    void test1() throws Exception {
        // given
        SignUp signUp = SignUp.builder()
                .email("sylee74133@gmail.com")
                .password("1234")
                .name("이인호")
                .build();

        // when
        mockMvc.perform(post("/auth/signUp")
                        .content(gson.toJson(signUp))
                        .contentType(APPLICATION_JSON)
                )
                .andExpect(status().isOk())
                .andDo(print());

        // then
        Optional<Member> member = memberRepository.findByEmail(signUp.getEmail());
        Assertions.assertEquals(member.get().getEmail(), signUp.getEmail());
        Assertions.assertEquals(member.get().getName(), signUp.getName());
    }

    @Test
    @DisplayName("로그인 (토큰 생성)")
    void test2() throws Exception {
        // given
        SignUp signUp = SignUp.builder()
                .email("dev")
                .password("1234")
                .build();
        authService.signUp(signUp);

        Optional<Member> member = memberRepository.findByEmail("dev");

        // when
        mockMvc.perform(post("/auth/login")
                        .content(gson.toJson(signUp))
                        .contentType(APPLICATION_JSON)
                )
                .andExpect(status().isOk())
                .andDo(print());
        // 검증 로직 추가...

        // then
    }
}