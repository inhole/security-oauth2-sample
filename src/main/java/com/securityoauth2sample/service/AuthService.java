package com.securityoauth2sample.service;

import com.securityoauth2sample.domain.Member;
import com.securityoauth2sample.dto.request.SignUp;
import com.securityoauth2sample.exception.member.AlreadyExistsEmailException;
import com.securityoauth2sample.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@RequiredArgsConstructor
@Service
public class AuthService {

    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;

    public void signUp(SignUp signUp) {
        Optional<Member> userOptional = memberRepository.findByEmail(signUp.getEmail());
        if (userOptional.isPresent()) {
            throw new AlreadyExistsEmailException();
        }

        String encryptedPassword = passwordEncoder.encode(signUp.getPassword());

        var member = Member.builder()
                .email(signUp.getEmail())
                .password(encryptedPassword)
                .name(signUp.getName())
                .build();
        memberRepository.save(member);
    }
}
