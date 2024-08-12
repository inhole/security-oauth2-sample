package com.securityoauth2sample.auth.dto;

import com.securityoauth2sample.common.KeyGenerator;
import com.securityoauth2sample.domain.member.entity.Member;
import com.securityoauth2sample.domain.member.entity.MemberRole;
import com.securityoauth2sample.exception.InvalidRegistrationId;
import lombok.Builder;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

import java.util.Map;

@Slf4j
@Getter
public class OAuth2UserInfo {

    public String name;
    public String email;
    public String profile;

    @Builder
    public OAuth2UserInfo(String name, String email, String profile) {
        this.name = name;
        this.email = email;
        this.profile = profile;
    }

    public static OAuth2UserInfo of(String registrationId, Map<String, Object> attributes) {
        return switch (registrationId) {
            case "github" -> ofGithub(attributes);
            case "google" -> ofGoogle(attributes);
            case "kakao" -> ofKakao(attributes);
            default -> throw new InvalidRegistrationId();
        };
    }

    private static OAuth2UserInfo ofGithub(Map<String, Object> attributes) {
        // github 파싱 값 확인...
        return OAuth2UserInfo.builder()
                .build();
    }

    private static OAuth2UserInfo ofGoogle(Map<String, Object> attributes) {
        return OAuth2UserInfo.builder()
                .name((String) attributes.get("name"))
                .email((String) attributes.get("email"))
                .profile((String) attributes.get("picture"))
                .build();
    }

    private static OAuth2UserInfo ofKakao(Map<String, Object> attributes) {
        Map<String, Object> account = (Map<String, Object>) attributes.get("kakao_account");
        Map<String, Object> profile = (Map<String, Object>) account.get("profile");

        return OAuth2UserInfo.builder()
                .name((String) profile.get("nickname"))
                .email((String) account.get("email"))
                .profile((String) profile.get("profile_image_url"))
                .build();
    }

    public Member toEntity() {
        return Member.builder()
                .name(name)
                .email(email)
                .profile(profile)
                .memberKey(KeyGenerator.generateKey())
                .memberRole(MemberRole.USER)
                .build();
    }
}
