
## 개요
````
스프링 시큐리티 (OAuth2) 설정 할때마다 매번 헷갈리고 이해 하고자 만든 샘플 프로젝트이다. 
````

## 구현 내용
````
Spring Security 와 jwt(jjwt)를 활용
    1). 회원가입 및 일반로그인
    - 커스텀한 로그인 구현체 EmailPasswordAuthFilter.class 로 json 형식으로 로그인 값을 받아 처리한다.
    - 패스워드 암호화는 Scrypt 알고리즘을 사용하여 구현했다.
    
    2). OAuth2 로그인 ( github, google, kakao )
    - 해당 호스팅에서 인증 후 검증을 통해 회원가입 및 로그인 구현했다.
    
    3) JWT
    - 로그인이 성공되면 AccessToken 과 RefreshToken을 생성하여 클라이언트에 AccessToken을 Response
    - Radis-Data 로 RefreshToken을 저장하며, filter를 통해 AccessToken이 만료되면 RefreshToken을 검증하여 AccessToken 재발급 
    -> AccessToken의 유효기간을 짧게, RefreshToken은 길게 가져간다. AccessToken을 자주 발급 시켜 보안적으로 안전
    -> api 요청시 Header { Authorization : `Bearer ${AccessToken}` } 형식으로 검증
    
    4) Radis 서버
    - local window
    - https://github.com/MicrosoftArchive/redis/releases
````

## 이슈 내용
````
#1 @AuthenticationPrincipal
1. 발단
- 로그인 후 로그아웃 요청 시 @AuthenticationPrincipal 객체가 null이 발생하는 문제
2. 원인
- 인증된 사용자 정보가 PrincipalDetail이 아니라 Spring Security의 기본 User 객체로 반환되고 있었다.
3. 해결
- 인증 정보를 세팅 해주는 부분 에서 PrincipalDetail이 객체로 저장 되게 바꾸었다.
````

## OAuth2 각 호스트 설정
```` 
1. github
- github > Settings > Developer Settings > New OAuth App
- 각 정보와 redirect url 을 맞게 입력 후 생성을 완료 하면 Client ID 가 생성이 되고 Client secrets 은 추가로 생성 할 수 있다.
-> https://github.com/settings/developers

2. google
- Google API Console 에서 프로젝트, 사용자 인증 정보, 리디렉션 URI를 설정
-> https://developers.google.com/identity/openid-connect/openid-connect?hl=ko

참고: https://github.com/spring-projects/spring-security/tree/5.2.12.RELEASE/samples/boot/oauth2login

3. kakao
- 앱 등록 및 동의 항목
-> https://developers.kakao.com/console
출처 참고: https://velog.io/@zhyun/spring-boot-OAuth-2-kakao-%EB%A1%9C%EA%B7%B8%EC%9D%B8-%EC%97%B0%EB%8F%99

````

## Spring Security Architecture
![security.png](src/main/resources/static/img/security.png)


## OAuth2 login 흐름
![oAuth2.png](src/main/resources/static/img/oAuth2.png)
