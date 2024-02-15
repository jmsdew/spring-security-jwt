package com.ohgiraffers.security.auth.filter;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ohgiraffers.security.auth.model.dto.LoginDTO;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;

public class CustomAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    public CustomAuthenticationFilter(AuthenticationManager authenticationManager){
        super.setAuthenticationManager(authenticationManager);
    }


    // 지정된 url 요청시 해당 요청을 가로채서 검증 로직을 수행하는 메서드
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        UsernamePasswordAuthenticationToken authenticationToken;

        try {
            authenticationToken = getAuthRequest(request);
            setDetails(request, authenticationToken); //사용자가 입력한 정보를 담은 토큰 정보
        } catch (IOException e) {
            throw new RuntimeException(e);
        }


        return this.getAuthenticationManager().authenticate(authenticationToken);  // 발행한 임시 토큰을 매니저에 담아 보내줌
    }
    
    /**
     *  사용자의 로그인 리소스 요청시 요청 정보를 임시 토큰에 저장하는 메소드
     *
     * @Param request = httpServletRequest
     * @return UserPasswordAuthenticationToken
     * @throw IOException e
     * */
    private UsernamePasswordAuthenticationToken getAuthRequest(HttpServletRequest request) throws IOException {
        ObjectMapper objectMapper = new ObjectMapper();

        // json 형식의 데이터를 dto와 매핑 시킬 때 사용
        objectMapper.configure(JsonParser.Feature.AUTO_CLOSE_SOURCE, true);

        LoginDTO user = objectMapper.readValue(request.getInputStream(), LoginDTO.class);
                                                        //json 데이터를 뿌려줌. dto 형식으로 매핑  기본 설정이 세터. 생성자 만드는 건 자유
        return new UsernamePasswordAuthenticationToken(user.getId(), user.getPass());  //임시 토큰 발행
    }
}
