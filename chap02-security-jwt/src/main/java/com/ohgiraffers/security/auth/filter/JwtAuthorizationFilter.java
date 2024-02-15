package com.ohgiraffers.security.auth.filter;

import com.ohgiraffers.security.auth.model.DetailsUser;
import com.ohgiraffers.security.common.AuthConstants;
import com.ohgiraffers.security.common.utils.TokenUtils;
import com.ohgiraffers.security.user.entity.User;
import com.ohgiraffers.security.user.model.OhgiraffersRole;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONObject;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager) {

        super(authenticationManager);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {

        /* 권한이 필요없는 리소스 */
        List<String> roleLeessList = Arrays.asList(
                "/signup"
        );

        // 권한이 필요없는 요청이 들어왔는지 확인함.
        if(roleLeessList.contains(request.getRequestURI())){
            chain.doFilter(request,response);
            return;  // 체이닝 걸려있어서 / 체이닝 하면 return 으로 끊어주기만 하면 알아서 받아감
        }
        // 권한이 필요하면 여기부터 실행
        String header = request.getHeader(AuthConstants.AUTH_HEADER);



        try {
            // header 가 존재하는 경우
            if(header != null && !header.equalsIgnoreCase("")){
                // 토큰 값만 담음
                String token = TokenUtils.splitHeader(header);


                if(TokenUtils.isValidToken(token)){
                    // 트루로 넘어오면 토큰 정상 - 만료되지 않음.

                    // 토큰의 클레임부분만 받음
                    Claims claims = TokenUtils.getClaimsFormToken(token);
                    DetailsUser authebtication = new DetailsUser();  // AbstractAuthenticationToken 에 들어갈 타입때문에 지정

                    User user = new User();
                    user.setUserId(claims.get("userId").toString());
                    user.setRole(OhgiraffersRole.valueOf(claims.get("Role").toString())); // 들어간 값 대로 권한 반환

                    authebtication.setUser(user); // AbstractAuthenticationToken 에 넣기 위해 넣어줌 디테일객체에 user 정보 담아줌
                    // 디테일 객체에 담기 위해 user 엔티티 생성후 담아줌.. 직접 담을수없음   담고 아래 토큰에 넣어줌

                    AbstractAuthenticationToken authenticationToken =
                            UsernamePasswordAuthenticationToken.authenticated(authebtication, token,authebtication.getAuthorities());
                    // 유저 토큰에 사용자의 임시 정보를 저장해놓고 인증 인가
                    authenticationToken.setDetails(new WebAuthenticationDetails(request));

                    // 인증 인가 로직을 시큐리티에서 처리하게 만들기 위해 만든 토큰을 넣어줌..권한정보를 담아서 수행해야 하는데
                    // 자동으로 담기는 콘텍스트 홀더를 다 커스터마이징을 해서 자동으로 담기지 않기 때문에 우리가 직접 만들어서 담아줌.
                    // 한번 담아주면 권한 있는지만 알아서 체크함 ...
                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                    chain.doFilter(request,response);  // 체이닝 걸려있어서 알아서 받아감
                }else {
                    throw new RuntimeException("토큰이 유효하지 않습니다.");
                }

            }else {
                throw new RuntimeException("토큰이 존재하지 않습니다.");
            }
        }catch (Exception e){
            response.setContentType("application/json");
            response.setCharacterEncoding("UTF-8");
            PrintWriter printWriter = response.getWriter();
            JSONObject jsonObject = jsonresponseWrapper(e);
            printWriter.println(jsonObject);
            printWriter.flush();
            printWriter.close();
        }

    }

    private JSONObject jsonresponseWrapper(Exception e){
        String resultMsg = "";
        if(e instanceof ExpiredJwtException){
            resultMsg = "Token Expired";
        } else if (e instanceof SignatureException) {
            resultMsg = "Token SignatureException login";
        } else if (e instanceof JwtException) {
            resultMsg = "Token parsing JwtException";
        }else {
            resultMsg = "Other token Error";
        }

        HashMap<String, Object> jsonMap = new HashMap<>();
        jsonMap.put("status",401);
        jsonMap.put("message", resultMsg);
        jsonMap.put("reason",e.getMessage());
        JSONObject jsonObject = new JSONObject(jsonMap);
        return jsonObject;
    }


}
