package com.ohgiraffers.security.common.utils;

import com.ohgiraffers.security.user.entity.User;
import io.jsonwebtoken.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import javax.xml.crypto.Data;
import java.security.Key;
import java.sql.NClob;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Component
public class TokenUtils {

    private static String jwtSecretKey;
    private static long tokenValidateTime;

    @Value("${jwt.key}")
    public static void setJwtSecretKey(String jwtSecretKey) {
        TokenUtils.jwtSecretKey = jwtSecretKey;
    }
    @Value("${jwt.time}")
    public static void setTokenValidateTime(long tokenValidateTime) {
        TokenUtils.tokenValidateTime = tokenValidateTime;
    }

    /**
     * header의 token 을 분리하는 메소드
     * @Param header: Authrization의 header값을 가져온다.
     * @return token : Authrization의 token을 반환한다.
    * */
    public static String splitHeader(String header){
        if(!header.equals("")){
            return header.split(" ")[1];  //BEARER를 제외한 토큰 값만 반환 해주는 메소드
        }else {
            return null;
        }

    }

    /**
     * 유효한 토큰인지 확인하는 메서드
     * @Param token : 토큰
     * @return boolean : 유효 여부
     * @throw ExpiredJwtException, {@link io.jsonwebtoken.JwtException} {@link NullPointerException}
     * */
    public static boolean isValidToken(String token){

/*        Claims claims = getClaimsFormToken(token); //payload 부분 - 실제 데이터를 넣는 부분 -> 복호화 시키기 위해 가져옴\
                        // 자체적으로 유효 검증 -> 토큰이 유효하지 않으면 복호화가 되지 않음*/

        try{
            Claims claims = getClaimsFormToken(token);
            return true;
        }catch (ExpiredJwtException e){
            e.printStackTrace();
            return false;
        }catch (JwtException e){
            e.printStackTrace();
            return false;
        }catch (NullPointerException e){
            e.printStackTrace();
            return false;
        }

    }

    /**
     * 토큰을 복호화 하는 메소드
     * @param token
     * @return Claims
     * */
    public static Claims getClaimsFormToken(String token){
        return Jwts.parser().setSigningKey(DatatypeConverter.parseBase64Binary(jwtSecretKey))
                .parseClaimsJws(token).getBody();
    }

    /**
     * token 을 생성하는 메소드
     * @param user userEntity
     * @return String token
     * */
    public static String generateJwtToken(User user){
        Date expireTime = new Date(System.currentTimeMillis()+tokenValidateTime);
        JwtBuilder builder = Jwts.builder()  // 토큰 생성 라이브러리 JwtBuilder
                .setHeader(createHeader())
                .setClaims(createClaims(user))
                .setSubject("ohgiraffers token : " + user.getUserNo())  // 토큰의 설명 정보를 담아줌
                .signWith(SignatureAlgorithm.HS256,createSignature())  // 토큰 암호화 방식 정의
                .setExpiration(expireTime); // 토큰 만료 시간 설정
        return builder.compact();
    }

    /**
     * token의 header를 설정하는 부분이다.
     * @return Map<String, Object> header의 설정 정보
     * */
    private static Map<String, Object> createHeader(){
        Map<String,Object> header = new HashMap<>();

        header.put("type","jwt");
        header.put("alg","HS256");
        header.put("date",System.currentTimeMillis()); // 토큰을 만든 설명

        return header;
    }
    
    /**
     * 사용자 정보를 기반으로 클레임을 생성해주는 메서드
     * @Param user 사용자 정보
     * @return Map<string,Object> Claims 정보
     * */
    private static Map<String,Object> createClaims(User user){
        Map<String,Object> claims = new HashMap<>();
        claims.put("userName",user.getUserName());
        claims.put("Role",user.getRole());
        claims.put("userEmail",user.getUserEmail());
        return claims;
    }

    /**
     * Jwt 서명을 발급해주는 메서드이다.
     * @return key
     * */
    private static Key createSignature(){
        byte[] secretBytes = DatatypeConverter.parseBase64Binary(jwtSecretKey);  //2진 데이터로 컨버트
        return new SecretKeySpec(secretBytes, SignatureAlgorithm.HS256.getJcaName()); // 256으로 암호화 후 반환 - 복호화 시에도 찾을 수 없음
    }
}
