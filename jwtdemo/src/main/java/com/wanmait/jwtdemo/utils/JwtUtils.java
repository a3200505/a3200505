package com.wanmait.jwtdemo.utils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Calendar;
import java.util.Map;

@Component
public class JwtUtils {
    private static String secretKey="!@#$%^&123abcQWE";
    /**
     * 生成token
     * @param map 传入的payload
     * @return
     */
    public static String getToken(Map<String, String> map){
        JWTCreator.Builder builder = JWT.create();
        map.forEach((k,v)->{
            builder.withClaim(k, v);
        });
        Calendar instance = Calendar.getInstance();
        //定义过期时间
        instance.add(Calendar.DATE, 1);
        builder.withExpiresAt(instance.getTime());
        return builder.sign(Algorithm.HMAC256(secretKey)).toString();
    }

    /**
     * 验证获取token中的payload，验证失败返回null
     * @param token
     * @return
     */
    public static DecodedJWT verify(String token){
        return JWT.require(Algorithm.HMAC256(secretKey)).build().verify(token);
    }

    /**
     * 获得token中的信息无需secret解密也能获得
     *
     * @return 指定key对应的值
     */
    public static String getValue(String token,String key) {
        try {
            if (token == null){
                return null;
            }
            DecodedJWT jwt = JWT.decode(token);
            return jwt.getClaim(key).asString();
        } catch (JWTDecodeException e) {
            return null;
        }
    }
}
