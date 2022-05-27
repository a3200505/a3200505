package com.wanmait.jwtdemo.interceptor;

import com.auth0.jwt.exceptions.AlgorithmMismatchException;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.wanmait.jwtdemo.utils.JwtUtils;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.util.HashMap;
import java.util.Map;

@Component
public class UserInterceptor implements HandlerInterceptor {
    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        Map<String, Object> map = new HashMap<>();
        //从请求头中获取token
        String token=request.getHeader("token");
        //从session中获取token 兼容不是前后端分离的项目
        if(token==null||token.equals("")){
            HttpSession session=request.getSession();
            token =(String)session.getAttribute("token");
        }
        //从请求参数中获取token
        if(token==null||token.equals("")){
            token=request.getParameter("token");
        }
        try {
            JwtUtils.verify(token);//验证令牌
            return true;//放行请求
        } catch (SignatureVerificationException e) {
            e.printStackTrace();
            map.put("msg","无效签名!");
        }catch (TokenExpiredException e){
            e.printStackTrace();
            map.put("msg","token过期!");
        }catch (AlgorithmMismatchException e){
            e.printStackTrace();
            map.put("msg","token算法不一致!");
        }catch (Exception e){
            e.printStackTrace();
            map.put("msg","token无效!!");
        }
        map.put("state",false);//设置状态
        //将map 专为json  jackson
        String json = new ObjectMapper().writeValueAsString(map);
        System.out.println(json);
        response.setContentType("application/json;charset=UTF-8");
        response.sendRedirect("/user/login.html");
        return false;
    }
}
