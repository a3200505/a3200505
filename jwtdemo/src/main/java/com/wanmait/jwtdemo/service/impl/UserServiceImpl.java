package com.wanmait.jwtdemo.service.impl;

import com.wanmait.jwtdemo.pojo.User;
import com.wanmait.jwtdemo.service.UserService;
import com.wanmait.jwtdemo.utils.JwtUtils;
import com.wanmait.jwtdemo.mapper.UserMapper;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.util.HashMap;
import java.util.UUID;

@Service
public class UserServiceImpl implements UserService {
    @Resource
    private JwtUtils jwtUtil;
    @Resource
    private UserMapper userMapper;
    @Override
    public String login(String username, String password) {
        //登录验证
        User user = userMapper.findByUserNameAndPassword(username, password);
        if (user == null) {
            return null;
        }
        //如果能查出，则表示账号密码正确，生成jwt返回
        String uuid = UUID.randomUUID().toString().replace("-", "");
        HashMap<String, String> map = new HashMap<>();
        map.put("username",user.getUsername());
        map.put("name", user.getName());
        map.put("id",String.valueOf(user.getId()));
        return JwtUtils.getToken(map);
    }
}
