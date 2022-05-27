一、什么是JWT
JWT(全称：Json Web Token)是一个开放标准(RFC 7519)，它定义了一种紧凑的、自包含的方式，用于作为JSON对象在各方之间安全地传输信息。该信息可以被验证和信任，因为它是数字签名的。
JWT的最常见方案是用于用户登录鉴权。用户登录后，每个后续请求都将包含JWT，从而允许用户访问该令牌允许的路由，服务和资源。
下面我们看看如何基于JWT来实现登录功能。
二、JWT结构介绍
在其紧凑的形式中，JSON Web令牌由点(.)分隔的三个部分组成，它们是:
头
有效载荷
签名
因此，JWT通常如下所示。
xxxxx.yyyyy.zzzzz
让我们分解一下不同的部分。
1、头
报头通常由两部分组成：令牌的类型，即JWT，以及所使用的签名算法，如HMAC SHA256或RSA。
例如:
{
  "alg": "HS256",
  "typ": "JWT"
}
然后，该JSON是Base64Url编码的，以形成JWT的第一部分。
2、有效载荷
令牌的第二部分是有效负载，它包含声明。声明是关于实体(通常是用户)和附加数据的声明。声明有三种类型：注册声明、公开声明和私有声明。
注册声明：这些是一组预定义声明，它们不是强制性的，而是推荐的，以提供一组有用的、可互操作的声明。其中包括:iss(发行人)、exp(到期时间)、sub(主题)、aud(受众)等。
注意，声明名只有三个字符长，因为JWT是为了紧凑。
公开声明：这些声明可以由使用JWT的人随意定义。但是为了避免冲突，应该在IANA JSON Web Token注册表中定义它们，或者将它们定义为包含抗冲突名称空间的URI。
私有声明：这些定制声明是为了在同意使用它们的各方之间共享信息而创建的，它们既不是注册的也不是公开的声明。
有效载荷的一个例子可以是：
{
  "sub": "1234567890",
  "name": "John Doe",
  "admin": true
}
然后对有效负载进行Base64Url编码，以形成JSON Web Token的第二部分。
请注意，对于已签名的令牌，该信息虽然受到保护，不会被篡改，但任何人都可以读懂。不要将机密信息放在JWT的有效负载或头元素中，除非它被加密了。
3、签名
要创建签名部分，你必须获取已编码的头、已编码的有效负载、一个密钥和头中指定的算法，并对其进行签名。
例如，使用HMAC SHA256算法时，签名的生成方式如下：
HMACSHA256(
  base64UrlEncode(header) + "." +
  base64UrlEncode(payload),
  secret)
签名用于验证消息在整个过程中没有被更改，而且，在使用私钥签名的令牌的情况下，它还可以验证JWT的发送方是它所声称的那个人。
4、把所有合起来
输出是三个用点分隔的Base64-URL字符串，它们可以很容易地在HTML和HTTP环境中传递，同时与基于xml的标准(如SAML)相比更紧凑。
下面展示了一个JWT，它对前面的头和有效负载进行了编码，并使用secret对其进行了签名。

三、JWT进行鉴权的思路
1、用户发起登录请求。
2、服务端创建一个加密后的JWT信息，作为Token返回。
3、在后续请求中JWT信息作为请求头，发给服务端。
4、服务端拿到JWT之后进行解密，正确解密表示此次请求合法，验证通过；解密失败说明Token无效或者已过期。

四、JWT实现的鉴权实例
1、新建数据库和表
这里我们使用Mysql数据库，首先在MySQL数据库中新建一个数据库jwt和数据库表User，
表结构如下：
![image](https://user-images.githubusercontent.com/80870043/170661063-3be94896-8901-4c3b-9c51-e688a089572f.png)

插入一条测试数据：
![image](https://user-images.githubusercontent.com/80870043/170661091-289d140a-d48b-44cf-a3f5-6e3f7f7a4e35.png)


2、新建springboot项目
在idea新建一个springboot项目，然后在pom文件中分别添加jwt、mysql、mybatis、lombok的依赖。
<dependency>
    <groupId>com.auth0</groupId>
    <artifactId>java-jwt</artifactId>
    <version>3.19.2</version>
</dependency>
<dependency>
    <groupId>org.mybatis.spring.boot</groupId>
    <artifactId>mybatis-spring-boot-starter</artifactId>
    <version>2.1.4</version>
</dependency>
<dependency>
    <groupId>mysql</groupId>
    <artifactId>mysql-connector-java</artifactId>
    <version>8.0.18</version>
</dependency>
<dependency>
    <groupId>org.projectlombok</groupId>
    <artifactId>lombok</artifactId>
</dependency>

3、搭建项目
项目结构如下：


(1)、添加实体类User
首先，添加一个实体类User，用于装载从数据库中查询的数据
@Data
public class User {
    private int id;
    private String username;
    private String password;
    private String name;
}
(2)、添加Mapper接口UserMapper，并添加一个方法findByUserNameAndPassword()根据用户名和密码从数据库中查询数据
@Mapper
public interface UserMapper {
    @Select("select * from user where username=#{username} and 	password=#{password}")
    User findByUserNameAndPassword(@Param("username") String    	username,@Param("password") String password);
}
(3)、添加jwt帮助类 JwtUtils 
这个类需要Spring来管理，所以要添加@Component注解。
在这个类中添加三个方法：
getToken()方法，根据有效载荷生成并返回token
verify()方法用来验证token
getValue()方法用来根据有效载荷的key来获取值 
注意：载荷中的值不需要解密也可以获得，因此要存放密码等机密的数据需要先加密
@Component
public class JwtUtils {
    private static String secretKey="!@#$%^&123abcQWE";
    /**
     * 生成token
     * @param map 传入的载荷
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
     * 验证获取token中的载荷，验证失败返回null
     * @param token
     * @return
     */
    public static DecodedJWT verify(String token){
        return JWT.require(Algorithm.HMAC256(secretKey)).build().verify(token);
    }

    /**
     * 获得token中的信息无需secret解密也能获得
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
(4)、添加Service接口和实现类 
首先添加接口UserService 并添加一个login()登录方法
public interface UserService {
    String login(String username, String password);
}
然后添加接口的实现类UserServiceImpl
然后实现接口的login方法，这个方法首先去数据库中查询用户输入的账号和密码是否正确，如果正确的话，调用JWTUtils里面的方法生成token，并返回。
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
(5)、添加控制器类UserController
接收用户输入的用户名和密码，如果正确，生成token并存放到session里面。
@Controller
@RequestMapping("/user")
public class UserController {
    @Resource
    private UserService userService;
    @PostMapping("/login")
    public String login(@RequestParam(name = "username") String username,
                              @RequestParam(name = "password") String password, HttpSession session, HttpServletResponse response){
        String token = userService.login(username, password);
        if(token==null){
            return "redirect:/user/login.html";
        }
        session.setAttribute("token",token);
        return "redirect:/user/index.html";
    }
}
(6)、添加拦截器类 UserInterceptor
如果用户登录成功，就放行，否则重定向回登录页面
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
      response.setContentType("application/json;charset=UTF-8");
        response.sendRedirect("/user/login.html");
        return false;
    }
}

(7)、添加配置类 WebConfig
对user目录下面的页面添加拦截器，排除登录验证链接/user/login和登录页面/user/login.jsp
@Configuration
public class WebConfig implements WebMvcConfigurer {
    @Resource
    private UserInterceptor userInterceptor;
    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(userInterceptor)
                .addPathPatterns("/user/**")
                .excludePathPatterns("/user/login","/user/login.html");
    }
}

(8)、在resources/templates/user目录下添加两个页面 会员登录页面login.html和会员中心首页index.html。
login.html代码如下：
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>登录</title>
</head>
<body>
    <form action="/user/login" method="post">
        <fieldset>
            <span>用户名：</span> <input type="text" name="username" id="username">
        </fieldset>
        <fieldset>
            <span>密　码：</span> <input type="text" name="password" id="password">
        </fieldset>
        <fieldset>
           <input type="submit">
        </fieldset>
    </form>
</body>
</html>

Index.html代码如下：
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>会员中心首页</title>
</head>
<body>
     会员中心首页
</body>
</html>

(9)、修改配置文件 application.properties
在配置文件中添加数据库的连接信息以及配置可以访问templates目录下的文件。
spring.datasource.url=jdbc:mysql://localhost:3306/jwt?useUnicode=true&characterEncoding=UTF-8&useSSL=false&serverTimezone=Asia/Shanghai
spring.datasource.username=root
spring.datasource.password=wanmait
spring.datasource.driver-class-name=com.mysql.cj.jdbc.Driver
spring.resources.static-locations=classpath:/templates,classpath:/static
至此，项目搭建完成。
4、运行项目
运行项目，并访问登陆页面/user/login.html


如果填写正确的用户名和密码，就会打开会员中心首页

因为我们的token是放到session里面存放的，所以再访问会员中心的其他页面，也不需要再登录了。如果需要长时间的保持登录状态，可以把token放到cookie中保存。但是这两种方式无法跨域，如果要跨域，可以把token放到请求头中请求。
这种方式也可以用于前后端分离的登录，前端访问的时候把获取的token放在请求头中就可以了。
