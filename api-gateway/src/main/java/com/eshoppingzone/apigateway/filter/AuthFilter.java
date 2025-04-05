package com.eshoppingzone.apigateway.filter;

import org.apache.http.HttpHeaders;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.stereotype.Component;

@Component
public class AuthFilter extends AbstractGatewayFilterFactory<AuthFilter.Config> {


    @Autowired
    private Validator validator;

    @Autowired
    private JwtService jwtService;

    public AuthFilter() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (((exchange, chain) -> {
            if (validator.isSecure.test(exchange.getRequest())) {
                if(!exchange.getRequest().getHeaders().containsKey(HttpHeaders.AUTHORIZATION)){
                    throw new RuntimeException("Missing authorization header.");
                }
                String authHeader = exchange.getRequest().getHeaders().get(HttpHeaders.AUTHORIZATION).get(0);
                String token = null;
                if(null != authHeader && authHeader.startsWith("Bearer ")) {
                    token = authHeader.substring(7);
                }
                try{
                    jwtService.validateToken(token);
                } catch (Exception e){
                    throw new RuntimeException("Un-Authorized");
                }
            }
            return chain.filter(exchange);
        }));
    }

    public static class Config{

    }
}
