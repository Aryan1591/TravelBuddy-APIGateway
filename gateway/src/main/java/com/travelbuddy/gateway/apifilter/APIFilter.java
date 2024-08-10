package com.travelbuddy.gateway.apifilter;

import com.travelbuddy.gateway.exception.CustomException;
import com.travelbuddy.gateway.util.JWTUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;

import java.util.Objects;

@Component
public class APIFilter extends AbstractGatewayFilterFactory<APIFilter.Config> {

    @Autowired
    private RouteValidator routeValidator;
    @Autowired
    private JWTUtil jwtUtil;

    public APIFilter() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return ((exchange, chain) -> {
            if (routeValidator.isSecured.test(exchange.getRequest())) {
                if (!exchange.getRequest().getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                    throw new CustomException("You are not authorized");
                }
                String tokenFromHeader = exchange.getRequest().getHeaders().get(HttpHeaders.AUTHORIZATION).get(0);
                if (Objects.nonNull(tokenFromHeader) && tokenFromHeader.startsWith("Bearer ")) {
                    tokenFromHeader = tokenFromHeader.substring(7);
                }
                try {
                    jwtUtil.validateJWTToken(tokenFromHeader);
                     ServerHttpRequest request =  exchange.getRequest().mutate().header("currentLoggedInUser", jwtUtil.extractUserName(tokenFromHeader))
                            .build();
                    return chain.filter(exchange.mutate().request(request).build());

                } catch (Exception e) {
                    throw new CustomException("You are not authorized");
                }
            }
            return chain.filter(exchange);
        });
    }

    public static class Config {

    }

}
