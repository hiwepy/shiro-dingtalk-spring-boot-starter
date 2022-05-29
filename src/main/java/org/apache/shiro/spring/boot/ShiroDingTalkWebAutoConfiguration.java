package org.apache.shiro.spring.boot;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import org.apache.shiro.spring.boot.dingtalk.authc.DingTalkAuthenticationSuccessHandler;
import org.apache.shiro.spring.boot.jwt.JwtPayloadRepository;
import org.apache.shiro.spring.web.config.AbstractShiroWebConfiguration;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@AutoConfigureBefore( name = {
	"org.apache.shiro.spring.config.web.autoconfigure.ShiroWebAutoConfiguration",
	"org.apache.shiro.spring.boot.ShiroBizWebAutoConfiguration"
})
@ConditionalOnProperty(prefix = ShiroDingTalkProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ ShiroDingTalkProperties.class })
public class ShiroDingTalkWebAutoConfiguration extends AbstractShiroWebConfiguration implements ApplicationContextAware {

	private ApplicationContext applicationContext;

	@Bean
	protected DingTalkAuthenticationSuccessHandler wxAuthenticationSuccessHandler(
			ObjectProvider<ObjectMapper> objectMapperProvider,
			ObjectProvider<JwtPayloadRepository> jwtPayloadRepositoryProvider,
			ShiroJwtProperties jwtProperties) {

		ObjectMapper objectMapper = objectMapperProvider.getIfAvailable(() -> {
			ObjectMapper objectMapperDef = new ObjectMapper();
			objectMapperDef.setSerializationInclusion(JsonInclude.Include.NON_NULL);
			objectMapperDef.enable(MapperFeature.USE_GETTERS_AS_SETTERS);
			objectMapperDef.enable(MapperFeature.ALLOW_FINAL_FIELDS_AS_MUTATORS);
			objectMapperDef.disable(SerializationFeature.FAIL_ON_EMPTY_BEANS);
			objectMapperDef.disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
			return objectMapperDef;
		});

		return new DingTalkAuthenticationSuccessHandler(objectMapper, jwtPayloadRepositoryProvider.getIfAvailable(), jwtProperties.isCheckExpiry());
	}

	@Override
	public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
		this.applicationContext = applicationContext;
	}

	public ApplicationContext getApplicationContext() {
		return applicationContext;
	}

}
