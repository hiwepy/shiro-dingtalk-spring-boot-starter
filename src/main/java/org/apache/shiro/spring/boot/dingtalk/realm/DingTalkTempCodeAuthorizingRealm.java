package org.apache.shiro.spring.boot.dingtalk.realm;

import com.dingtalk.spring.boot.DingTalkTemplate;
import com.taobao.api.ApiException;
import lombok.extern.slf4j.Slf4j;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.biz.realm.AbstractAuthorizingRealm;
import org.apache.shiro.biz.realm.AuthorizingRealmListener;
import org.apache.shiro.spring.boot.dingtalk.authc.DingTalkTmpCodeLoginRequest;
import org.apache.shiro.spring.boot.dingtalk.exception.DingTalkAuthenticationServiceException;
import org.apache.shiro.spring.boot.dingtalk.exception.DingTalkCodeNotFoundException;
import org.apache.shiro.spring.boot.dingtalk.token.DingTalkTmpCodeAuthenticationToken;
import org.springframework.util.StringUtils;

/**
 * DingTalk AuthorizingRealm
 * @author 		： <a href="https://github.com/hiwepy">hiwepy</a>
 */
@Slf4j
public class DingTalkTempCodeAuthorizingRealm extends AbstractAuthorizingRealm {

	private final DingTalkTemplate dingTalkTemplate;

	public DingTalkTempCodeAuthorizingRealm(DingTalkTemplate dingTalkTemplate) {
		this.dingTalkTemplate = dingTalkTemplate;
	}

	@Override
	public Class<?> getAuthenticationTokenClass() {
		return DingTalkTmpCodeAuthenticationToken.class;
	}

	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {

		log.info("Handle authentication token {}.", new Object[] { token });

    	AuthenticationException ex = null;
    	AuthenticationInfo info = null;

    	try {

			DingTalkTmpCodeAuthenticationToken dingTalkToken = (DingTalkTmpCodeAuthenticationToken) token;
			DingTalkTmpCodeLoginRequest loginRequest = (DingTalkTmpCodeLoginRequest) dingTalkToken.getPrincipal();

			if (!StringUtils.hasText(loginRequest.getCode())) {
				log.debug("No Code found in request.");
				throw new DingTalkCodeNotFoundException("No Code found in request.");
			}

			if(!dingTalkTemplate.hasAppKey(loginRequest.getKey())) {
				log.debug("Invalid App Key {} .", loginRequest.getKey());
				throw new DingTalkCodeNotFoundException("Invalid App Key.");
			}

			try {
				if (StringUtils.hasText(loginRequest.getCode())) {

					String appKey = loginRequest.getKey();
					String appSecret = dingTalkTemplate.getAppSecret(loginRequest.getKey());
					// 获取access_token
					String accessToken = dingTalkTemplate.getAccessToken(appKey, appSecret);
					loginRequest.setAccessToken(accessToken);
				}
			} catch (ApiException e) {
				throw new DingTalkAuthenticationServiceException(e.getErrMsg(), e);
			}

			info = getRepository().getAuthenticationInfo(dingTalkToken);

		} catch (AuthenticationException e) {
			ex = e;
		}

		//调用事件监听器
		if(getRealmsListeners() != null && getRealmsListeners().size() > 0){
			for (AuthorizingRealmListener realmListener : getRealmsListeners()) {
				if(ex != null || null == info){
					realmListener.onFailure(this, token, ex);
				}else{
					realmListener.onSuccess(this, info);
				}
			}
		}

		if(ex != null){
			throw ex;
		}

		return info;
	}

}
