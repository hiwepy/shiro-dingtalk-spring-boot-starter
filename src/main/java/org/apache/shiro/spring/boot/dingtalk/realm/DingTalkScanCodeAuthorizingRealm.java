package org.apache.shiro.spring.boot.dingtalk.realm;

import com.dingtalk.api.response.OapiSnsGetuserinfoBycodeResponse;
import com.dingtalk.api.response.OapiSnsGetuserinfoBycodeResponse.UserInfo;
import com.dingtalk.spring.boot.DingTalkTemplate;
import com.taobao.api.ApiException;
import lombok.extern.slf4j.Slf4j;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.biz.realm.AbstractAuthorizingRealm;
import org.apache.shiro.biz.realm.AuthorizingRealmListener;
import org.apache.shiro.spring.boot.dingtalk.authc.DingTalkMaLoginRequest;
import org.apache.shiro.spring.boot.dingtalk.authc.DingTalkScanCodeLoginRequest;
import org.apache.shiro.spring.boot.dingtalk.exception.DingTalkAuthenticationServiceException;
import org.apache.shiro.spring.boot.dingtalk.exception.DingTalkCodeNotFoundException;
import org.apache.shiro.spring.boot.dingtalk.token.DingTalkScanCodeAuthenticationToken;
import org.springframework.util.StringUtils;

/**
 * DingTalk AuthorizingRealm
 * @author 		： <a href="https://github.com/hiwepy">hiwepy</a>
 */
@Slf4j
public class DingTalkScanCodeAuthorizingRealm extends AbstractAuthorizingRealm {

    private final DingTalkTemplate dingTalkTemplate;

    public DingTalkScanCodeAuthorizingRealm(DingTalkTemplate dingTalkTemplate) {
        this.dingTalkTemplate = dingTalkTemplate;
    }

	@Override
	public Class<?> getAuthenticationTokenClass() {
		return DingTalkScanCodeAuthenticationToken.class;
	}

	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {

		log.info("Handle authentication token {}.", new Object[] { token });

    	AuthenticationException ex = null;
    	AuthenticationInfo info = null;

    	try {

			DingTalkScanCodeAuthenticationToken dingTalkToken = (DingTalkScanCodeAuthenticationToken) token;
			DingTalkScanCodeLoginRequest loginRequest = (DingTalkScanCodeLoginRequest) dingTalkToken.getPrincipal();
			if ( !StringUtils.hasText(loginRequest.getLoginTmpCode())) {
				log.debug("No loginTmpCode found in request.");
				throw new DingTalkCodeNotFoundException("No loginTmpCode found in request.");
			}

			if(!dingTalkTemplate.hasAppKey(loginRequest.getKey())) {
				log.debug("Invalid App Key {} .", loginRequest.getKey());
				throw new DingTalkCodeNotFoundException("Invalid App Key.");
			}

			String appKey = loginRequest.getKey();
			String appSecret = dingTalkTemplate.getAppSecret(loginRequest.getKey());
			if (StringUtils.hasText(loginRequest.getLoginTmpCode())) {

				// 第三方应用钉钉扫码登录：通过临时授权码Code获取用户信息，临时授权码只能使用一次
				OapiSnsGetuserinfoBycodeResponse response = dingTalkTemplate.opsForSns().getUserinfoByTmpCode(loginRequest.getLoginTmpCode(), appKey, appSecret);
				/*{
				    "errcode": 0,
				    "errmsg": "ok",
				    "user_info": {
				        "nick": "张三",
				        "openid": "liSii8KCxxxxx",
				        "unionid": "7Huu46kk"
				    }
				}*/
				if(!response.isSuccess()) {
					log.error(response.getBody());
					throw new DingTalkAuthenticationServiceException(response.getErrmsg());
				}

				UserInfo userInfo = response.getUserInfo();

				dingTalkToken.setUnionid(userInfo.getUnionid());
				dingTalkToken.setOpenid(userInfo.getOpenid());
				dingTalkToken.setUserInfo(userInfo);

			}
			info = getRepository().getAuthenticationInfo(dingTalkToken);

		} catch (AuthenticationException e) {
			ex = e;
		} catch (ApiException e) {
			ex = new AuthenticationException(e);
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
