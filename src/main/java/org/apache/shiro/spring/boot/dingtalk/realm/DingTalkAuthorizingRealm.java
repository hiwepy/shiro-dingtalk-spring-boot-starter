package org.apache.shiro.spring.boot.dingtalk.realm;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.biz.authc.AuthcResponse;
import org.apache.shiro.biz.realm.AbstractAuthorizingRealm;
import org.apache.shiro.biz.realm.AuthorizingRealmListener;
import org.apache.shiro.spring.boot.ShiroDingTalkProperties;
import org.apache.shiro.spring.boot.dingtalk.authc.DingTalkTemplate;
import org.apache.shiro.spring.boot.dingtalk.exception.DingTalkAuthenticationServiceException;
import org.apache.shiro.spring.boot.dingtalk.exception.DingTalkCodeNotFoundException;
import org.apache.shiro.spring.boot.dingtalk.property.ShiroDingTalkCropAppProperties;
import org.apache.shiro.spring.boot.dingtalk.property.ShiroDingTalkLoginProperties;
import org.apache.shiro.spring.boot.dingtalk.property.ShiroDingTalkPersonalMiniAppProperties;
import org.apache.shiro.spring.boot.dingtalk.property.ShiroDingTalkSuiteProperties;
import org.apache.shiro.spring.boot.dingtalk.token.DingTalkAuthenticationToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import com.alibaba.fastjson.JSONObject;
import com.dingtalk.api.response.OapiSnsGetuserinfoBycodeResponse;
import com.dingtalk.api.response.OapiSnsGetuserinfoBycodeResponse.UserInfo;
import com.dingtalk.api.response.OapiUserGetResponse;
import com.dingtalk.api.response.OapiUserGetUseridByUnionidResponse;
import com.dingtalk.api.response.OapiUserGetuserinfoResponse;
import com.taobao.api.ApiException;

/**
 * DingTalk AuthorizingRealm
 * @author 		： <a href="https://github.com/hiwepy">hiwepy</a>
 */
public class DingTalkAuthorizingRealm extends AbstractAuthorizingRealm implements InitializingBean {
	
	private static final Logger logger = LoggerFactory.getLogger(DingTalkAuthorizingRealm.class);
	private final ShiroDingTalkProperties dingtalkProperties;
    private final DingTalkTemplate dingTalkTemplate;
    private Map<String, String> appKeySecret = new ConcurrentHashMap<>();
    
    public DingTalkAuthorizingRealm(
    		final DingTalkTemplate dingTalkTemplate,
    		final ShiroDingTalkProperties dingtalkProperties) {
        this.dingTalkTemplate = dingTalkTemplate;
        this.dingtalkProperties = dingtalkProperties;
    }

	@Override
	public void afterPropertiesSet() throws Exception {
		
		if(!CollectionUtils.isEmpty(this.dingtalkProperties.getCropApps())) {
			for (ShiroDingTalkCropAppProperties properties : this.dingtalkProperties.getCropApps()) {
				appKeySecret.put(properties.getAppKey(), properties.getAppSecret());
			}
		}
		if(!CollectionUtils.isEmpty(this.dingtalkProperties.getApps())) {
			for (ShiroDingTalkPersonalMiniAppProperties properties : this.dingtalkProperties.getApps()) {
				appKeySecret.put(properties.getAppId(), properties.getAppSecret());
			}
		}
		if(!CollectionUtils.isEmpty(this.dingtalkProperties.getSuites())) {
			for (ShiroDingTalkSuiteProperties properties : this.dingtalkProperties.getSuites()) {
				appKeySecret.put(properties.getAppId(), properties.getSuiteSecret());
			}
		}
		if(!CollectionUtils.isEmpty(this.dingtalkProperties.getLogins())) {
			for (ShiroDingTalkLoginProperties properties : this.dingtalkProperties.getLogins()) {
				appKeySecret.put(properties.getAppId(), properties.getAppSecret());
			}
		}
		
		logger.debug(appKeySecret.toString());
		
	}
    
	@Override
	public Class<?> getAuthenticationTokenClass() {
		return DingTalkAuthenticationToken.class;// 此Realm只支持SmsLoginToken
	}
	
	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
		
		logger.info("Handle authentication token {}.", new Object[] { token });
    	
    	AuthenticationException ex = null;
    	AuthenticationInfo info = null;
    	
    	try {
    		
    		DingTalkAuthenticationToken loginToken =  (DingTalkAuthenticationToken) token;
    		
    		if ( !StringUtils.hasText(loginToken.getCode()) && !StringUtils.hasText(loginToken.getLoginTmpCode())) {
    			logger.debug("No loginTmpCode or Code found in request.");
    			throw new DingTalkCodeNotFoundException("No loginTmpCode or Code found in request.");
    		}
    		
    		if(!appKeySecret.containsKey(loginToken.getKey())) {
				logger.debug("Invalid App Key {} .", loginToken.getKey());
				throw new DingTalkCodeNotFoundException("Invalid App Key.");
			}
			
			String appKey = loginToken.getKey();
			String appSecret = appKeySecret.get(loginToken.getKey());
			// 获取access_token
			String accessToken = dingTalkTemplate.getAccessToken(appKey, appSecret);
			
			// 企业内部应用免登录：通过免登授权码和access_token获取用户信息
			if(StringUtils.hasText(loginToken.getCode())) {
				loginToken = doAuthenticationByCode(loginToken, accessToken, loginToken.getCode());
			}
			// 第三方应用钉钉扫码登录：通过临时授权码Code获取用户信息，临时授权码只能使用一次
			else if(StringUtils.hasText(loginToken.getLoginTmpCode())) {
				loginToken = doAuthenticationByTmpCode(loginToken, accessToken, loginToken.getLoginTmpCode(), appKey, appSecret);
			}
			
			info = getRepository().getAuthenticationInfo(loginToken);
			 
		} catch (AuthenticationException e) {
			ex = e;
		} catch (ExecutionException e) {
			ex = new AuthenticationException(e);
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
	
	protected DingTalkAuthenticationToken doAuthenticationByCode(DingTalkAuthenticationToken authentication, String accessToken, String code) throws ApiException{


		DingTalkAuthenticationToken dingTalkToken = (DingTalkAuthenticationToken) authentication;
			
		OapiUserGetuserinfoResponse response = dingTalkTemplate.getUserinfoBycode(code, accessToken);
		/*{
		    "userid": "****",
		    "sys_level": 1,
		    "errmsg": "ok",
		    "is_sys": true,
		    "errcode": 0
		}*/
		if (logger.isDebugEnabled()) {
			logger.debug(response.getCode());
		}

		if(!response.isSuccess()) {
			logger.error(JSONObject.toJSONString(AuthcResponse.error(response.getErrorCode(), response.getErrmsg())));
			throw new DingTalkAuthenticationServiceException(response.getErrmsg());
		}
		
		OapiUserGetResponse userInfoResponse = dingTalkTemplate.getUserByUserid(response.getUserid(), accessToken);
		if(!userInfoResponse.isSuccess()) {
			logger.error(JSONObject.toJSONString(AuthcResponse.error(userInfoResponse.getErrorCode(), userInfoResponse.getErrmsg())));
			throw new DingTalkAuthenticationServiceException(userInfoResponse.getErrmsg());
		}
		
		// 解析钉钉用户信息到Token对象
		this.extractRespone(dingTalkToken, userInfoResponse);
		
		return dingTalkToken;
    }
    
	protected DingTalkAuthenticationToken doAuthenticationByTmpCode(DingTalkAuthenticationToken authentication, String accessToken, String loginTmpCode, String appId, String appSecret) throws ApiException{
    	
    	// 第三方应用钉钉扫码登录：通过临时授权码Code获取用户信息，临时授权码只能使用一次
		OapiSnsGetuserinfoBycodeResponse response = dingTalkTemplate.getSnsGetuserinfoBycode(loginTmpCode, appId, appSecret);
		/*{ 
		    "errcode": 0,
		    "errmsg": "ok",
		    "user_info": {
		        "nick": "张三",
		        "openid": "liSii8KCxxxxx",
		        "unionid": "7Huu46kk"
		    }
		}*/
		if (logger.isDebugEnabled()) {
			logger.debug(response.getCode());
		}

		if(!response.isSuccess()) {
			logger.error(JSONObject.toJSONString(AuthcResponse.error(response.getErrorCode(), response.getErrmsg())));
			throw new DingTalkAuthenticationServiceException(response.getErrmsg());
		}
			
		UserInfo userInfo = response.getUserInfo();
		
		DingTalkAuthenticationToken dingTalkToken = (DingTalkAuthenticationToken) authentication;
		
		dingTalkToken.setNick(userInfo.getNick());
		dingTalkToken.setOpenid(userInfo.getOpenid());
		dingTalkToken.setUnionid(userInfo.getUnionid());
		
		// 根据unionid获取userid
		OapiUserGetUseridByUnionidResponse unionidResponse = dingTalkTemplate.getUseridByUnionid(userInfo.getUnionid(), accessToken);
		if(!unionidResponse.isSuccess()) {
			logger.error(JSONObject.toJSONString(AuthcResponse.error(unionidResponse.getErrorCode(), unionidResponse.getErrmsg())));
			throw new DingTalkAuthenticationServiceException(unionidResponse.getErrmsg());
		}
		
		// 根据UserId 获取用户信息
		OapiUserGetResponse userInfoResponse = dingTalkTemplate.getUserByUserid(unionidResponse.getUserid(), accessToken);
		if(!userInfoResponse.isSuccess()) {
			logger.error(JSONObject.toJSONString(AuthcResponse.error(userInfoResponse.getErrorCode(), userInfoResponse.getErrmsg())));
			throw new DingTalkAuthenticationServiceException(userInfoResponse.getErrmsg());
		}
		// 解析钉钉用户信息到Token对象
		this.extractRespone(dingTalkToken, userInfoResponse);
		return dingTalkToken;
    }

    /*    
	 {
	    "active":true,
	    "avatar":"https://static.dingtalk.com/media/lADPBbCc1dSekr_NAczNAcw_460_460.jpg",
	    "body":"{"errcode":0,"unionid":"DhoiSf4ug6KuOpAY95CytZwiEiE","userid":"061955121419944345","isLeaderInDepts":"{110421538:false}","isBoss":false,"isSenior":false,"department":[110421538],"orderInDepts":"{110421538:176362815343598512}","errmsg":"ok","active":true,"avatar":"https://static.dingtalk.com/media/lADPBbCc1dSekr_NAczNAcw_460_460.jpg","isAdmin":false,"tags":{},"isHide":false,"jobnumber":"","name":"万大龙","position":"高级JAVA开发"}",
	    "department":[
	        110421538
	    ],
	    "errcode":0,
	    "errmsg":"ok",
	    "errorCode":"0",
	    "isAdmin":false,
	    "isBoss":false,
	    "isHide":false,
	    "isLeaderInDepts":"{110421538:false}",
	    "isSenior":false,
	    "jobnumber":"",
	    "msg":"ok",
	    "name":"",
	    "orderInDepts":"{110421538:176362815343598512}",
	    "params":{
	        "userid":"061955121419944345"
	    },
	    "position":"高级JAVA开发",
	    "success":true,
	    "unionid":"DhoiSf4ug6KuOpAY95CytZwiEiE",
	    "userid":"061955121419944345"
	} 
	*/
	
    @SuppressWarnings("unchecked")
	protected void extractRespone(DingTalkAuthenticationToken dingTalkToken, OapiUserGetResponse userInfoResponse) {

		dingTalkToken.setActive(userInfoResponse.getActive());
		dingTalkToken.setAdmin(userInfoResponse.getIsAdmin());
		dingTalkToken.setAvatar(userInfoResponse.getAvatar());
		dingTalkToken.setBoss(userInfoResponse.getIsBoss());
		dingTalkToken.setDepts(userInfoResponse.getDepartment());
		dingTalkToken.setEmail(userInfoResponse.getEmail());
		if(StringUtils.hasText(userInfoResponse.getExtattr())) {
			dingTalkToken.setExtattr(JSONObject.parseObject(userInfoResponse.getExtattr(), Map.class));
		}
		dingTalkToken.setHide(userInfoResponse.getIsHide());
		dingTalkToken.setHiredDate(userInfoResponse.getHiredDate());
		dingTalkToken.setInviteMobile(userInfoResponse.getInviteMobile());
		dingTalkToken.setJobnumber(userInfoResponse.getJobnumber());
		dingTalkToken.setMobile(userInfoResponse.getMobile());
		dingTalkToken.setName(userInfoResponse.getName());
		dingTalkToken.setNick(userInfoResponse.getNickname());
		dingTalkToken.setOrgEmail(userInfoResponse.getOrgEmail());
		dingTalkToken.setPosition(userInfoResponse.getPosition());
		dingTalkToken.setUserid(userInfoResponse.getUserid());
		dingTalkToken.setRemark(userInfoResponse.getRemark());
		dingTalkToken.setRoles(userInfoResponse.getRoles());
		dingTalkToken.setSenior(userInfoResponse.getIsSenior());
		dingTalkToken.setStateCode(userInfoResponse.getStateCode());
		dingTalkToken.setTel(userInfoResponse.getTel());
		dingTalkToken.setWorkPlace(userInfoResponse.getWorkPlace());
		
	}

}
