/*
 * Copyright (c) 2018, hiwepy (https://github.com/hiwepy).
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.apache.shiro.spring.boot.dingtalk.token;

import com.dingtalk.api.response.OapiSnsGetuserinfoBycodeResponse;
import org.apache.shiro.biz.authc.token.DefaultAuthenticationToken;
import org.apache.shiro.spring.boot.dingtalk.authc.DingTalkMaLoginRequest;
import org.apache.shiro.spring.boot.dingtalk.authc.DingTalkScanCodeLoginRequest;

/**
 * DingTalk Authentication Token
 *
 * @author ： <a href="https://github.com/hiwepy">hiwepy</a>
 */
@SuppressWarnings("serial")
public class DingTalkScanCodeAuthenticationToken extends DefaultAuthenticationToken {

	/**
	 * 登录请求信息
	 */
	private DingTalkScanCodeLoginRequest loginRequest;
	/**
	 * 第三方平台UnionID（通常指第三方账号体系下用户的唯一ID）
	 */
	protected String unionid;
	/**
	 * 第三方平台OpenID（通常指第三方账号体系下某应用中用户的唯一ID）
	 */
	protected String openid;
	/**
	 * 用户信息
	 */
	protected OapiSnsGetuserinfoBycodeResponse.UserInfo userInfo ;

	public DingTalkScanCodeAuthenticationToken(DingTalkScanCodeLoginRequest reqloginRequestuest, String host) {
		this.loginRequest = loginRequest;
		this.setHost(host);
	}

	public DingTalkScanCodeLoginRequest getLoginRequest() {
		return loginRequest;
	}

	public String getUnionid() {
		return unionid;
	}

	public void setUnionid(String unionid) {
		this.unionid = unionid;
	}

	public String getOpenid() {
		return openid;
	}

	public void setOpenid(String openid) {
		this.openid = openid;
	}

	public OapiSnsGetuserinfoBycodeResponse.UserInfo getUserInfo() {
		return userInfo;
	}

	public void setUserInfo(OapiSnsGetuserinfoBycodeResponse.UserInfo userInfo) {
		this.userInfo = userInfo;
	}
}
