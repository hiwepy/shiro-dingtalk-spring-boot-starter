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

import org.apache.shiro.biz.authc.token.DefaultAuthenticationToken;
import org.apache.shiro.spring.boot.dingtalk.authc.DingTalkScanCodeLoginRequest;
import org.apache.shiro.spring.boot.dingtalk.authc.DingTalkTmpCodeLoginRequest;

/**
 * DingTalk Authentication Token
 *
 * @author ： <a href="https://github.com/hiwepy">hiwepy</a>
 */
@SuppressWarnings("serial")
public class DingTalkTmpCodeAuthenticationToken extends DefaultAuthenticationToken {

	/**
	 * 登录请求信息
	 */
	private DingTalkTmpCodeLoginRequest principal;

	public DingTalkTmpCodeAuthenticationToken(DingTalkTmpCodeLoginRequest loginRequest, String host) {
		this.principal = loginRequest;
		this.setHost(host);
	}

	@Override
	public Object getPrincipal() {
		return principal;
	}

}
