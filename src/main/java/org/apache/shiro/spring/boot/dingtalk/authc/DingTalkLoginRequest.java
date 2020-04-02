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
package org.apache.shiro.spring.boot.dingtalk.authc;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * DingTalk Login Request
 * @author ： <a href="https://github.com/hiwepy">hiwepy</a>
 */
public class DingTalkLoginRequest {
	
	/**
	 * 	应用的唯一标识key
	 */
	private String key;
	private String code;
    private String loginTmpCode;
    
    @JsonCreator
    public DingTalkLoginRequest(@JsonProperty("key") String key, @JsonProperty("code") String code,  @JsonProperty("loginTmpCode") String loginTmpCode) {
        this.key = key;
        this.code = code;
        this.loginTmpCode = loginTmpCode;
    }

	public String getKey() {
		return key;
	}

	public void setKey(String key) {
		this.key = key;
	}

	public String getCode() {
		return code;
	}

	public void setCode(String code) {
		this.code = code;
	}

	public String getLoginTmpCode() {
		return loginTmpCode;
	}

	public void setLoginTmpCode(String loginTmpCode) {
		this.loginTmpCode = loginTmpCode;
	}
	
}
