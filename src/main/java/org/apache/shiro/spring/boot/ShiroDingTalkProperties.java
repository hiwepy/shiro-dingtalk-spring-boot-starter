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
package org.apache.shiro.spring.boot;

import java.util.List;

import org.apache.shiro.spring.boot.dingtalk.property.ShiroDingTalkCropAppProperties;
import org.apache.shiro.spring.boot.dingtalk.property.ShiroDingTalkLoginProperties;
import org.apache.shiro.spring.boot.dingtalk.property.ShiroDingTalkPersonalMiniAppProperties;
import org.apache.shiro.spring.boot.dingtalk.property.ShiroDingTalkSuiteProperties;
import org.springframework.boot.context.properties.ConfigurationProperties;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@ConfigurationProperties(ShiroDingTalkProperties.PREFIX)
@Getter
@Setter
@ToString
public class ShiroDingTalkProperties {

	public static final String PREFIX = "shiro.dingtalk";
	
	/** Whether Enable DingTalk Authentication. */
	private boolean enabled = false;

	/**
	 * 	企业ID
	 */
	private String corpId;
	
	/**
	 *    企业内部开发：小程序、H5配置
	 */
	private List<ShiroDingTalkCropAppProperties> cropApps;
	/**
	 *    第三方个人应用：小程序配置
	 */
	private List<ShiroDingTalkPersonalMiniAppProperties> apps;
	/**
	 * 	第三方企业应用：小程序、H5配置
	 */
	private List<ShiroDingTalkSuiteProperties> suites;
	/**
	 *	 移动接入应用：扫码登录配置
	 */
	private List<ShiroDingTalkLoginProperties> logins;
	
}

